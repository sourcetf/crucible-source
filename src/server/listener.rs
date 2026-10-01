//! Per-connection protocol dispatch (ALPN → h2 / h1; TLS via BoringSSL + legacy stacks).

use crate::config::ListenerConfig;
use crate::server::live_config::LiveConfig;
use crate::server::{h1, h2, port_reuse};
use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;

/// 该 listener 是否就是 `local`（实际接受连接的那个 socket 地址）对应的配置。
///
/// 规则：端口必须相同；地址按解析后的 IP 比较，**通配地址按同族匹配任意本地地址**
///（`0.0.0.0` 匹配任何 v4、`::` 匹配任何 v6）。`address_v6` 也参与比较。
fn listener_matches_local(l: &ListenerConfig, local: SocketAddr) -> bool {
    if l.port != local.port() {
        return false;
    }
    let ip = local.ip();
    let parse = |s: &str| s.trim().parse::<std::net::IpAddr>().ok();
    if let Some(v6) = l.address_v6.as_deref().and_then(parse) {
        if v6 == ip {
            return true;
        }
    }
    match parse(&l.address) {
        Some(a) if a == ip => true,
        Some(std::net::IpAddr::V4(v4)) if v4.is_unspecified() && ip.is_ipv4() => true,
        Some(std::net::IpAddr::V6(v6)) if v6.is_unspecified() && ip.is_ipv6() => true,
        _ => false,
    }
}

pub async fn handle_connection(
    stream: TcpStream,
    live: Arc<LiveConfig>,
    local: SocketAddr,
    peer: SocketAddr,
) -> Result<()> {
    let cfg = live.snapshot();
    // 按「端口 + **实际绑定的地址**」选配置：同端口不同地址的两个 listener 各自服务
    // 自己的站点（见 `mod.rs::bind_key` 与审计 C-2）。只按端口取会拿到另一个站点的配置。
    let lc = cfg
        .listeners
        .iter()
        .find(|l| listener_matches_local(l, local))
        .or_else(|| cfg.listeners.iter().find(|l| l.port == local.port()))
        .cloned()
        .context("listener vanished")?;

    // §16.18 L4 不透明转发：l4_forward 配置后整条连接双向透传，不做 HTTP/TLS 解析
    if let Some(dest) = &lc.l4_forward {
        let addr: SocketAddr = dest
            .parse()
            .with_context(|| format!("l4_forward {dest:?} 无效，应为 ip:port"))?;
        crate::server::l4::proxy_tcp(stream, addr).await?;
        return Ok(());
    }

    #[cfg(feature = "tls")]
    if lc.ssl.is_some() {
        return crate::server::tls::accept::accept_connection(stream, live, lc, peer).await;
    }

    #[cfg(not(feature = "tls"))]
    if lc.ssl.is_some() {
        anyhow::bail!("TLS listener but crucible built without `tls` feature");
    }

    dispatch_plain(stream, live, lc, peer).await
}

async fn dispatch_plain(
    stream: TcpStream,
    live: Arc<LiveConfig>,
    lc: ListenerConfig,
    peer: SocketAddr,
) -> Result<()> {
    // 早期规格 5：port_reuse TLS ClientHello → SNI 路由到目标 TLS listener。
    // 明文口（ssl=None, port_reuse=true）收到 TLS 记录 → peek_sni → proxy_to_ssl_listener。
    //
    // 注意：这里用的是 `try_read`，它会**真的把字节读走**（不是 peek）。
    // 因此明文分支必须把这批字节原样交给 HTTP 层继续解析，否则第一个请求段
    // 被丢掉，客户端只会挂到超时；这也是「明文口 301/HSTS 重定向永远不生效」的原因。
    let mut plain_prefix: Vec<u8> = Vec::new();
    if lc.port_reuse && lc.ssl.is_none() {
        stream.readable().await.ok();
        let mut peek = vec![0u8; 4096];
        // `mut`：下面补齐半个 ClientHello 时会继续往 peek 里写（并把 n 加上读到的字节数）
        let mut n = match stream.try_read(&mut peek) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => 0,
            Err(_) => 0,
        };
        if n > 0 {
            // 仅 TLS record header (0x16) 才走 SNI 分流；明文 HTTP 方法名留给下面。
            if peek[0] == 0x16 && n >= 5 {
                // 单次 try_read 可能只拿到半个 ClientHello（TCP 分段）——直接按「无 SNI」
                // 丢弃会把**正常客户端**误杀。先按 record 头声明的长度补齐：
                // TLS record = type(1)+version(2)+length(2)+payload ⇒ 需要 `5 + length` 字节。
                // 最多 8 轮、每轮 300ms，且不超过缓冲区容量。
                {
                    let mut rounds = 0;
                    while rounds < 8 {
                        if port_reuse::peek_sni(&peek[..n]).is_some() {
                            break;
                        }
                        let need = 5 + u16::from_be_bytes([peek[3], peek[4]]) as usize;
                        // 已收齐仍解析不出 SNI → 确实没有；或已超缓冲区 → 放弃（同旧行为）
                        if need <= n || need > peek.len() {
                            break;
                        }
                        stream.readable().await.ok();
                        match stream.try_read(&mut peek[n..need]) {
                            Ok(k) if k > 0 => n += k,
                            _ => break,
                        }
                        rounds += 1;
                        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                    }
                }
                let sni = match port_reuse::peek_sni(&peek[..n]) {
                    Some(s) => s,
                    None => {
                        // 是 TLS 但 SNI 取不到：明文口无法路由，明确丢弃并记账。
                        log::info!(
                            "port_reuse: TLS ClientHello 无可用 SNI（peer={peer}），丢弃"
                        );
                        drop(stream);
                        return Ok(());
                    }
                };
                let cfg = live.snapshot();
                // 按 server_name / sni_name 找匹配的 TLS listener
                let target = cfg.listeners.iter().find(|l| {
                    l.ssl.is_some() && (
                        l.server_name.as_deref().map_or(false, |sn| {
                            sni.eq_ignore_ascii_case(&*sn)
                                || sni.ends_with(&format!(".{}", sn.to_lowercase()))
                        }) ||
                        l.ssl.as_ref().map_or(false, |s| {
                            s.sni_name.as_deref().map_or(false, |n| sni.eq_ignore_ascii_case(n))
                        })
                    )
                });
                if let Some(tl) = target {
                    let bind_ip: std::net::IpAddr = tl.address.parse().unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
                    let target_addr = SocketAddr::new(bind_ip, tl.port);
                    log::info!("port_reuse: SNI={} TLS ClientHello → 转接 {}:{} (listener idx)",
                        sni, tl.address, tl.port);
                    // 透明 TCP 转发（TLS 握手在目标 listener 侧完成）
                    let (mut pr, mut pw) = stream.into_split();
                    return match tokio::net::TcpStream::connect(target_addr).await {
                        Ok(mut up) => {
                            use tokio::io::{AsyncReadExt, AsyncWriteExt};
                            // 先把已读走的 TLS record 前缀补发过去
                            let _ = up.write_all(&peek[..n]).await?;
                            let (mut ur, mut uw) = up.into_split();
                            let _ = tokio::try_join!(
                                tokio::io::copy(&mut pr, &mut uw),
                                tokio::io::copy(&mut ur, &mut pw),
                            );
                            Ok(())
                        }
                        Err(e) => {
                            log::warn!("port_reuse: connect to TLS listener {}:{} failed: {}", tl.address, tl.port, e);
                            Err(anyhow::anyhow!("port_reuse upstream connect failed"))
                        }
                    };
                } else {
                    log::info!("port_reuse: SNI={} 无匹配 TLS listener，拒绝", sni);
                    drop(stream);
                    return Ok(());
                }
            } else {
                // 明文 HTTP：这批字节已经被 try_read 读走，必须交回 HTTP 层。
                plain_prefix = peek[..n].to_vec();
            }
        }
    }

    // 明文分发：port_reuse 分支若已读到字节就直接用，避免二次读取丢数据。
    if plain_prefix.is_empty() {
        stream.readable().await.ok();
        let mut buf = [0u8; 24];
        let n = stream.try_read(&mut buf).unwrap_or(0);
        plain_prefix = buf[..n].to_vec();
    }
    let prefix: &[u8] = plain_prefix.as_slice();
    // 草案 §10.1：非 TLS 时用首 8 字节的协议魔数识别 QMux（QX_TRANSPORT_PARAMETERS 的帧类型
    // 字段，wire 上是 `\xffQMX\r\n\r\n`）。与 h2 prior-knowledge 是同一条嗅探路径。
    // 注意：规范编码下首字节是**记录 Size**，魔数在其后（见 proto::plaintext_is_qmux 的说明）。
    if lc.qmux && crate::server::qmux::proto::plaintext_is_qmux(prefix) {
        // 已 try_read 走的字节必须交回协议层，否则首帧被吞
        let io = crate::server::prefixed_stream::PrefixedStream::new(stream, prefix.to_vec());
        crate::server::qmux::serve_h1(io, live, lc, peer).await
    } else if prefix.len() >= 24 && &prefix[..24] == b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" {
        if !lc.allows_h2() {
            anyhow::bail!("h2 prior-knowledge but http_versions disables h2");
        }
        h2::serve_with_prefix(stream, live, lc, peer, prefix).await
    } else if !prefix.is_empty() {
        if !lc.allows_h1() {
            anyhow::bail!("h1 request but http_versions disables h1");
        }
        h1::serve_with_prefix(stream, live, lc, peer, prefix).await
    } else {
        if !lc.allows_h1() {
            anyhow::bail!("empty preface and h1 disabled");
        }
        h1::serve(stream, live, lc, peer).await
    }
}

pub fn hsts_header_value() -> &'static str {
    "max-age=31536000; includeSubDomains"
}

pub fn should_redirect_http_to_https(lc: &ListenerConfig) -> bool {
    lc.ssl.is_some()
}
