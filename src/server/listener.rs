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
        // 通配 v6（`::`）匹配同族任意本地地址 —— 与 `address = "0.0.0.0"` 对称。
        // 这条是本轮单测抓出来的：此前只做精确相等，`address_v6 = "::"` 的 listener
        // 会**匹配不上任何 v6 连接**（生产配置没有 address_v6，所以真机验证看不见这个缺口）。
        if v6 == ip || (v6.is_unspecified() && ip.is_ipv6()) {
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

/// §16.1：per-listener `[listeners.ip_access]` 与全局 `[ip_access]` 的**合并判定**。
///
/// 语义：**两份都必须放行**才放行 —— listener 档位是在全局档位之上**再收窄**，不是覆盖。
/// 这样「全局白名单 + 个别 listener 再加一道」符合直觉，也不会因为某个 listener 少配一处
/// 就把全局策略意外放宽。`lc.ip_access` 为 `None` 时等价于只用全局档位（与旧版行为一致）。
///
/// **调用点说明**：h1/h2/h3 的请求路径目前调的是 `access::is_allowed(&snap.ip_access, peer)`；
/// 要完整支持 per-listener（含 TLS 口），把那一行换成
/// `crate::server::listener::ip_allowed(&snap.ip_access, &lc, peer)` 即可（`lc` 在三个
/// 调用点都已持有）。本函数放在 listener.rs（core scope）供其调用。明文 listener 的连接层
/// 拦截见 `handle_connection`。
pub fn ip_allowed(
    global: &crate::config::IpAccessConfig,
    lc: &ListenerConfig,
    peer: SocketAddr,
) -> bool {
    if !crate::server::access::is_allowed(global, peer) {
        return false;
    }
    match &lc.ip_access {
        Some(local) => crate::server::access::is_allowed(local, peer),
        None => true,
    }
}

/// 明文 listener 上对「被 ip_access 拒绝」的连接写一个最小 HTTP/1.1 403 后关闭。
///
/// 为什么在连接层直接回（而不是交给 h1/h2/h3）：明文口在协议分发**之前**就能确定对端 IP，
/// 这里拒绝可让 h1/h2c/port_reuse 共用同一道门，且无需改 h1/h2/h3。响应固定为 HTTP/1.1
/// 文本 403（拒绝场景下不保证协议协商，符合「拒绝」语义）。带超时，避免对端不收包时挂住。
async fn deny_plain_http(mut stream: TcpStream) {
    use tokio::io::AsyncWriteExt;
    let body = b"forbidden by ip_access\n";
    let head = format!(
        "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        stream.write_all(head.as_bytes()).await?;
        stream.write_all(body).await?;
        stream.shutdown().await
    })
    .await;
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

    // §16.18 L4 不透明转发：l4_forward 配置后整条连接双向透传，不做 HTTP/TLS 解析。
    //
    // **但服务器级 `[ip_access]` 必须先生效**：L4 路径不做任何 HTTP/TLS 层检查，
    // 若把它放在 ACL 之前，一条 l4_forward 配置就等于给被 deny 的来源开了一个
    // 直通内网目标的隧道（报告 P2「l4_forward 完全绕过 ip_access」实测正是如此）。
    if let Some(dest) = &lc.l4_forward {
        if !ip_allowed(&cfg.ip_access, &lc, peer) {
            log::debug!("l4: connection from {peer} denied by [ip_access]");
            return Ok(());
        }
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

    // §16.1 per-listener `[listeners.ip_access]`：**明文** listener 在连接层直接拒绝。
    //
    // 只在该 listener **确实配了** `ip_access` 时走这条（`lc.ip_access.is_some()`），
    // 因此「只有全局 [ip_access]」的既有行为完全不变（仍由 h1/h2/h3 的请求路径回 403）。
    // TLS listener 不在此拦截（握手后才能判定协议），其 per-listener 档位由各协议请求路径
    // 的 `ip_allowed` 处理（见该函数注释里点名的一行改法）。
    if lc.ip_access.is_some() && !ip_allowed(&cfg.ip_access, &lc, peer) {
        log::debug!(
            "plain connection from {peer} denied by [listeners.ip_access] ({}:{})",
            lc.address,
            lc.port
        );
        deny_plain_http(stream).await;
        return Ok(());
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
        // 同样必须带超时（理由见下面 `plain_prefix.is_empty()` 分支）：这里是
        // port_reuse 明文口（例如 55555/55556 那对）的嗅探入口。
        // 超时 ⇒ sniff_ready=false ⇒ n 保持 0 ⇒ 不做 TLS 分流，plain_prefix 仍为空，
        // 交给下面的分支（它也有自己的超时）再判一次 —— 语义等同「对端没发字节」。
        let sniff_ready = tokio::time::timeout(
            crate::server::tls::accept::PEEK_TOTAL_WAIT,
            stream.readable(),
        )
        .await
        .is_ok();
        let mut peek = vec![0u8; 4096];
        // `mut`：下面补齐半个 ClientHello 时会继续往 peek 里写（并把 n 加上读到的字节数）
        let mut n = if sniff_ready {
            match stream.try_read(&mut peek) {
                Ok(m) => m,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => 0,
                Err(_) => 0,
            }
        } else {
            0
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
                        // `readable().await` **必须带超时**：客户端发 `16 03 01 01 00`
                        // （声明长度 > 已收字节）后停住时，无超时的 readable 会永久挂起
                        // 这条任务与 fd（tls-core P2 邻接项，第 6 轮只给首字节嗅探套了
                        // 超时，这处补齐循环漏了）。超时即按「SNI 不可得」放弃补齐。
                        if tokio::time::timeout(
                            std::time::Duration::from_millis(300),
                            stream.readable(),
                        )
                        .await
                        .is_err()
                        {
                            break;
                        }
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
                    // 透明 TCP 转发（TLS 握手在目标 listener 侧完成）。
                    // 走 `l4::forward_guarded`：**带守卫**（connect 5s 上限 + 两个方向各自
                    // 60s 空闲上限）。本路径在 h1/h2/h3 之前跑、不继承它们的任何超时；
                    // 此前这里是内联的 `TcpStream::connect` + `tokio::io::copy`（零超时）。
                    // 已读走的 TLS record 前缀由 prefix 参数补发给上游。
                    return match crate::server::l4::forward_guarded(stream, target_addr, &peek[..n]).await {
                        Ok(()) => Ok(()),
                        Err(e) => {
                            log::warn!(
                                "port_reuse: 转发到 TLS listener {}:{} 失败: {}",
                                tl.address, tl.port, e
                            );
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
        // **首字节必须有超时**（与 TLS 侧 `accept::PEEK_TOTAL_WAIT` 同一预算）。
        // 旧实现是裸 `stream.readable().await`：明文口连上后**一个字节都不发**，就能把这个
        // 任务连同它的 fd 永久挂住 —— h1 的 30s 头读超时**盖不到**这里（根本还没进 h1）。
        // 叠加「无 per-IP/全局连接上限」，约 940 个零字节空连接即可打满 fd，进而让某个
        // accept 循环撞上 EMFILE（第 6 轮并发报告 #1/#2，同一攻击链的两端）。
        // 超时后 prefix 仍为空 ⇒ 落到下面的 `h1::serve`，由 h1 自己的头读超时兜底：
        // 连接依然是**有界**的，只是分流判定延后，语义不变。
        if tokio::time::timeout(
            crate::server::tls::accept::PEEK_TOTAL_WAIT,
            stream.readable(),
        )
        .await
        .is_ok()
        {
            let mut buf = [0u8; 24];
            let mut n = stream.try_read(&mut buf).unwrap_or(0);
            // h2c prior-knowledge 前奏是 **24 字节固定串**，可能被 TCP 分段到达：
            // `readable()` 只保证 ≥1 字节可读，单次 `try_read` 完全可能只拿到前几个字节。
            // 只要已读到的字节仍是该前奏的**真前缀**，就继续读到满 24 字节或预算耗尽 ——
            // 否则半个前奏会被判成 h1，连接被 400/关闭（实测：把 24 字节前奏分两段发
            // 必失败）。非前奏前缀（普通 h1 请求、QMux 魔数等）不进入此循环，
            // 因此不会给正常请求增加等待。
            const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
            if n > 0 && n < buf.len() && H2_PREFACE.starts_with(&buf[..n]) {
                let deadline =
                    std::time::Instant::now() + crate::server::tls::accept::PEEK_TOTAL_WAIT;
                while n < buf.len() {
                    let now = std::time::Instant::now();
                    if now >= deadline {
                        break;
                    }
                    if tokio::time::timeout(deadline - now, stream.readable())
                        .await
                        .is_err()
                    {
                        break;
                    }
                    match stream.try_read(&mut buf[n..]) {
                        Ok(0) => break,
                        Ok(k) => n += k,
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                        Err(_) => break,
                    }
                }
            }
            plain_prefix = buf[..n].to_vec();
        }
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

// 已删除：`hsts_header_value()` —— 无任何调用者（死代码），且其值
// `max-age=31536000; includeSubDomains` 与 HSTS 的唯一权威来源 `h1::hsts_header()`
// （`max-age=31536000`，h1/h2/h3 三协议都调它）**分叉**。留着它只会让下一个改 HSTS 的人
// 改错地方。选择「删除」而不是「让 h1 复用」：h1.rs 不在本 agent 的 scope 内，且 h1 侧
// 的值已是三协议共用的单一来源，没有理由把一个在 listener.rs 里、语义更宽的副本提升为权威。
pub fn should_redirect_http_to_https(lc: &ListenerConfig) -> bool {
    lc.ssl.is_some()
}

#[cfg(test)]
mod match_tests {
    use super::*;

    fn lc(address: &str, address_v6: Option<&str>, port: u16) -> ListenerConfig {
        let mut l = ListenerConfig::default();
        l.address = address.into();
        l.address_v6 = address_v6.map(|s| s.to_string());
        l.port = port;
        l
    }

    /// 连接分发按「端口 + **实际绑定的地址**」选配置（审计 C-2）：
    /// 同端口不同地址的两个 listener 必须各认自己的 socket。
    #[test]
    fn matches_by_port_and_address() {
        // 精确匹配
        assert!(listener_matches_local(
            &lc("127.0.0.1", None, 8443),
            "127.0.0.1:8443".parse().unwrap()
        ));
        // 端口不同 ⇒ 不匹配
        assert!(!listener_matches_local(
            &lc("127.0.0.1", None, 8443),
            "127.0.0.1:9443".parse().unwrap()
        ));
        // 地址不同 ⇒ 不匹配（否则同端口两个站点会串）
        assert!(!listener_matches_local(
            &lc("127.0.0.1", None, 8443),
            "127.0.0.2:8443".parse().unwrap()
        ));
        // 通配 v4 匹配任意 v4 本地地址（生产就是 0.0.0.0）
        assert!(listener_matches_local(
            &lc("0.0.0.0", None, 8443),
            "127.0.0.1:8443".parse().unwrap()
        ));
        assert!(listener_matches_local(
            &lc("0.0.0.0", None, 8443),
            "83.229.125.81:8443".parse().unwrap()
        ));
        // 通配 v4 **不**匹配 v6 本地地址
        assert!(!listener_matches_local(
            &lc("0.0.0.0", None, 8443),
            "[::1]:8443".parse().unwrap()
        ));
        // address_v6 参与匹配
        assert!(listener_matches_local(
            &lc("0.0.0.0", Some("::"), 8443),
            "[::1]:8443".parse().unwrap()
        ));
        assert!(listener_matches_local(
            &lc("0.0.0.0", Some("::1"), 8443),
            "[::1]:8443".parse().unwrap()
        ));
    }
}

#[cfg(test)]
mod ip_allowed_tests {
    use super::ip_allowed;
    use crate::config::{IpAccessConfig, ListenerConfig};

    fn local(allow: &[&str], deny: &[&str]) -> Option<IpAccessConfig> {
        Some(IpAccessConfig {
            allow: allow.iter().map(|s| s.to_string()).collect(),
            deny: deny.iter().map(|s| s.to_string()).collect(),
        })
    }

    /// §16.1：per-listener 档位必须在全局之上**再收窄**，而不是被忽略。
    ///
    /// 这正是验收 agent 黑盒复现的缺陷：`[listeners.ip_access] allow = ["10.0.0.0/8"]`
    /// 从 127.0.0.1 访问应被拒，而旧实现（字段不存在 → serde 静默忽略）放行。
    #[test]
    fn per_listener_allow_denies_outside_source() {
        let global = IpAccessConfig::default(); // 全局不限制
        let peer: std::net::SocketAddr = "127.0.0.1:5000".parse().unwrap();

        let mut lc = ListenerConfig::default();
        lc.ip_access = local(&["10.0.0.0/8"], &[]);
        assert!(
            !ip_allowed(&global, &lc, peer),
            "listener allow=[10/8] 必须拒绝 127.0.0.1（旧实现因字段缺失而放行）"
        );

        // 白名单内的来源放行。
        let inside: std::net::SocketAddr = "10.1.2.3:5000".parse().unwrap();
        assert!(ip_allowed(&global, &lc, inside));
    }

    /// `None` = 只用全局档位（旧行为零变化）。
    #[test]
    fn none_falls_back_to_global_only() {
        let global = IpAccessConfig {
            allow: vec![],
            deny: vec!["127.0.0.1".into()],
        };
        let peer: std::net::SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let lc = ListenerConfig::default(); // ip_access = None
        assert!(!ip_allowed(&global, &lc, peer), "全局 deny 必须生效");

        let global_open = IpAccessConfig::default();
        assert!(ip_allowed(&global_open, &lc, peer));
    }

    /// 两份都要放行：全局拒绝时，listener 再宽松也拒（listener 只能收窄，不能放宽）。
    #[test]
    fn listener_cannot_widen_global_deny() {
        let global = IpAccessConfig {
            allow: vec![],
            deny: vec!["127.0.0.1".into()],
        };
        let peer: std::net::SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let mut lc = ListenerConfig::default();
        // listener 明确放行 127.0.0.1 —— 但全局 deny 优先，仍必须拒。
        lc.ip_access = local(&["127.0.0.1"], &[]);
        assert!(
            !ip_allowed(&global, &lc, peer),
            "listener 档位不得覆盖（放宽）全局 deny"
        );
    }
}
