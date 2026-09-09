//! Per-connection protocol dispatch (ALPN → h2 / h1; TLS via BoringSSL + legacy stacks).

use crate::config::ListenerConfig;
use crate::server::live_config::LiveConfig;
use crate::server::{h1, h2, port_reuse};
use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;

pub async fn handle_connection(
    stream: TcpStream,
    live: Arc<LiveConfig>,
    port: u16,
    peer: SocketAddr,
) -> Result<()> {
    let cfg = live.snapshot();
    let lc = cfg
        .listeners
        .iter()
        .find(|l| l.port == port)
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
    if lc.port_reuse && lc.ssl.is_none() {
        stream.readable().await.ok();
        let mut peek = vec![0u8; 4096];
        let n = match stream.try_read(&mut peek) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => 0,
            Err(_) => 0,
        };
        if n > 0 {
            // 仅 TLS record header (0x16) 才处理，明文 HTTP 方法名直接忽略
            if peek[0] == 0x16 && peek.len() >= 5 {
                if let Some(sni) = port_reuse::peek_sni(&peek[..n]) {
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
                                // First forward the peeked TLS record prefix
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
                }
            }
        }
    }

    stream.readable().await.ok();
    let mut buf = [0u8; 24];
    let n = stream.try_read(&mut buf).unwrap_or(0);
    if n >= 24 && &buf[..24] == b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" {
        if !lc.allows_h2() {
            anyhow::bail!("h2 prior-knowledge but http_versions disables h2");
        }
        h2::serve_with_prefix(stream, live, lc, peer, &buf[..24]).await
    } else if n > 0 {
        if !lc.allows_h1() {
            anyhow::bail!("h1 request but http_versions disables h1");
        }
        h1::serve_with_prefix(stream, live, lc, peer, &buf[..n]).await
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
