//! Per-connection protocol dispatch (ALPN → h2 / h1; TLS via BoringSSL + legacy stacks).

use crate::config::ListenerConfig;
use crate::server::live_config::LiveConfig;
use crate::server::{h1, h2};
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
