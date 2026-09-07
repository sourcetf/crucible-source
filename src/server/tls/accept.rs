//! Unified TLS accept: peek ClientHello → route → Boring / NSS / TomCrypt / rustls.

use crate::config::ListenerConfig;
use crate::server::live_config::LiveConfig;
use crate::server::tls::client_hello::{self, HelloRoute};
use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;

/// Peek the ClientHello, classify, and hand off to the selected stack.
/// Legacy failures must never tear down the process (TomCrypt ARGCHK used to `abort()`).
pub async fn accept_connection(
    stream: TcpStream,
    live: Arc<LiveConfig>,
    lc: ListenerConfig,
    peer: SocketAddr,
) -> Result<()> {
    match accept_connection_inner(stream, live, lc, peer).await {
        Ok(()) => Ok(()),
        Err(e) => {
            log::error!("tls accept soft-fail peer={peer}: {e:#}");
            Ok(())
        }
    }
}

async fn accept_connection_inner(
    stream: TcpStream,
    live: Arc<LiveConfig>,
    lc: ListenerConfig,
    peer: SocketAddr,
) -> Result<()> {
    let ssl_cfg = lc.ssl.clone().context("ssl listener without ssl config")?;
    stream.readable().await.ok();
    let mut peek = vec![0u8; 4096];
    let n = match stream.try_read(&mut peek) {
        Ok(n) => n,
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => 0,
        Err(e) => return Err(e).context("peek ClientHello"),
    };
    let peek = peek[..n].to_vec();

    // Defense-in-depth: never hand malformed SSLv2-framed garbage to any stack.
    if !peek.is_empty() && peek[0] & 0x80 != 0 {
        let wire = client_hello::route(&peek);
        if wire == HelloRoute::Boring {
            log::info!(
                "tls soft-drop incomplete/non-TLS SSLv2-framed peek peer={peer} len={}",
                peek.len()
            );
            drop(stream);
            return Ok(());
        }
    }

    // 早期规格 8：sni_only——空/错 SNI 直接静默丢弃（不发 reset 不回包，性能优先）。
    if ssl_cfg.sni_only {
        let want = ssl_cfg
            .sni_name
            .as_deref()
            .map(|s| s.to_string())
            .or_else(|| lc.server_name.clone());
        let got = client_hello::parse_sni(&peek);
        let ok = match (want, got) {
            (Some(w), Some(g)) => g.eq_ignore_ascii_case(&w),
            _ => false,
        };
        if !ok {
            log::info!("tls sni_only: dropped peer={peer} (missing/mismatched SNI)");
            drop(stream);
            return Ok(());
        }
    }

    // 早期规格 5：端口复用——明文口（或未配 ssl 的口）收到 TLS ClientHello 时，
    // 按 SNI 找到匹配 server_name 的已配置 TLS listener，用其证书直接走 TLS。
    // （本函数只在 ssl listener 上被调用；非 ssl 口的复用在 server::mod 分流。）
    let wire = client_hello::route(&peek);
    let route = client_hello::resolve(wire, &ssl_cfg);
    log::info!(
        "tls route peer={peer} wire={wire:?} stack={route:?} peek={} primary={} legacy={}",
        peek.len(),
        crate::server::tls::active_stack(),
        crate::server::tls::legacy_modules()
    );

    match route {
        HelloRoute::TomCrypt => {
            #[cfg(feature = "tls_tomcrypt")]
            {
                return crate::server::tls::tomcrypt::accept_and_serve(
                    stream, peek, &ssl_cfg, lc, peer, live,
                )
                .await;
            }
            #[cfg(not(feature = "tls_tomcrypt"))]
            anyhow::bail!("TomCrypt legacy stack not compiled in (rebuild with --enable-tomcrypt)");
        }
        HelloRoute::Nss => {
            #[cfg(feature = "tls_nss")]
            {
                return crate::server::tls::nss::accept_and_serve(
                    stream, peek, &ssl_cfg, lc, peer, live,
                )
                .await;
            }
            #[cfg(not(feature = "tls_nss"))]
            anyhow::bail!("NSS legacy stack not compiled in (rebuild with --enable-nss)");
        }
        HelloRoute::Boring => {
            #[cfg(feature = "tls_boring")]
            {
                return crate::server::tls::boring_path::accept_and_serve(
                    stream, peek, &ssl_cfg, lc, peer, live,
                )
                .await;
            }
            #[cfg(all(feature = "tls_rustls", not(feature = "tls_boring")))]
            {
                return crate::server::tls::rustls_path::accept_and_serve(
                    stream, peek, &ssl_cfg, lc, peer, live,
                )
                .await;
            }
            #[cfg(not(any(feature = "tls_boring", feature = "tls_rustls")))]
            anyhow::bail!("TLS feature disabled");
        }
    }
}
