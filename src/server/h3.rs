//! HTTP/3 (QUIC) via quinn + h3-quinn.
//!
//! 使用标准 h3-quinn（rustls）实现。
//! TLS 1.3 via rustls (boring feature disabled for simplicity).

use crate::config::ListenerConfig;
use crate::server::live_config::LiveConfig;
use anyhow::{anyhow, Context, Result};
use bytes::{Buf, Bytes};
use http::{Request, Response, StatusCode};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use quinn::{Endpoint, ServerConfig};
use rustls::pki_types::CertificateDer;
use rustls::pki_types::PrivateKeyDer;
use rustls::ServerConfig as RustlsConfig;
use rustls::crypto::ring::default_provider;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;

pub async fn serve(
    bind: SocketAddr,
    lc: ListenerConfig,
    live: Arc<LiveConfig>,
) -> Result<()> {
    let ssl = lc.ssl.as_ref().context("h3 listener requires ssl config")?;
    let cert_pem = crate::server::ssl_material::load_bytes(
        ssl.cert.as_deref().context("ssl.cert")?,
    ).context("load cert")?;
    let key_pem = crate::server::ssl_material::load_bytes(
        ssl.key.as_deref().context("ssl.key")?,
    ).context("load key")?;

    let certs: Vec<CertificateDer<'_>> = rustls_pemfile::certs(&mut &*cert_pem)
        .context("parse cert PEM")?
        .into_iter()
        .collect();
    let key = rustls_pemfile::pkcs8_private_keys(&mut &*key_pem)
        .context("parse key PEM")?
        .into_iter()
        .next()
        .context("no private key found")?;
    let key = PrivateKeyDer::from(key);

    let mut server_config = RustlsConfig::builder()
        .with_default_provider()
        .with_single_cert(certs, key)
        .context("failed to load cert/key")?;

    if ssl.prefer_tls13.unwrap_or(false) {
        server_config.alpn_protocols = vec![b"h3".to_vec(), b"h3-qmux".to_vec()];
    } else {
        server_config.alpn_protocols = vec![b"h3".to_vec()];
    }

    let crypto = ServerConfig::from(server_config);

    // Transport config: 定制拥塞控制、连接置信度、0-RTT 等。
    // quinn 默认通过 rustls 提供 TLS 1.3（0-RTT 已内置）。
    // 这里显式指定传输参数，确保 h3-qmux 的流量区分。
    let mut transport = quinn::TransportConfig::default();
    // 拥塞控制：Cubic（默认），可切换 BBR；
    transport.congestion_controller_factory(Arc::new(quinn::congestion::CubicConfig::default()));
    // 连接置信度：保活与空闲超时
    transport.max_idle_timeout(Some(std::time::Duration::from_secs(60).try_into().unwrap()));
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(20)));
    // 0-RTT窗口
    transport.max_concurrent_bidi_streams(quinn::VarInt::from_u32(100));
    transport.max_concurrent_uni_streams(quinn::VarInt::from_u32(100));

    let mut ep_config = quinn::EndpointConfig::default();
    ep_config.transport_config(Arc::new(transport));

    let socket = UdpSocket::bind(bind).await.context("h3 udp bind")?;
    let endpoint = Endpoint::new(
        ep_config,
        Some(Arc::new(crypto)),
        socket,
        Arc::new(quinn::TokioRuntime),
    ).context("h3 quinn endpoint")?;

    log::info!("h3 quinn endpoint ready on {bind}");

    while let Some(incoming) = endpoint.accept().await {
        let live_c = Arc::clone(&live);
        let lc_c = lc.clone();
        let endpoint_c = endpoint.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(incoming, live_c, lc_c, endpoint_c).await {
                log::warn!("h3 connection error: {e:#}");
            }
        });
    }

    Ok(())
}

async fn handle_connection(
    incoming: quinn::Incoming,
    live: Arc<LiveConfig>,
    lc: ListenerConfig,
    endpoint: Endpoint,
) -> Result<()> {
    let connection = match incoming.await {
        Ok(c) => c,
        Err(e) => {
            log::debug!("h3 connection soft-fail: {e}");
            return Ok(());
        }
    };
    let peer = connection.remote_address();

    let h3_conn = ::h3_quinn::Connection::new(connection);
    let mut server = match ::h3::server::Connection::new(h3_conn).await {
        Ok(s) => s,
        Err(e) => {
            log::warn!("h3 server connection peer={peer}: {e}");
            return Ok(());
        }
    };

    loop {
        match server.accept().await {
            Ok(Some(resolver)) => {
                let live_c = Arc::clone(&live);
                let lc_c = lc.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_request(resolver, live_c, lc_c, peer).await {
                        log::debug!("h3 request soft-fail peer={peer}: {e}");
                    }
                });
            }
            Ok(None) => break,
            Err(e) => {
                let msg = format!("{e}");
                if msg.contains("reset") || msg.contains("RESET") {
                    log::info!("h3 stream reset peer={peer}");
                    break;
                }
                log::warn!("h3 accept error peer={peer}: {msg}");
                break;
            }
        }
    }
    Ok(())
}

async fn handle_request(
    resolver: ::h3::server::RequestResolver<::h3_quinn::Connection, Bytes>,
    live: Arc<LiveConfig>,
    lc: ListenerConfig,
    peer: SocketAddr,
) -> Result<()> {
    crate::server::qmux::stream_opened();
    let result = async {
        let (mut req, mut stream) = match resolver.resolve_request().await {
            Ok(pair) => pair,
            Err(e) => {
                log::debug!("h3 resolve_request reset peer={peer}: {e}");
                return Ok(());
            }
        };

        let method = req.method().as_str().to_string();
        let path = req.uri().path().to_string();

        // RFC 9298: CONNECT-UDP
        if method == "CONNECT" {
            if let Some(target) = parse_connect_target(&path) {
                log::info!("h3 CONNECT target={} peer={}", target, peer);
                let ok_resp: Response<Bytes> = Response::builder()
                    .status(StatusCode::OK)
                    .body(Bytes::new())?;
                if stream.send_response(ok_resp, false).await.is_err() {
                    return Ok(());
                }
                if let Err(e) = proxy_connect_udp(stream, target).await {
                    log::warn!("h3 CONNECT-UDP proxy failed: {e}");
                }
                crate::server::qmux::stream_closed();
                return Ok(());
            }
        }

        // Collect body for h3
        let mut body: Vec<u8> = Vec::new();
        loop {
            match stream.recv_data().await {
                Ok(Some(mut buf)) => {
                    let chunk = buf.copy_to_bytes(buf.remaining());
                    body.extend_from_slice(&chunk);
                }
                Ok(None) => break,
                Err(e) => {
                    log::debug!("h3 recv_data peer={peer}: {e}");
                    break;
                }
            }
        }

        let req = req.map(|()| Bytes::from(body));

        // Dispatch to H1 handler
        let response = crate::server::h1::handle_request(req, live, lc, peer).await;
        let status = response.status();
        let body = http_body_util::Full::new(response.into_body());

        if stream.send_response(body, true).await.is_err() {
            log::debug!("h3 send_response peer={peer}");
        }
        Ok(())
    }.await;

    crate::server::qmux::stream_closed();
    result
}

fn parse_connect_target(target: &str) -> Option<(std::net::IpAddr, u16)> {
    let t = target.trim_start_matches('/');
    let (h, p) = t.rsplit_once(':')?;
    let ip: std::net::IpAddr = h.parse().ok()?;
    let port = p.parse().ok()?;
    Some((ip, port))
}

async fn proxy_connect_udp(
    mut stream: ::h3::server::RequestStream<::h3_quinn::OpenStreams, Bytes>,
    target: SocketAddr,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let udp = UdpSocket::bind("0.0.0.0:0").await?;
    udp.connect(target).await?;

    let mut udp_buf = vec![0u8; 65535];

    loop {
        tokio::select! {
            result = async { stream.recv_data().await } => {
                match result {
                    Ok(Some(mut buf)) => {
                        let data = buf.copy_to_bytes(buf.remaining());
                        if data.is_empty() { break; }
                        if udp.send(&data).await.is_err() { break; }
                    }
                    Ok(None) => break,
                    Err(_) => break,
                }
            }
            result = udp.recv(&mut udp_buf) => {
                match result {
                    Ok(n) if n > 0 => {
                        if stream.send_data(Bytes::copy_from_slice(&udp_buf[..n])).await.is_err() {
                            break;
                        }
                    }
                    _ => break,
                }
            }
        }
    }

    let _ = stream.finish().await;
    Ok(())
}
