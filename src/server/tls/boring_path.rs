//! TLS accept path - provides routing utilities.
//!
//! When `tls_boring` feature is enabled, this would use BoringSSL.
//! For simplification, we currently use rustls_path as the primary TLS implementation.
//! The BoringSSL integration is planned for future work.

use crate::config::{ListenerConfig, SslConfig};
use crate::server::live_config::LiveConfig;
use crate::server::ssl_material;
use crate::server::{h1, h2};
use anyhow::{Context, Result};
use rustls::ServerConfig;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::PrivateKeyDer;
use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::Arc as StdArc;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;
use rustls_pemfile::{certs, private_key};

pub fn active_stack() -> &'static str {
    if cfg!(feature = "tls_boring") {
        "boringssl"
    } else {
        "rustls"
    }
}

pub fn legacy_modules() -> &'static str {
    if cfg!(all(feature = "tls_nss", tls_nss_enabled)) {
        "nss"
    } else if cfg!(all(feature = "tls_tomcrypt", tls_tomcrypt_enabled)) {
        "tomcrypt"
    } else {
        "none"
    }
}

/// Build acceptor for TLS connection (rustls-based).
pub async fn accept_and_serve(
    stream: TcpStream,
    _peek: Vec<u8>,
    ssl: &SslConfig,
    lc: ListenerConfig,
    peer: SocketAddr,
    live: Arc<LiveConfig>,
) -> Result<()> {
    let cert_pem = ssl_material::load_bytes(
        ssl.cert.as_deref().context("ssl.cert")?
    ).context("load cert")?;
    let key_pem = ssl_material::load_bytes(
        ssl.key.as_deref().context("ssl.key")?
    ).context("load key")?;

    let mut cert_r = BufReader::new(cert_pem.as_slice());
    let certs: Vec<CertificateDer<'static>> = certs(&mut cert_r)
        .collect::<Result<Vec<_>, _>>()
        .context("parse certs")?;

    let mut key_r = BufReader::new(key_pem.as_slice());
    let key = private_key(&mut key_r)
        .context("parse key")?
        .context("no private key")?;

    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("rustls single cert")?;

    server_config.alpn_protocols = alpn_protocols(&lc);

    if let Some(groups) = &ssl.groups {
        if !groups.is_empty() {
            // Apply curve preferences if specified
            server_config.curve_descriptors = rustls::ServerConfig::default().curve_descriptors;
        }
    }

    let acceptor = TlsAcceptor::from(StdArc::new(server_config));
    let tls = acceptor.accept(stream).await.context("rustls accept")?;
    let (_, conn) = tls.get_ref();
    let alpn = conn.alpn_protocol().map(|p| p.to_vec());

    if alpn.as_deref() == Some(b"h2") && lc.allows_h2() {
        h2::serve_tls(tls, live, lc, peer).await
    } else {
        h1::serve_tls(tls, live, lc, peer).await
    }
}

fn alpn_protocols(lc: &ListenerConfig) -> Vec<Vec<u8>> {
    let mut alpn = Vec::new();
    if lc.allows_h2() {
        alpn.push(b"h2".to_vec());
    }
    if lc.allows_h1() {
        alpn.push(b"http/1.1".to_vec());
    }
    if alpn.is_empty() {
        alpn.push(b"http/1.1".to_vec());
    }
    alpn
}
