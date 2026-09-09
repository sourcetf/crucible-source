//! rustls fallback when `tls_boring` is not enabled (dev / minimal builds).

use crate::config::{ListenerConfig, SslConfig};
use crate::server::live_config::LiveConfig;
use crate::server::prefixed_stream::PrefixedStream;
use crate::server::ssl_material;
use crate::server::{h1, h2};
use anyhow::{Context, Result};
use rustls::ServerConfig;
use std::net::SocketAddr;
use std::sync::Arc as StdArc;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;

pub async fn accept_and_serve(
    stream: TcpStream,
    peek: Vec<u8>,
    ssl: &SslConfig,
    lc: ListenerConfig,
    peer: SocketAddr,
    live: Arc<LiveConfig>,
) -> Result<()> {
    let (certs, key) = load_certs_key(ssl)?;
    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("rustls single cert")?;
    server_config.alpn_protocols = alpn_protocols(&lc);
    let acceptor = TlsAcceptor::from(StdArc::new(server_config));
    let io = PrefixedStream::new(stream, peek);
    let tls = acceptor.accept(io).await.context("rustls accept")?;
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

fn load_certs_key(
    ssl: &SslConfig,
) -> Result<(
    Vec<rustls::pki_types::CertificateDer<'static>>,
    rustls::pki_types::PrivateKeyDer<'static>,
)> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use rustls_pemfile::{certs, private_key};
    use std::io::BufReader;

    let cert_pem = ssl_material::load_bytes(ssl.cert.as_deref().context("ssl.cert")?)?;
    let key_pem = ssl_material::load_bytes(ssl.key.as_deref().context("ssl.key")?)?;
    let mut cert_r = BufReader::new(cert_pem.as_slice());
    let certs: Vec<CertificateDer<'static>> = certs(&mut cert_r)
        .collect::<Result<Vec<_>, _>>()
        .context("parse certs")?;
    let mut key_r = BufReader::new(key_pem.as_slice());
    let key = private_key(&mut key_r)
        .context("parse key")?
        .context("no private key")?;
    Ok((certs, key))
}
