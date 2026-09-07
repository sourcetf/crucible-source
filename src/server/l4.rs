//! L4 opaque TCP stream proxy (bidirectional copy).

use anyhow::{Context, Result};
use std::net::SocketAddr;
use tokio::net::TcpStream;

/// Forward a TCP connection to an upstream until either side closes.
pub async fn proxy_tcp(client: TcpStream, upstream: SocketAddr) -> Result<()> {
    let mut upstream = TcpStream::connect(upstream)
        .await
        .with_context(|| format!("l4 connect {upstream}"))?;
    let (mut client_read, mut client_write) = client.into_split();
    let (mut upstream_read, mut upstream_write) = upstream.into_split();

    let c1 = tokio::io::copy(&mut client_read, &mut upstream_write);
    let c2 = tokio::io::copy(&mut upstream_read, &mut client_write);
    match tokio::try_join!(c1, c2) {
        Ok(_) => Ok(()),
        Err(e) => Err(e).context("l4 copy"),
    }
}
