//! Tor 客户端代理支持。
//! SOCKS5 代理到 Tor 网络的透明代理。

use anyhow::{Context, Result};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// SOCKS5 代理连接
pub async fn connect_via_socks5(
    proxy_addr: SocketAddr,
    target: SocketAddr,
) -> Result<TcpStream> {
    let mut stream = TcpStream::connect(proxy_addr).await?;

    // SOCKS5 握手
    // 发送：版本 + 认证方法列表 (NO AUTH)
    let handshake = [0x05, 0x01, 0x00];
    stream.write_all(&handshake).await?;

    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await?;
    if resp[0] != 0x05 || resp[1] != 0x00 {
        anyhow::bail!("Socks5 handshake failed");
    }

    // 发送 CONNECT 请求
    let target_bytes = target_to_bytes(&target);
    let mut req = vec![0x05, 0x01, 0x00, 0x03];
    req.push(target_bytes.0.len() as u8);
    req.extend_from_slice(&target_bytes.0);
    req.extend_from_slice(&target_bytes.1.to_be_bytes());
    stream.write_all(&req).await?;

    let mut resp = [0u8; 4];
    stream.read_exact(&mut resp).await?;
    if resp[1] != 0x00 {
        anyhow::bail!("Socks5 connect failed: code {}", resp[1]);
    }

    Ok(stream)
}

fn target_to_bytes(target: &SocketAddr) -> (Vec<u8>, u16) {
    match target {
        SocketAddr::V4(addr) => (addr.ip().octets().to_vec(), addr.port()),
        SocketAddr::V6(addr) => (addr.ip().octets().to_vec(), addr.port()),
    }
}
