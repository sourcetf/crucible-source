//! L4 opaque / stream proxy.
//! §16.18 L4 不透明转发：l4_forward 配置后整条连接双向透传，不做 HTTP/TLS 解析。

use anyhow::{Context, Result};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// 透明 TCP 代理：上行→下行双向拷贝
pub async fn proxy_tcp(mut stream: TcpStream, dest: SocketAddr) -> Result<()> {
    let mut upstream =
        TcpStream::connect(dest).await.with_context(|| format!("connect to {dest}"))?;

    let (mut sr, mut sw) = stream.into_split();
    let (mut ur, mut uw) = upstream.into_split();

    let from_down = async {
        let mut buf = vec![0u8; 8192];
        loop {
            let n = sr.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            uw.write_all(&buf[..n]).await?;
        }
        Ok::<_, anyhow::Error>(())
    };

    let from_up = async {
        let mut buf = vec![0u8; 8192];
        loop {
            let n = ur.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            sw.write_all(&buf[..n]).await?;
        }
        Ok::<_, anyhow::Error>(())
    };

    tokio::try_join!(from_down, from_up)?;
    Ok(())
}
