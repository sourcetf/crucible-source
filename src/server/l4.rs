//! L4 opaque TCP stream proxy (bidirectional copy), with the guards every
//! pre-HTTP path needs.
//!
//! **为什么例外的地方要用这个而不是自己内联 `io::copy`**：本模块的转发跑在
//! h1/h2/h3 **之前**（`l4_forward` 与 port_reuse 的 SNI 直通都是），所以不会继承它们
//! 任何一个超时。历史教训：port_reuse.rs 里曾有一份**带守卫**的实现，却没有任何调用者
//! （死代码），而 listener.rs 自己内联了一遍**不带守卫**的 —— 客户端连上什么都不发、
//! 或与一个不回包的目标互等，就能无限占用连接/FD/内存。所以现在只有这一个实现，
//! 两条路径都调它。

use anyhow::{Context, Result};
use std::net::SocketAddr;
use tokio::net::TcpStream;

/// 连接目标的上限时间：目标不响应时立刻放弃，而不是把 accept 资源一直挂住。
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
/// 两个方向共享的**空闲**超时：搬完一段数据就重新计时。
const IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Forward a TCP connection to an upstream until either side closes.
pub async fn proxy_tcp(client: TcpStream, upstream: SocketAddr) -> Result<()> {
    forward_guarded(client, upstream, &[])
        .await
        .with_context(|| format!("l4 forward {upstream}"))
}

/// 带守卫的双向转发；`prefix` 是调用方已经从客户端读走、需要先补发给上游的字节
/// （port_reuse 的 SNI 分流用 `try_read` 真的读走了 ClientHello 前缀）。
pub async fn forward_guarded(
    client: TcpStream,
    upstream: SocketAddr,
    prefix: &[u8],
) -> std::io::Result<()> {
    let mut up = match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(upstream)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("connect {upstream} 超时（{CONNECT_TIMEOUT:?}）"),
            ))
        }
    };
    if !prefix.is_empty() {
        use tokio::io::AsyncWriteExt;
        up.write_all(prefix).await?;
    }
    let (mut client_read, mut client_write) = client.into_split();
    let (mut up_read, mut up_write) = up.into_split();
    // 每个方向各一个「带空闲超时的 copy」：超时即结束该方向，try_join 随即收尾。
    let _ = tokio::try_join!(
        copy_idle(&mut client_read, &mut up_write),
        copy_idle(&mut up_read, &mut client_write),
    );
    Ok(())
}

/// `tokio::io::copy` + 每段数据之间的空闲超时（单段搬完就重置计时）。
async fn copy_idle<R, W>(r: &mut R, w: &mut W) -> std::io::Result<u64>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = vec![0u8; 16 * 1024];
    let mut total = 0u64;
    loop {
        let n = match tokio::time::timeout(IDLE_TIMEOUT, r.read(&mut buf)).await {
            Ok(Ok(0)) => return Ok(total), // EOF
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e),
            Err(_) => return Ok(total), // 空闲超时：正常收尾（对端可在其它方向继续）
        };
        w.write_all(&buf[..n]).await?;
        total += n as u64;
    }
}
