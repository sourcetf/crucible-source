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
        copy_idle(&mut client_read, &mut up_write, IDLE_TIMEOUT),
        copy_idle(&mut up_read, &mut client_write, IDLE_TIMEOUT),
    );
    Ok(())
}

/// `tokio::io::copy` + 每段数据之间的空闲超时（单段搬完就重置计时）。
///
/// `idle` 由调用方给：L4 用 [`IDLE_TIMEOUT`]，反代的 WebSocket 隧道用更宽松的
/// 上限（WS 可能长时间没有数据帧，但绝不能无限期挂住 —— 见 proxy::WS_IDLE_TIMEOUT）。
pub(crate) async fn copy_idle<R, W>(
    r: &mut R,
    w: &mut W,
    idle: std::time::Duration,
) -> std::io::Result<u64>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = vec![0u8; 16 * 1024];
    let mut total = 0u64;
    loop {
        let n = match tokio::time::timeout(idle, r.read(&mut buf)).await {
            Ok(Ok(0)) => return Ok(total), // EOF
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e),
            Err(_) => return Ok(total), // 空闲超时：正常收尾（对端可在其它方向继续）
        };
        w.write_all(&buf[..n]).await?;
        total += n as u64;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// 空闲超时必须在「对端一直不发数据」时返回，而不是永久挂住（WS 隧道复用它）。
    #[tokio::test]
    async fn copy_idle_returns_after_idle_timeout() {
        let (mut r, _keep_open) = tokio::io::duplex(64);
        let mut out: Vec<u8> = Vec::new();
        let t0 = std::time::Instant::now();
        let n = copy_idle(&mut r, &mut out, Duration::from_millis(50))
            .await
            .expect("空闲超时不是错误");
        assert_eq!(n, 0);
        assert!(
            t0.elapsed() >= Duration::from_millis(40),
            "应等满空闲预算，实际 {:?}",
            t0.elapsed()
        );
        assert!(out.is_empty());
    }

    /// 有数据时照常搬运，搬完后的静默同样按空闲超时收尾。
    #[tokio::test]
    async fn copy_idle_moves_bytes_then_times_out() {
        let (mut r, mut w_peer) = tokio::io::duplex(64);
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let _ = w_peer.write_all(b"hello").await;
            // 保持连接打开且不再发送：copy 写完 5 字节后必须按空闲超时返回。
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        let mut out: Vec<u8> = Vec::new();
        let t0 = std::time::Instant::now();
        let n = copy_idle(&mut r, &mut out, Duration::from_millis(80))
            .await
            .unwrap();
        assert_eq!(n, 5);
        assert_eq!(out, b"hello");
        assert!(t0.elapsed() < Duration::from_secs(5), "不得等到对端关闭");
    }
}
