//! Bidirectional TCP ↔ relay bridge for legacy TLS handshakes (NSS / TomCrypt).
//!
//! # Thread model (O8)
//!
//! The relay direction is bridged by a **tokio task** (`copy_bidirectional`),
//! not by the two `std::thread`s the old implementation spawned per connection.
//! Together with [`LegacySyncIo`] (one reader + one writer thread, created only
//! *after* a successful handshake) an established legacy connection uses at
//! most two OS threads instead of four. During the handshake the C stack runs
//! in one `spawn_blocking` slot, bounded by [`LEGACY_HANDSHAKE_MAX_CONCURRENT`]
//! and a hard [`LEGACY_HANDSHAKE_TIMEOUT`] deadline.

use anyhow::Context as _;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream as StdTcpStream};
use std::os::unix::io::{IntoRawFd, RawFd};
use std::pin::Pin;
use std::sync::OnceLock;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

/// Hard deadline covering both waiting for a handshake slot and the legacy
/// handshake itself (NSS `SSL_ForceHandshake` / TomCrypt record exchange).
/// BoringSSL uses 30s; a slow legacy handshake must not pin resources longer.
pub const LEGACY_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Upper bound on concurrently running C handshakes. Each one occupies a
/// `spawn_blocking` thread blocked in `read(2)`. 100 slow handshakes in the
/// stress test all get a slot; beyond this, callers wait under the same
/// deadline and are then dropped (never unbounded thread growth).
pub const LEGACY_HANDSHAKE_MAX_CONCURRENT: usize = 128;

fn handshake_slots() -> &'static Semaphore {
    static SLOTS: OnceLock<Semaphore> = OnceLock::new();
    SLOTS.get_or_init(|| Semaphore::new(LEGACY_HANDSHAKE_MAX_CONCURRENT))
}

/// Relay socket handed to a C legacy stack. The fd is kept by Rust (for
/// `shutdown(2)` on timeout); the C side gets its own `dup()` so a C close can
/// never invalidate the fd Rust may still shut down.
pub struct LegacyRelay {
    fd: RawFd,
}

/// Owned duplicate of a relay fd destined for C.
///
/// Between `dup(2)` and the C call several failure paths can return early
/// (semaphore timeout, join error). This guard closes the duplicate unless the
/// caller explicitly hands it to C via [`LegacyRelayFd::into_raw`], so those
/// paths cannot leak an fd per rejected connection.
pub struct LegacyRelayFd(RawFd);

impl LegacyRelayFd {
    /// Transfer ownership to the C shim (which closes it via `crucible_*_free`).
    pub fn into_raw(self) -> RawFd {
        let fd = self.0;
        std::mem::forget(self);
        fd
    }
}

impl Drop for LegacyRelayFd {
    fn drop(&mut self) {
        // SAFETY: sole owner of this duplicate.
        unsafe {
            libc::close(self.0);
        }
    }
}

impl LegacyRelay {
    /// Duplicate the relay fd for the C shim. The returned guard must be
    /// `into_raw()`d immediately before the FFI call; on any earlier failure it
    /// is closed automatically.
    pub fn c_fd(&self) -> std::io::Result<LegacyRelayFd> {
        let fd = unsafe { libc::dup(self.fd) };
        if fd < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(LegacyRelayFd(fd))
        }
    }

    /// Interrupt a handshake blocked in `read(2)`/`write(2)`: `shutdown(2)` on
    /// the relay makes the C side see EOF/EPIPE immediately (both directions).
    pub fn interrupt(&self) {
        // SAFETY: fd is a live socket owned by this struct.
        unsafe {
            libc::shutdown(self.fd, libc::SHUT_RDWR);
        }
    }
}

impl Drop for LegacyRelay {
    fn drop(&mut self) {
        // SAFETY: sole owner of this fd (C received a dup).
        unsafe {
            libc::close(self.fd);
        }
    }
}

/// Run a blocking C handshake with a hard deadline and a concurrency cap.
///
/// `f` runs in `spawn_blocking`; on timeout the relay socket is shut down so
/// the blocked `read(2)` returns, then the task is given a short grace period
/// to unwind. This deliberately does NOT leak a thread per slow client.
pub async fn run_legacy_handshake<T, F>(relay: &LegacyRelay, f: F) -> anyhow::Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let deadline = tokio::time::Instant::now() + LEGACY_HANDSHAKE_TIMEOUT;
    let _permit = match tokio::time::timeout_at(deadline, handshake_slots().acquire()).await {
        Ok(Ok(permit)) => permit,
        Ok(Err(_)) => anyhow::bail!("legacy handshake slots closed"),
        Err(_) => anyhow::bail!(
            "legacy handshake slots busy (>{}s)",
            LEGACY_HANDSHAKE_TIMEOUT.as_secs()
        ),
    };
    let mut handle = tokio::task::spawn_blocking(f);
    match tokio::time::timeout_at(deadline, &mut handle).await {
        Ok(joined) => Ok(joined.context("legacy handshake join")?),
        Err(_) => {
            relay.interrupt();
            // shutdown(2) wakes read(2); give the C shim a moment to free its
            // duplicate fd and release the blocking thread.
            let _ = tokio::time::timeout(Duration::from_secs(2), &mut handle).await;
            anyhow::bail!(
                "legacy handshake timeout after {}s",
                LEGACY_HANDSHAKE_TIMEOUT.as_secs()
            )
        }
    }
}

/// 建一对**回环 TCP** 连接当 legacy 栈的 relay。
///
/// 为什么不能用 `UnixStream::pair()`：NSS 的 `PR_ImportTCPSocket` 接受任意 fd，
/// 但握手途中会按 TCP socket 处理（`getsockname`/socket option 等）。AF_UNIX 在
/// 这一步返回 `PR_ADDRESS_NOT_SUPPORTED_ERROR (-5985)`，于是 `SSL_ForceHandshake`
/// 立刻失败 —— 实测：真实 webserver 里每条 NSS 连接都 `crucible_nss_accept returned
/// null`，而单测/独立 harness 用真实 TCP fd 时一切正常（同一份 shim、同一张证书）。
/// 回环 TCP 对 NSS 就是普通 TCP，对 TomCrypt 的裸 read/write 也毫无区别。
fn loopback_tcp_pair() -> anyhow::Result<(StdTcpStream, StdTcpStream)> {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .map_err(|e| anyhow::anyhow!("relay listener bind: {e}"))?;
    let addr = listener
        .local_addr()
        .map_err(|e| anyhow::anyhow!("relay listener local_addr: {e}"))?;
    let tx = StdTcpStream::connect(addr).map_err(|e| anyhow::anyhow!("relay connect: {e}"))?;
    let (rx, _peer) = listener
        .accept()
        .map_err(|e| anyhow::anyhow!("relay accept: {e}"))?;
    for s in [&tx, &rx] {
        s.set_nonblocking(false)
            .map_err(|e| anyhow::anyhow!("relay set_nonblocking: {e}"))?;
    }
    Ok((tx, rx))
}

/// Bridge the real client socket to the relay's peer **without OS threads**.
///
/// `relay_tx` is switched to nonblocking and handed to a tokio task; the C
/// stack keeps blocking semantics on `relay_rx`. `copy_bidirectional`
/// propagates EOF with half-closes in both directions.
fn spawn_async_bridge(mut tcp: TcpStream, relay_tx: StdTcpStream) -> anyhow::Result<()> {
    relay_tx
        .set_nonblocking(true)
        .map_err(|e| anyhow::anyhow!("relay_tx set_nonblocking: {e}"))?;
    let mut relay_tx =
        TcpStream::from_std(relay_tx).map_err(|e| anyhow::anyhow!("relay_tx from_std: {e}"))?;
    tokio::spawn(async move {
        let _ = tokio::io::copy_bidirectional(&mut tcp, &mut relay_tx).await;
        // Both directions ended (peer closed or shutdown(2) from the timeout
        // path): dropping both streams closes the client connection.
    });
    Ok(())
}

/// Write peek to relay peer, bridge tcp ↔ relay, return the relay for the C shim.
/// Use for NSS (reads only from the fd — needs ClientHello reinjected on the wire).
pub async fn relay_with_peek(stream: TcpStream, peek: Vec<u8>) -> anyhow::Result<LegacyRelay> {
    let (mut relay_tx, relay_rx) = loopback_tcp_pair()?;
    relay_tx
        .write_all(&peek)
        .map_err(|e| anyhow::anyhow!("relay peek write: {e}"))?;
    spawn_async_bridge(stream, relay_tx)?;
    Ok(LegacyRelay {
        fd: relay_rx.into_raw_fd(),
    })
}

/// Bridge tcp ↔ relay **without** writing peek (TomCrypt owns peek via `peek_io`).
/// Writing peek here AND into peek_io double-feeds ClientHello as a fake CMK and can abort.
pub async fn relay_bridge_only(stream: TcpStream) -> anyhow::Result<LegacyRelay> {
    let (relay_tx, relay_rx) = loopback_tcp_pair()?;
    spawn_async_bridge(stream, relay_tx)?;
    Ok(LegacyRelay {
        fd: relay_rx.into_raw_fd(),
    })
}

/// 桥接阻塞 legacy Read/Write（NSS PR_Read / TomCrypt read）到 async。
///
/// 健壮性修复（任务 6）：旧实现把阻塞 read/write 直接放进 poll_read/poll_write 的
/// `block_in_place`——worker_threads=2 时两个慢 legacy 客户端就能占死全部 executor
/// 线程。新实现为每条连接开一对专用阻塞线程，经 tokio mpsc 与 async 侧交换：
/// - 读侧 bounded(8)：`Receiver::poll_recv` 正确注册 waker，天然背压；
/// - 写侧 unbounded：legacy 响应体在本服务侧已 ≤16MiB（read_file_capped），
///   无无界内存面；Sender 无 poll_ready（tokio 1.53），unbounded 避免假 Pending 死锁。
/// 调用方需把连接拆成读写两个 half（NSS/TomCrypt 的同一描述符并发读写由
/// NSPR/shim 内部锁保护，TLS 全双工语义）。
pub struct LegacySyncIo {
    rx: tokio::sync::mpsc::Receiver<std::io::Result<Vec<u8>>>,
    chunk: Option<Vec<u8>>,
    off: usize,
    tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
}

const LEGACY_READ_BUF: usize = 16 * 1024;

impl LegacySyncIo {
    fn new<R: Read + Send + 'static, W: Write + Send + 'static>(
        mut reader: R,
        mut writer: W,
    ) -> Self {
        let (r_tx, r_rx) = tokio::sync::mpsc::channel::<std::io::Result<Vec<u8>>>(8);
        let (w_tx, mut w_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();

        // 读线程：阻塞 read → 通道（Ok(空 Vec) 表示 EOF）。
        let _ = std::thread::Builder::new()
            .name("cruc-legacy-rd".into())
            .spawn(move || {
                let mut buf = vec![0u8; LEGACY_READ_BUF];
                loop {
                    match reader.read(&mut buf) {
                        Ok(0) => {
                            let _ = r_tx.blocking_send(Ok(Vec::new()));
                            break;
                        }
                        Ok(n) => {
                            if r_tx.blocking_send(Ok(buf[..n].to_vec())).is_err() {
                                break; // async 侧已 drop
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(e) => {
                            let _ = r_tx.blocking_send(Err(e));
                            break;
                        }
                    }
                }
            });

        // 写线程：通道 → 阻塞 write_all；通道关闭（async 侧 drop）后 flush 收尾。
        let _ = std::thread::Builder::new()
            .name("cruc-legacy-wr".into())
            .spawn(move || {
                while let Some(data) = w_rx.blocking_recv() {
                    if writer.write_all(&data).is_err() {
                        break;
                    }
                }
                let _ = writer.flush();
            });

        Self {
            rx: r_rx,
            chunk: None,
            off: 0,
            tx: w_tx,
        }
    }
}

impl AsyncRead for LegacySyncIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // 先消费上次取回但未读完的残余。
        if self.chunk.is_none() {
            match self.rx.poll_recv(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Ok(data))) => {
                    if data.is_empty() {
                        // 读线程显式 EOF
                        return Poll::Ready(Ok(()));
                    }
                    self.chunk = Some(data);
                    self.off = 0;
                }
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(e)),
                Poll::Ready(None) => return Poll::Ready(Ok(())), // 读线程退出 → EOF
            }
        }
        // 借用拆分：chunk 借用域内只读，游标更新放在域外（E0502）。
        let n = {
            let chunk = self.chunk.as_ref().expect("chunk set above");
            let take = (chunk.len() - self.off).min(buf.remaining());
            buf.put_slice(&chunk[self.off..self.off + take]);
            take
        };
        self.off += n;
        if self
            .chunk
            .as_ref()
            .is_some_and(|c| self.off >= c.len())
        {
            self.chunk = None;
            self.off = 0;
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for LegacySyncIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        match self.tx.send(data.to_vec()) {
            Ok(()) => Poll::Ready(Ok(data.len())),
            Err(_) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "legacy writer thread gone",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // 写线程按序 write_all，无需额外 flush。
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // legacy 栈不支持 close_notify：drop 时由线程收尾（flush 后退出）。
        Poll::Ready(Ok(()))
    }
}

/// 把同一阻塞连接拆成「读 half + 写 half」交给桥的两个线程；
/// 底层描述符的并发读写线程安全由 C 栈保证（见各 Half 文档）。
pub fn sync_io_bridge<R, W>(reader: R, writer: W) -> LegacySyncIo
where
    R: Read + Send + 'static,
    W: Write + Send + 'static,
{
    LegacySyncIo::new(reader, writer)
}
