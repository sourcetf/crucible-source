//! Bidirectional TCP ↔ relay bridge for legacy TLS handshakes (NSS / TomCrypt).
//!
//! # Thread model (O8 / G-04)
//!
//! The relay direction is bridged by a **tokio task** (`copy_bidirectional`),
//! not by the two `std::thread`s the old implementation spawned per connection.
//! The established connection itself is then driven by a **single** dedicated
//! poll thread inside each legacy stack (`tls_nss::spawn_poll_io` /
//! `tls_tomcrypt::spawn_poll_io`) — see those modules. During the handshake the
//! C stack runs in one `spawn_blocking` slot, bounded by
//! [`LEGACY_HANDSHAKE_MAX_CONCURRENT`] and a hard [`LEGACY_HANDSHAKE_TIMEOUT`]
//! deadline.

use anyhow::Context as _;
use std::io::Write as _;
use std::net::{TcpListener, TcpStream as StdTcpStream};
use std::os::unix::io::{IntoRawFd, RawFd};
use std::sync::OnceLock;
use std::time::Duration;
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

    /// Half-close the relay (FIN towards the client bridge). The C legacy
    /// stacks have no close_notify, and their fd stays open as long as the
    /// reader thread is blocked in `read(2)`; without this explicit FIN a
    /// completed HTTP/1.1 `Connection: close` response would never reach the
    /// client as EOF and both sides would wait until the client gives up.
    pub fn shutdown_send(self) {
        // SAFETY: fd is a live socket owned by this struct.
        unsafe {
            libc::shutdown(self.fd, libc::SHUT_WR);
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
