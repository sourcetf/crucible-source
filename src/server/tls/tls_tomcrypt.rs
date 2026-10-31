//! libtomcrypt legacy TLS handler (SSLv2 records).
//!
//! Compiled only when feature `tls_tomcrypt` is enabled.
//! Truncated ClientHello probes are rejected in Rust before any C/RSA work
//! (LibTomCrypt `LTC_ARGCHK` calls `abort()` and cannot be caught by `catch_unwind`).

use crate::config::{ListenerConfig, SslConfig};
use crate::server::live_config::LiveConfig;
use crate::server::ssl_material;
use crate::server::tls::legacy_io::{relay_bridge_only, run_legacy_handshake, LegacyRelay};
use crate::server::{h1};
use anyhow::{Context, Result};
use std::ffi::CString;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

mod ffi {
    use std::os::raw::c_int;

    #[link(name = "crucible_tls_tomcrypt", kind = "static")]
    extern "C" {
        pub fn crucible_tomcrypt_init() -> c_int;
        pub fn crucible_tomcrypt_accept(
            relay_fd: c_int,
            peek: *const u8,
            peek_len: usize,
            cert_pem: *const u8,
            cert_len: usize,
            key_pem: *const u8,
            key_len: usize,
        ) -> *mut crucible_tomcrypt_conn;
        /// >=0 bytes (0 = EOF), -2 = would block, -1 = error.
        pub fn crucible_tomcrypt_read(conn: *mut crucible_tomcrypt_conn, buf: *mut u8, len: usize) -> isize;
        pub fn crucible_tomcrypt_write(conn: *mut crucible_tomcrypt_conn, buf: *const u8, len: usize) -> isize;
        /// 0 = drained, -2 = would block (partial), -1 = error.
        pub fn crucible_tomcrypt_flush(conn: *mut crucible_tomcrypt_conn) -> isize;
        /// Bytes still queued for the socket.
        pub fn crucible_tomcrypt_out_pending(conn: *mut crucible_tomcrypt_conn) -> isize;
        /// Bitmask: 1=readable, 2=writable, 4=wakeup, 0=timeout, -1=error.
        pub fn crucible_tomcrypt_poll(
            conn: *mut crucible_tomcrypt_conn,
            want_read: c_int,
            want_write: c_int,
            timeout_ms: c_int,
        ) -> c_int;
        pub fn crucible_tomcrypt_wakeup(conn: *mut crucible_tomcrypt_conn) -> c_int;
        pub fn crucible_tomcrypt_free(conn: *mut crucible_tomcrypt_conn);
    }

    pub enum crucible_tomcrypt_conn {}
}

/// TomCrypt 连接共享指针：引用计数归零时释放一次。
///
/// 所有 I/O 由唯一一条 poll 线程发起（见 [`spawn_poll_io`]），异步写侧只通过
/// mpsc 排队 + `wakeup()`（自管道）通知 poll 线程；因此 `crucible_tomcrypt_read`
/// 与 `flush` 之间没有并发调用。
struct TomcryptShared {
    conn: *mut ffi::crucible_tomcrypt_conn,
}

unsafe impl Send for TomcryptShared {}
unsafe impl Sync for TomcryptShared {}

/// `crucible_tomcrypt_read/flush` 的返回值：-2=would-block，其它负值=错误。
fn map_io(n: isize) -> io::Result<usize> {
    match n {
        -2 => Err(io::Error::from(io::ErrorKind::WouldBlock)),
        n if n < 0 => Err(io::Error::last_os_error()),
        n => Ok(n as usize),
    }
}

impl TomcryptShared {
    fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        if self.conn.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "tomcrypt closed",
            ));
        }
        map_io(unsafe { ffi::crucible_tomcrypt_read(self.conn, buf.as_mut_ptr(), buf.len()) })
    }

    fn write(&self, buf: &[u8]) -> io::Result<usize> {
        if self.conn.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "tomcrypt closed",
            ));
        }
        map_io(unsafe { ffi::crucible_tomcrypt_write(self.conn, buf.as_ptr(), buf.len()) })
    }

    /// Drain the C-side encrypted queue. `Ok(())` when fully written; would-block
    /// is surfaced as `ErrorKind::WouldBlock` so the poll loop can wait.
    fn flush(&self) -> io::Result<()> {
        if self.conn.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "tomcrypt closed",
            ));
        }
        let n = unsafe { ffi::crucible_tomcrypt_flush(self.conn) };
        map_io(n).map(|_| ())
    }

    fn out_pending(&self) -> usize {
        if self.conn.is_null() {
            return 0;
        }
        let n = unsafe { ffi::crucible_tomcrypt_out_pending(self.conn) };
        if n < 0 {
            0
        } else {
            n as usize
        }
    }

    fn poll(&self, want_read: bool, want_write: bool, timeout_ms: i32) -> io::Result<i32> {
        if self.conn.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "tomcrypt closed",
            ));
        }
        let rc = unsafe {
            ffi::crucible_tomcrypt_poll(
                self.conn,
                want_read as i32,
                want_write as i32,
                timeout_ms,
            )
        };
        if rc < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(rc)
        }
    }

    fn wakeup(&self) {
        if !self.conn.is_null() {
            unsafe {
                ffi::crucible_tomcrypt_wakeup(self.conn);
            }
        }
    }
}

impl Drop for TomcryptShared {
    fn drop(&mut self) {
        if !self.conn.is_null() {
            unsafe {
                ffi::crucible_tomcrypt_free(self.conn);
            }
            self.conn = std::ptr::null_mut();
        }
    }
}

/// 已建立 TomCrypt 连接的 async 侧。写方向把明文块交给 poll 线程并唤醒它；
/// 读方向从 poll 线程的通道取解密后的明文。
struct TomcryptPollIo {
    rx: tokio::sync::mpsc::Receiver<io::Result<Vec<u8>>>,
    chunk: Option<Vec<u8>>,
    off: usize,
    tx: Option<tokio::sync::mpsc::UnboundedSender<Vec<u8>>>,
    /// 仅用于 Drop 时唤醒即将退出的 poll 线程（持 Arc 保证 conn 指针有效）。
    shared: Arc<TomcryptShared>,
}

impl Drop for TomcryptPollIo {
    fn drop(&mut self) {
        // 关闭写通道，让 poll 线程写完剩余数据后收尾并发 FIN。
        self.tx.take();
        self.shared.wakeup();
    }
}

impl AsyncRead for TomcryptPollIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.chunk.is_none() {
            match self.rx.poll_recv(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Ok(data))) => {
                    if data.is_empty() {
                        return Poll::Ready(Ok(())); // 读线程显式 EOF
                    }
                    self.chunk = Some(data);
                    self.off = 0;
                }
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(e)),
                Poll::Ready(None) => return Poll::Ready(Ok(())),
            }
        }
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

impl AsyncWrite for TomcryptPollIo {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut TaskContext<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let Some(tx) = self.tx.as_ref() else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "tomcrypt poll thread gone",
            )));
        };
        match tx.send(data.to_vec()) {
            Ok(()) => {
                // 只有写侧知道队列里出现了新数据；唤醒可能正阻塞在 poll 的线程。
                self.shared.wakeup();
                Poll::Ready(Ok(data.len()))
            }
            Err(_) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "tomcrypt poll thread gone",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        // legacy 栈无 close_notify；poll 线程收尾时对 relay 做 SHUT_WR。
        Poll::Ready(Ok(()))
    }
}

const TC_IO_BUF: usize = 16 * 1024;
/// 写侧「零进展」上限：有排队响应但连续的 socket 写一个字节都推不进去（对端
/// 不读、内核发送缓冲持续全满）就强制关断，线程必有界。
const TC_IO_WRITE_IDLE: Duration = Duration::from_secs(60);

/// 启动唯一一条 poll 线程：非阻塞 read + flush + poll 双向驱动。
fn spawn_poll_io(shared: Arc<TomcryptShared>, relay: LegacyRelay) -> TomcryptPollIo {
    let (r_tx, r_rx) = tokio::sync::mpsc::channel::<io::Result<Vec<u8>>>(8);
    let (w_tx, mut w_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let thread_shared = Arc::clone(&shared);

    let _ = std::thread::Builder::new()
        .name("cruc-tc-io".into())
        .spawn(move || tc_poll_loop(thread_shared, relay, r_tx, &mut w_rx));

    TomcryptPollIo {
        rx: r_rx,
        chunk: None,
        off: 0,
        tx: Some(w_tx),
        shared,
    }
}

fn tc_poll_loop(
    shared: Arc<TomcryptShared>,
    relay: LegacyRelay,
    r_tx: tokio::sync::mpsc::Sender<io::Result<Vec<u8>>>,
    w_rx: &mut tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
) {
    let mut relay = Some(relay);
    let mut read_open = true;
    let mut write_closed = false;
    let mut last_progress = Instant::now();
    let mut last_pending = 0usize;
    let mut rbuf = vec![0u8; TC_IO_BUF];

    loop {
        // 1. 收集 async 写侧排队的明文并加密入 C 队列。通道断开 = h1 处理完整条连接。
        loop {
            match w_rx.try_recv() {
                Ok(data) => {
                    if let Err(e) = shared.write(&data) {
                        let _ = r_tx.blocking_send(Err(e));
                        if let Some(r) = relay.take() {
                            r.shutdown_send();
                        }
                        return;
                    }
                }
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                    write_closed = true;
                    break;
                }
            }
        }

        // 2. 把 C 队列里的密文推给内核（非阻塞；排空或 would-block）。
        if let Err(e) = shared.flush() {
            if e.kind() != io::ErrorKind::WouldBlock {
                let _ = r_tx.blocking_send(Err(e));
                break;
            }
        }

        // 3. 非阻塞读：staged 整条记录 → 明文；would-block 则等待。
        if read_open {
            loop {
                match shared.read(&mut rbuf) {
                    Ok(0) => {
                        let _ = r_tx.blocking_send(Ok(Vec::new()));
                        read_open = false;
                        break;
                    }
                    Ok(n) => {
                        if r_tx.blocking_send(Ok(rbuf[..n].to_vec())).is_err() {
                            read_open = false;
                            break;
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => {
                        // 遗留客户端通常直接 close（无 close_notify）：按 EOF 处理，
                        // 让已排队的响应仍能写完。
                        log::debug!(target: "tls_tomcrypt", "tomcrypt poll read end: {e}");
                        let _ = r_tx.blocking_send(Ok(Vec::new()));
                        read_open = false;
                        break;
                    }
                }
            }
        }

        // 4. 退出/防永久阻塞：排队响应零进展超时则强行关断。
        let pending = shared.out_pending();
        if pending != last_pending {
            last_pending = pending;
            last_progress = Instant::now();
        }
        if write_closed && pending == 0 {
            break;
        }
        if pending > 0 && last_progress.elapsed() >= TC_IO_WRITE_IDLE {
            if let Some(r) = relay.as_ref() {
                r.interrupt();
            }
            break;
        }

        // 5. 阻塞等待：{relay fd 可读/可写, wakeup event}。
        let want_write = pending > 0;
        let timeout_ms = if want_write { 250 } else { -1 };
        match shared.poll(read_open, want_write, timeout_ms) {
            Ok(_) => {}
            Err(_) => {
                let _ = r_tx.blocking_send(Ok(Vec::new()));
                break;
            }
        }
    }

    // 统一收尾：显式 FIN（遗留栈没有 close_notify）；C 连接在 Arc 归零时释放。
    if let Some(r) = relay.take() {
        r.shutdown_send();
    }
}

/// True when peek is a complete SSLv2 CLIENT-HELLO we are willing to hand to C.
fn sslv2_hello_complete(peek: &[u8]) -> bool {
    if peek.len() < 11 || peek[0] & 0x80 == 0 || peek[2] != 0x01 {
        return false;
    }
    if !(peek[3] == 0x00 && peek[4] == 0x02) {
        return false;
    }
    let cipher_len = u16::from_be_bytes([peek[5], peek[6]]) as usize;
    let session_len = u16::from_be_bytes([peek[7], peek[8]]) as usize;
    let challenge_len = u16::from_be_bytes([peek[9], peek[10]]) as usize;
    if challenge_len == 0 || challenge_len > 32 || cipher_len > 256 || session_len > 256 {
        return false;
    }
    let need = 11usize.saturating_add(cipher_len).saturating_add(session_len).saturating_add(challenge_len);
    peek.len() >= need
}

pub async fn accept_and_serve(
    stream: TcpStream,
    peek: Vec<u8>,
    ssl: &SslConfig,
    lc: ListenerConfig,
    peer: SocketAddr,
    live: Arc<LiveConfig>,
) -> Result<()> {
    let peek_len = peek.len();
    // Soft-reject incomplete probes in Rust — never enter C/RSA for truncated hellos.
    // debug, not info: anonymous clients can trigger this per connection (a few
    // bytes are enough), and this file is compiled into the public TLS listener.
    if !sslv2_hello_complete(&peek) {
        log::debug!(
            target: "tls_tomcrypt",
            "tomcrypt soft-reject incomplete/probe SSLv2 hello peer={peer} peek_len={peek_len}"
        );
        drop(stream);
        return Ok(());
    }

    match accept_and_serve_inner(stream, peek, ssl, lc, peer, live).await {
        Ok(()) => Ok(()),
        Err(e) => {
            // Never escalate legacy failures into process-killing panics.
            // 只写短原因（同 accept.rs / tls_nss.rs）：`{e:#}` 可能带着客户端字节。
            // 节流：匿名客户端发个 SSLv2 hello 就能触发，逐连接 warn 会刷盘。
            crate::server::log_throttle::warn_every(
                "tls-tomcrypt-softfail",
                std::time::Duration::from_secs(60),
                &format!(
                    "tomcrypt legacy TLS soft-fail peer={peer} peek_len={peek_len}: {}",
                    crate::server::tls::handshake_failure_reason(&e)
                ),
            );
            log::debug!(target: "tls_tomcrypt", "tomcrypt soft-fail peer={peer} 完整错误: {e:#}");
            Ok(())
        }
    }
}

async fn accept_and_serve_inner(
    stream: TcpStream,
    peek: Vec<u8>,
    ssl: &SslConfig,
    lc: ListenerConfig,
    peer: SocketAddr,
    live: Arc<LiveConfig>,
) -> Result<()> {
    log::debug!(
        target: "tls_tomcrypt",
        "tomcrypt accept_and_serve peer={peer} peek_len={}",
        peek.len()
    );

    // **先**初始化，再创建 relay fd。原来 init 在 `spawn_blocking` 闭包里、晚于
    // `relay_bridge_only`（后者 `into_raw_fd()` 了 relay 描述符）：init 失败即 `?` 返回，
    // 裸 fd 无人持有 ⇒ **每条连接泄漏一个 fd**（init 失败会永久失败，匿名可发的
    // SSLv2 hello 就能把 fd 耗尽）。放到 fd 创建之前，失败路径就没有 fd 可漏。
    if unsafe { ffi::crucible_tomcrypt_init() } != 0 {
        anyhow::bail!("tomcrypt init failed");
    }

    let cert_pem = ssl_material::load_bytes(ssl.cert.as_deref().context("ssl.cert")?)?;
    let key_pem = ssl_material::load_bytes(ssl.key.as_deref().context("ssl.key")?)?;
    // NUL-terminate for C PEM parsers (length-bounded, but keep CString as belt+suspenders).
    let cert_c = CString::new(cert_pem).context("cert PEM contains NUL")?;
    let key_c = CString::new(key_pem).context("key PEM contains NUL")?;

    let relay = relay_bridge_only(stream).await?;
    let relay_fd = relay.c_fd().context("tomcrypt relay dup")?;
    let peek_copy = peek;
    let peer_log = peer;

    // O8：10s 绝对 deadline + 并发上限；超时 shutdown(relay) 打断 C 侧阻塞读。
    let shared = run_legacy_handshake(&relay, move || -> Result<Arc<TomcryptShared>> {
        let relay_fd = relay_fd.into_raw();
        unsafe {
            let ptr = ffi::crucible_tomcrypt_accept(
                relay_fd,
                peek_copy.as_ptr(),
                peek_copy.len(),
                cert_c.as_ptr() as *const u8,
                cert_c.as_bytes().len(),
                key_c.as_ptr() as *const u8,
                key_c.as_bytes().len(),
            );
            if ptr.is_null() {
                anyhow::bail!("crucible_tomcrypt_accept failed");
            }
            log::debug!(target: "tls_tomcrypt", "tomcrypt handshake accepted peer={peer_log}");
            Ok(Arc::new(TomcryptShared { conn: ptr }))
        }
    })
    .await
    .context("tomcrypt handshake")??;
    // C 侧持有 relay fd 的 dup。Rust 这份的所有权交给唯一 poll 线程：响应写完后
    // 由它对 relay 做 SHUT_WR，客户端才能收到 FIN（遗留栈无 close_notify）。
    // G-04：已建立连接 1 条 OS 线程（旧实现读+写各 1 条 = 2 条；relay 是 tokio
    // 任务，无 OS 线程）。非阻塞 read/flush + poll 在同一线程内多路复用。
    let io = spawn_poll_io(shared, relay);
    h1::serve_tls(io, live, lc, peer).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::tls::client_hello::{route, HelloRoute};

    #[test]
    fn sslv2_routes_tomcrypt_classifier() {
        // Incomplete probe blob — routing soft-drops before TomCrypt.
        let hello = [0x80u8, 0x12, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10];
        assert_eq!(route(&hello), HelloRoute::Boring);
    }

    #[test]
    fn truncated_probe_incomplete() {
        // Same blob as scripts/test_sslv2_probe.py — challenge claims 16 bytes but wire short.
        let hello = [
            0x80u8, 0x12, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(!sslv2_hello_complete(&hello));
    }
}
