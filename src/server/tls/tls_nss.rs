//! NSS legacy TLS handshake handler (SSLv3 / IE6 v2-compatible hello).
//!
//! Compiled only when feature `tls_nss` is enabled.
//!
//! # Thread model (G-04)
//!
//! Per connection:
//! - handshake: one `spawn_blocking` slot running the C `SSL_ForceHandshake`
//!   (blocking fd), bounded by [`LEGACY_HANDSHAKE_MAX_CONCURRENT`] and the 10s
//!   [`LEGACY_HANDSHAKE_TIMEOUT`] deadline; on timeout `shutdown(2)` on the
//!   relay interrupts `read(2)` and the slot is released;
//! - established: **one** dedicated poll thread ("cruc-nss-io"). It calls
//!   non-blocking `PR_Read`/`PR_Write` and blocks in `PR_Poll` on
//!   {SSL fd, pollable event}; the async writer side sets the pollable event
//!   (`crucible_nss_wakeup`) whenever it queues response bytes. The previous
//!   design used one reader thread + one writer thread (2 OS threads); the
//!   relay itself is a tokio task (`copy_bidirectional`, no OS thread).
//!
//! NSS's non-blocking `PR_Write` contract makes a single thread sufficient:
//! `ssl3_SendApplicationData` never consumes the whole user buffer into its
//! internal ciphertext `pendingBuf` without leaving the last byte unconsumed
//! (`appDataBuffered`), so retrying the exact remainder sends the buffered
//! ciphertext first. FIN on close stays an explicit `shutdown(SHUT_WR)` on the
//! relay fd (legacy stacks have no close_notify).

use crate::config::{ListenerConfig, SslConfig};
use crate::server::live_config::LiveConfig;
use crate::server::ssl_material;
use crate::server::tls::legacy_io::{relay_with_peek, run_legacy_handshake, LegacyRelay};
use crate::server::{h1};
use anyhow::{Context, Result};
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

mod ffi {
    use std::os::raw::{c_int, c_uchar};

    #[link(name = "crucible_tls_nss", kind = "static")]
    extern "C" {
        pub fn crucible_nss_init(config_dir: *const u8) -> c_int;
        pub fn crucible_nss_accept(
            relay_fd: c_int,
            cert_pem: *const c_uchar,
            cert_len: usize,
            key_pem: *const c_uchar,
            key_len: usize,
        ) -> *mut crucible_nss_conn;
        pub fn crucible_nss_read(conn: *mut crucible_nss_conn, buf: *mut c_uchar, len: usize) -> isize;
        pub fn crucible_nss_write(
            conn: *mut crucible_nss_conn,
            buf: *const c_uchar,
            len: usize,
        ) -> isize;
        /// Bitmask: 1=readable, 2=writable, 4=wakeup, 0=timeout, -1=error.
        pub fn crucible_nss_poll(
            conn: *mut crucible_nss_conn,
            want_read: c_int,
            want_write: c_int,
            timeout_ms: c_int,
        ) -> c_int;
        pub fn crucible_nss_wakeup(conn: *mut crucible_nss_conn) -> c_int;
        pub fn crucible_nss_free(conn: *mut crucible_nss_conn);
    }

    #[allow(non_camel_case_types)]
    pub enum crucible_nss_conn {}
}


pub fn global_init() -> Result<()> {
    // NSS_Init 进程级只做一次（此前每条连接重复 init，既慢又有状态泄漏风险）。
    static INIT: std::sync::OnceLock<Result<(), String>> = std::sync::OnceLock::new();
    let res = INIT.get_or_init(|| {
        let rc = unsafe { ffi::crucible_nss_init(std::ptr::null()) };
        if rc != 0 {
            log::error!(target: "tls_nss", "NSS_Init failed rc={rc}");
            Err(format!("NSS_Init failed ({rc})"))
        } else {
            log::debug!(target: "tls_nss", "NSS_Init ok");
            Ok(())
        }
    });
    res.clone().map_err(anyhow::Error::msg)
}

/// NSS 连接共享指针：引用计数归零时释放，杜绝双重 free。
///
/// 所有 I/O 由唯一一条 poll 线程发起（见 [`spawn_poll_io`]），因此
/// PR_Read/PR_Write 之间没有并发调用；`wakeup` 可从 async 写侧线程调用
/// （NSPR pollable event 是线程安全的合并事件）。
struct NssShared {
    conn: *mut ffi::crucible_nss_conn,
}

unsafe impl Send for NssShared {}
unsafe impl Sync for NssShared {}

/// `crucible_nss_read/write` 的返回值：>=0 字节数（0=EOF），-2=would-block，
/// -1=错误（Shim 不把 NSPR 错误码当 errno 暴露，日志只记录类别）。
fn map_io(n: isize) -> io::Result<usize> {
    match n {
        -2 => Err(io::Error::from(io::ErrorKind::WouldBlock)),
        n if n < 0 => Err(io::Error::last_os_error()),
        n => Ok(n as usize),
    }
}

impl NssShared {
    fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        if self.conn.is_null() {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "nss closed"));
        }
        map_io(unsafe { ffi::crucible_nss_read(self.conn, buf.as_mut_ptr(), buf.len()) })
    }

    fn write(&self, buf: &[u8]) -> io::Result<usize> {
        if self.conn.is_null() {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "nss closed"));
        }
        map_io(unsafe { ffi::crucible_nss_write(self.conn, buf.as_ptr(), buf.len()) })
    }

    fn poll(&self, want_read: bool, want_write: bool, timeout_ms: i32) -> io::Result<i32> {
        if self.conn.is_null() {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "nss closed"));
        }
        let rc = unsafe {
            ffi::crucible_nss_poll(
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
                ffi::crucible_nss_wakeup(self.conn);
            }
        }
    }
}

impl Drop for NssShared {
    fn drop(&mut self) {
        if !self.conn.is_null() {
            unsafe {
                ffi::crucible_nss_free(self.conn);
            }
            self.conn = std::ptr::null_mut();
        }
    }
}

/// 已建立 NSS 连接的 async 侧。写方向把明文块交给 poll 线程并唤醒它；
/// 读方向从 poll 线程的通道取解密后的明文。
struct NssPollIo {
    rx: tokio::sync::mpsc::Receiver<io::Result<Vec<u8>>>,
    chunk: Option<Vec<u8>>,
    off: usize,
    tx: Option<tokio::sync::mpsc::UnboundedSender<Vec<u8>>>,
    /// 仅用于 Drop 时唤醒即将退出的 poll 线程（持 Arc 保证 conn 指针有效）。
    shared: Arc<NssShared>,
}

impl Drop for NssPollIo {
    fn drop(&mut self) {
        // 关闭写通道，让 poll 线程写完剩余数据后收尾并发 FIN。
        self.tx.take();
        self.shared.wakeup();
    }
}

impl AsyncRead for NssPollIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // 消费上次取回但未读完的残余。
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

impl AsyncWrite for NssPollIo {
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
                "nss poll thread gone",
            )));
        };
        match tx.send(data.to_vec()) {
            Ok(()) => {
                // 只有写侧知道队列里出现了新数据；唤醒可能正阻塞在 PR_Poll
                // 的 poll 线程。
                self.shared.wakeup();
                Poll::Ready(Ok(data.len()))
            }
            Err(_) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "nss poll thread gone",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        // legacy 栈无 close_notify；写线程收尾时对 relay 做 SHUT_WR。
        Poll::Ready(Ok(()))
    }
}

const NSS_IO_BUF: usize = 16 * 1024;
/// 写侧「零进展」上限：有排队响应但 NSS 连续这么久一个字节都没能交给内核
/// （对端不读、内核发送缓冲全满）就强制关断，线程必有界。只要还在前进，
/// 慢客户端可以慢慢下载（响应体 ≤16MiB）；与 h1 的 body 空闲超时同量级。
const NSS_IO_WRITE_IDLE: Duration = Duration::from_secs(60);

/// 启动唯一一条 poll 线程：非阻塞 PR_Read/PR_Write + PR_Poll 双向驱动。
fn spawn_poll_io(shared: Arc<NssShared>, relay: LegacyRelay) -> NssPollIo {
    let (r_tx, r_rx) = tokio::sync::mpsc::channel::<io::Result<Vec<u8>>>(8);
    let (w_tx, mut w_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let thread_shared = Arc::clone(&shared);

    let _ = std::thread::Builder::new()
        .name("cruc-nss-io".into())
        .spawn(move || poll_loop(thread_shared, relay, r_tx, &mut w_rx));

    NssPollIo {
        rx: r_rx,
        chunk: None,
        off: 0,
        tx: Some(w_tx),
        shared,
    }
}

fn poll_loop(
    shared: Arc<NssShared>,
    relay: LegacyRelay,
    r_tx: tokio::sync::mpsc::Sender<io::Result<Vec<u8>>>,
    w_rx: &mut tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
) {
    let mut relay = Some(relay);
    let mut pending: Vec<u8> = Vec::new();
    let mut off = 0usize;
    let mut read_open = true;
    let mut write_closed = false;
    let mut last_write_progress = Instant::now();
    let mut rbuf = vec![0u8; NSS_IO_BUF];

    loop {
        // 1. 收集 async 写侧排队的明文。通道断开 = h1 处理完整条连接。
        loop {
            match w_rx.try_recv() {
                Ok(data) => pending.extend_from_slice(&data),
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                    write_closed = true;
                    break;
                }
            }
        }
        if off > 0 {
            if off >= pending.len() {
                pending.clear();
                off = 0;
            } else if off >= NSS_IO_BUF {
                pending.drain(..off);
                off = 0;
            }
        }

        // 2. 非阻塞写。NSS 的 PR_Write 返回「已消费的明文字节数」；
        //    按返回值前进、保留剩余字节重试，就等于让 NSS 先把内部
        //    pendingBuf 里的密文发完（见模块文档）。
        let mut write_err: Option<io::Error> = None;
        while off < pending.len() {
            match shared.write(&pending[off..]) {
                Ok(0) => break,
                Ok(n) => {
                    off += n;
                    last_write_progress = Instant::now();
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    write_err = Some(e);
                    break;
                }
            }
        }
        if let Some(e) = write_err {
            log::debug!(target: "tls_nss", "nss poll write end: {e}");
            let _ = r_tx.blocking_send(Err(e));
            break;
        }
        if off >= pending.len() {
            pending.clear();
            off = 0;
        }

        // 3. 非阻塞读（先读再 poll：NSS 可能已在握手/上一次读时缓冲了明文）。
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
                        // 遗留客户端通常直接 close（无 close_notify），NSS 报
                        // PR_END_OF_FILE_ERROR；按 EOF 处理，让已排队的响应仍能写完。
                        log::debug!(target: "tls_nss", "nss poll read end: {e}");
                        let _ = r_tx.blocking_send(Ok(Vec::new()));
                        read_open = false;
                        break;
                    }
                }
            }
        }

        // 4. 退出条件。
        let pending_done = off >= pending.len();
        if write_closed && pending_done {
            break;
        }
        if !pending_done && last_write_progress.elapsed() >= NSS_IO_WRITE_IDLE {
            // 对端不读、内核发送缓冲持续满：先 shutdown 打断 relay，再放弃剩余响应。
            if let Some(r) = relay.as_ref() {
                r.interrupt();
            }
            break;
        }

        // 5. 阻塞等待：{SSL fd 可读/可写, wakeup event}。
        // 有未写完数据时用短超时轮询「零进展」期限；否则阻塞到事件。
        let want_write = !pending_done;
        let timeout_ms = if pending_done { -1 } else { 250 };
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

/// Accept legacy ClientHello via NSS (bidirectional relay + SSL PR_Read/Write).
pub async fn accept_and_serve(
    stream: TcpStream,
    peek: Vec<u8>,
    ssl: &SslConfig,
    lc: ListenerConfig,
    peer: SocketAddr,
    live: Arc<LiveConfig>,
) -> Result<()> {
    let peek_len = peek.len();
    match accept_and_serve_inner(stream, peek, ssl, lc, peer, live).await {
        Ok(()) => Ok(()),
        Err(e) => {
            // Soft-fail like TomCrypt — never escalate legacy failures into panics
            // or tear down the accept loop for other connections.
            // 只写短原因：完整错误链里可能带着客户端字节，`{e:#}` 会把它们全写进日志
            // （见 `tls::handshake_failure_reason` 的说明）。
            // 按类别+时间节流：这条路径匿名可触发（发一个 IE6 风格 hello 即可），
            // 逐连接 warn 等于给磁盘开一个按连接数计费的写入口。
            crate::server::log_throttle::warn_every(
                "tls-nss-softfail",
                std::time::Duration::from_secs(60),
                &format!(
                    "nss legacy TLS soft-fail peer={peer} peek_len={peek_len}: {}",
                    crate::server::tls::handshake_failure_reason(&e)
                ),
            );
            log::debug!(target: "tls_nss", "nss soft-fail peer={peer} 完整错误: {e:#}");
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
    let peek_len = peek.len();
    log::debug!(
        target: "tls_nss",
        "nss accept_and_serve peer={peer} peek_len={peek_len}"
    );

    // **先**做进程级初始化，再创建 relay fd。原来 init 放在 `spawn_blocking` 闭包里、
    // 晚于 `relay_with_peek`（后者 `into_raw_fd()` 了 relay 描述符）：一旦 init 失败就
    // 直接 `?` 返回，那个裸 fd 再没有任何人持有 ⇒ **每条走 NSS 的连接泄漏一个 fd**。
    // NSS_Init 失败是**永久性**的（`OnceLock` 缓存失败结果），而 IE6 风格的 hello 是
    // 匿名可发的 ⇒ 可以拿它把进程 fd 耗尽。提到 fd 创建之前，失败路径就没有 fd 可漏。
    global_init()?;

    let cert_pem = ssl_material::load_bytes(ssl.cert.as_deref().context("ssl.cert")?)
        .map_err(|e| {
            log::error!(target: "tls_nss", "nss: load cert failed peer={peer}: {e:#}");
            e
        })?;
    let key_pem = ssl_material::load_bytes(ssl.key.as_deref().context("ssl.key")?).map_err(|e| {
        log::error!(target: "tls_nss", "nss: load key failed peer={peer}: {e:#}");
        e
    })?;

    let relay = relay_with_peek(stream, peek).await.map_err(|e| {
        log::error!(target: "tls_nss", "nss: relay_with_peek failed peer={peer}: {e:#}");
        e
    })?;
    let relay_fd = relay.c_fd().context("nss relay dup")?;
    let cert = cert_pem.clone();
    let key = key_pem.clone();
    let peer_log = peer;

    // O8：10s 绝对 deadline + 并发上限；超时用 shutdown(relay) 打断阻塞的
    // SSL_ForceHandshake（以前 spawn_blocking 无超时，慢握手可长期占线程/fd）。
    let shared = run_legacy_handshake(&relay, move || -> Result<Arc<NssShared>> {
        let relay_fd = relay_fd.into_raw();
        let ptr = unsafe {
            ffi::crucible_nss_accept(
                relay_fd,
                cert.as_ptr(),
                cert.len(),
                key.as_ptr(),
                key.len(),
            )
        };
        if ptr.is_null() {
            log::error!(
                target: "tls_nss",
                "crucible_nss_accept returned null peer={peer_log}"
            );
            anyhow::bail!("crucible_nss_accept failed");
        }
        log::debug!(target: "tls_nss", "nss handshake accepted peer={peer_log}");
        Ok(Arc::new(NssShared { conn: ptr }))
    })
    .await
    .map_err(|e| {
        log::debug!(target: "tls_nss", "nss handshake failed peer={peer}: {e:#}");
        e
    })??;
    // C 侧持有 relay fd 的 dup。Rust 这份的所有权交给唯一 poll 线程：响应写完后
    // 由它对 relay 做 SHUT_WR，客户端才能收到 FIN（遗留栈无 close_notify）。
    // G-04：已建立连接 1 条 OS 线程（旧实现读+写各 1 条，共 2 条；再早是 relay
    // 2 条 + sync_io 2 条 = 4 条）。握手仍占 1 个 spawn_blocking 槽（≤128 并发）。
    let io = spawn_poll_io(shared, relay);
    h1::serve_tls(io, live, lc, peer).await.map_err(|e| {
        log::error!(target: "tls_nss", "nss h1::serve_tls failed peer={peer}: {e:#}");
        e
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::tls::client_hello::{route, HelloRoute};

    #[test]
    fn ie6_hello_classified_nss() {
        let hello = [0x80, 0x4a, 0x01, 0x03, 0x00, 0x00, 0x2f];
        assert_eq!(route(&hello), HelloRoute::Nss);
    }
}
