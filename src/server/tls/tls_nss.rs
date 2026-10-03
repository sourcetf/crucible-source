//! NSS legacy TLS handshake handler (SSLv3 / IE6 v2-compatible hello).
//!
//! Compiled only when feature `tls_nss` is enabled.

use crate::config::{ListenerConfig, SslConfig};
use crate::server::live_config::LiveConfig;
use crate::server::ssl_material;
use crate::server::tls::legacy_io::{relay_with_peek, sync_io_bridge};
use crate::server::{h1};
use anyhow::{Context, Result};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;

mod ffi {
    use std::os::raw::c_int;

    #[link(name = "crucible_tls_nss", kind = "static")]
    extern "C" {
        pub fn crucible_nss_init(config_dir: *const u8) -> c_int;
        pub fn crucible_nss_accept(
            relay_fd: c_int,
            cert_pem: *const u8,
            cert_len: usize,
            key_pem: *const u8,
            key_len: usize,
        ) -> *mut crucible_nss_conn;
        pub fn crucible_nss_read(conn: *mut crucible_nss_conn, buf: *mut u8, len: usize) -> isize;
        pub fn crucible_nss_write(conn: *mut crucible_nss_conn, buf: *const u8, len: usize) -> isize;
        pub fn crucible_nss_free(conn: *mut crucible_nss_conn);
    }

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

/// NSS 连接共享指针：PR_Read/PR_Write 在同一描述符上并发调用由 NSPR 内部锁保护
/// （TLS 全双工语义）；引用计数归零时释放，杜绝双重 free。
struct NssShared {
    conn: *mut ffi::crucible_nss_conn,
}

unsafe impl Send for NssShared {}
unsafe impl Sync for NssShared {}

impl NssShared {
    fn read(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.conn.is_null() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "nss closed",
            ));
        }
        let n = unsafe { ffi::crucible_nss_read(self.conn, buf.as_mut_ptr(), buf.len()) };
        if n < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }

    fn write(&self, buf: &[u8]) -> std::io::Result<usize> {
        if self.conn.is_null() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "nss closed",
            ));
        }
        let n = unsafe { ffi::crucible_nss_write(self.conn, buf.as_ptr(), buf.len()) };
        if n < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(n as usize)
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

/// 读写 half：Clone 共享同一 NssShared，分别交给桥的读/写线程。
#[derive(Clone)]
struct NssHalf {
    shared: Arc<NssShared>,
}

impl Read for NssHalf {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.shared.read(buf)
    }
}

impl Write for NssHalf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.shared.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
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
            log::warn!(
                target: "tls_nss",
                "nss legacy TLS soft-fail peer={peer} peek_len={peek_len}: {}",
                crate::server::tls::handshake_failure_reason(&e)
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
    log::info!(
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

    let relay_fd = relay_with_peek(stream, peek).await.map_err(|e| {
        log::error!(target: "tls_nss", "nss: relay_with_peek failed peer={peer}: {e:#}");
        e
    })?;
    let cert = cert_pem.clone();
    let key = key_pem.clone();
    let peer_log = peer;

    let shared = tokio::task::spawn_blocking(move || -> Result<Arc<NssShared>> {
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
        log::info!(target: "tls_nss", "nss handshake accepted peer={peer_log}");
        Ok(Arc::new(NssShared { conn: ptr }))
    })
    .await
    .map_err(|e| {
        log::error!(target: "tls_nss", "nss join error peer={peer}: {e}");
        e
    })
    .context("nss join")??;

    // 任务 6：阻塞 IO 移出 executor——读写线程 + mpsc 桥；同一描述符的并发读写
    // 由 NSPR 内部锁保证（全双工），Drop 只在最后一个 half 释放时 free 一次。
    let io = sync_io_bridge(
        NssHalf {
            shared: Arc::clone(&shared),
        },
        NssHalf { shared },
    );
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
