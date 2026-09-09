//! libtomcrypt legacy TLS handler (SSLv2 records).
//!
//! Compiled only when feature `tls_tomcrypt` is enabled.
//! Truncated ClientHello probes are rejected in Rust before any C/RSA work
//! (LibTomCrypt `LTC_ARGCHK` calls `abort()` and cannot be caught by `catch_unwind`).

use crate::config::{ListenerConfig, SslConfig};
use crate::server::live_config::LiveConfig;
use crate::server::ssl_material;
use crate::server::tls::legacy_io::{relay_bridge_only, sync_io_bridge};
use crate::server::{h1};
use anyhow::{Context, Result};
use std::ffi::CString;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::Arc;
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
        pub fn crucible_tomcrypt_read(conn: *mut crucible_tomcrypt_conn, buf: *mut u8, len: usize) -> isize;
        pub fn crucible_tomcrypt_write(conn: *mut crucible_tomcrypt_conn, buf: *const u8, len: usize) -> isize;
        pub fn crucible_tomcrypt_free(conn: *mut crucible_tomcrypt_conn);
    }

    pub enum crucible_tomcrypt_conn {}
}

/// TomCrypt 连接共享指针：读写 half 共享（桥的读/写线程分用）；
/// shim 的记录层按方向加锁（TLS 全双工）；引用计数归零时释放一次。
struct TomcryptShared {
    conn: *mut ffi::crucible_tomcrypt_conn,
}

unsafe impl Send for TomcryptShared {}
unsafe impl Sync for TomcryptShared {}

impl TomcryptShared {
    fn read(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.conn.is_null() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "tomcrypt closed",
            ));
        }
        let n = unsafe { ffi::crucible_tomcrypt_read(self.conn, buf.as_mut_ptr(), buf.len()) };
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
                "tomcrypt closed",
            ));
        }
        let n = unsafe { ffi::crucible_tomcrypt_write(self.conn, buf.as_ptr(), buf.len()) };
        if n < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(n as usize)
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

/// 读写 half：Clone 共享同一 TomcryptShared。
#[derive(Clone)]
struct TomcryptHalf {
    shared: Arc<TomcryptShared>,
}

impl Read for TomcryptHalf {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.shared.read(buf)
    }
}

impl Write for TomcryptHalf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.shared.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
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
    if !sslv2_hello_complete(&peek) {
        log::info!(
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
            log::error!(
                target: "tls_tomcrypt",
                "tomcrypt legacy TLS soft-fail peer={peer} peek_len={peek_len}: {e:#}"
            );
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
    log::info!(
        target: "tls_tomcrypt",
        "tomcrypt accept_and_serve peer={peer} peek_len={}",
        peek.len()
    );

    let cert_pem = ssl_material::load_bytes(ssl.cert.as_deref().context("ssl.cert")?)?;
    let key_pem = ssl_material::load_bytes(ssl.key.as_deref().context("ssl.key")?)?;
    // NUL-terminate for C PEM parsers (length-bounded, but keep CString as belt+suspenders).
    let cert_c = CString::new(cert_pem).context("cert PEM contains NUL")?;
    let key_c = CString::new(key_pem).context("key PEM contains NUL")?;

    let relay_fd = relay_bridge_only(stream).await?;
    let peek_copy = peek;
    let peer_log = peer;

    let shared = tokio::task::spawn_blocking(move || -> Result<Arc<TomcryptShared>> {
        unsafe {
            if ffi::crucible_tomcrypt_init() != 0 {
                anyhow::bail!("tomcrypt init failed");
            }
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
            log::info!(target: "tls_tomcrypt", "tomcrypt handshake accepted peer={peer_log}");
            Ok(Arc::new(TomcryptShared { conn: ptr }))
        }
    })
    .await
    .context("tomcrypt join")??;

    // 任务 6：阻塞 IO 移出 executor——读写线程 + mpsc 桥（ halves 共享同一连接）。
    let io = sync_io_bridge(
        TomcryptHalf {
            shared: Arc::clone(&shared),
        },
        TomcryptHalf { shared },
    );
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
