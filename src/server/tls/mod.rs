//! TLS facade: BoringSSL primary + optional NSS / TomCrypt legacy stacks.
//!
//! - **BoringSSL**: TLS 1.2/1.3, ECH, PQC hybrid groups, ALPN → H1/H2
//! - **NSS**: SSLv3, TLS 1.0–1.2, IE6 v2-compatible ClientHello
//! - **TomCrypt**: pure SSLv2 records
//!
//! ClientHello peek routing lives in [`client_hello`]; legacy modules compile only
//! when `tls_nss` / `tls_tomcrypt` features are enabled (configure `--enable-*`).

use crate::config::SslConfig;

pub mod accept;
pub mod boring_path;
pub mod client_hello;
#[cfg(feature = "tls_boring")]
pub mod ech_pem;
pub mod legacy_io;
#[cfg(all(feature = "tls_rustls", not(feature = "tls_boring")))]
pub mod rustls_path;

#[cfg(feature = "tls_nss")]
#[path = "tls_nss.rs"]
pub mod nss;

#[cfg(feature = "tls_tomcrypt")]
#[path = "tls_tomcrypt.rs"]
pub mod tomcrypt;

pub use boring_path::{active_stack, legacy_modules};

/// Primary stack for a listener (always BoringSSL when compiled in).
/// Legacy NSS/TomCrypt are selected per-connection via [`client_hello::resolve`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsStack {
    Boring,
    Nss,
    Tomcrypt,
}

/// Declared primary TLS implementation for admin/catalog (not per-hello routing).
pub fn select_stack(_ssl: &SslConfig) -> TlsStack {
    TlsStack::Boring
}
