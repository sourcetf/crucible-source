//! Stub for a future BoringSSL-backed quinn `crypto::ServerConfig`, plus a real
//! PEM validation entry point used by H3 startup.
//!
//! # Status
//! Crucible's TCP TLS path already uses BoringSSL (`tls_boring`). QUIC/H3 still
//! falls back to quinn's rustls provider when a full `quinn::crypto::ServerConfig`
//! against BoringSSL is unavailable. This module:
//! 1. Validates cert/key PEM via the optional `boring` crate.
//! 2. Returns a typed [`BoringQuicConfig`] wrapper H3 can prefer.
//! 3. Documents the remaining work for a full quinn crypto provider.

use std::fmt;

/// Typed wrapper around validated BoringSSL material for a future QUIC provider.
///
/// Holds PEM bytes (and, when `boring` is enabled, confirms they parse). This is
/// **not** yet a `quinn::crypto::ServerConfig`; callers should fall back to
/// rustls transport when [`BoringQuicConfig::as_quinn_crypto`] returns `None`.
#[derive(Clone)]
pub struct BoringQuicConfig {
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    /// True when BoringSSL successfully parsed the cert and key.
    pub validated: bool,
}

impl fmt::Debug for BoringQuicConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoringQuicConfig")
            .field("cert_pem_len", &self.cert_pem.len())
            .field("key_pem_len", &self.key_pem.len())
            .field("validated", &self.validated)
            .finish()
    }
}

impl BoringQuicConfig {
    /// Placeholder for a future `Arc<dyn quinn::crypto::ServerConfig>`.
    /// Always `None` until the full Boring QUIC Session is implemented.
    pub fn as_quinn_crypto(&self) -> Option<()> {
        let _ = self;
        None
    }

    pub fn status_line(&self) -> String {
        if self.validated {
            "quinn-boring: BoringQuicConfig validated (cert/key PEM via boring); QUIC transport still rustls until full provider lands".into()
        } else {
            "quinn-boring: BoringQuicConfig present but boring validation skipped/unavailable; prefer rustls".into()
        }
    }
}

/// Alias kept for older call sites / docs.
#[derive(Debug, Clone, Copy, Default)]
pub struct BoringQuicServerCrypto;

impl BoringQuicServerCrypto {
    /// Validate cert/key PEM and return a [`BoringQuicConfig`] when successful.
    ///
    /// With the `boring` feature: parses X509 + PKey via BoringSSL.
    /// Without `boring`: returns `None` so H3 falls back to rustls cleanly.
    pub fn try_build(cert_pem: &[u8], key_pem: &[u8]) -> Option<BoringQuicConfig> {
        try_build(cert_pem, key_pem)
    }

    /// Human-readable status for logs / admin.
    pub fn status_line() -> &'static str {
        if cfg!(feature = "boring") {
            "quinn-boring: try_build validates PEM via boring; QUIC transport still rustls (full provider TBD)"
        } else {
            "quinn-boring: peer_identity live; build with --features boring for PEM validation; QUIC still rustls"
        }
    }
}

/// Prefer this name from `h3.rs`: returns validated config or `None` → rustls.
pub fn try_build(cert_pem: &[u8], key_pem: &[u8]) -> Option<BoringQuicConfig> {
    if cert_pem.is_empty() || key_pem.is_empty() {
        return None;
    }
    #[cfg(feature = "boring")]
    {
        match validate_pem_boring(cert_pem, key_pem) {
            Ok(()) => Some(BoringQuicConfig {
                cert_pem: cert_pem.to_vec(),
                key_pem: key_pem.to_vec(),
                validated: true,
            }),
            Err(e) => {
                // Caller falls back to rustls; surface reason via eprintln for early boot.
                eprintln!("quinn-boring try_build: boring PEM validation failed: {e}");
                None
            }
        }
    }
    #[cfg(not(feature = "boring"))]
    {
        // Soft accept structure without crypto parse — H3 still uses rustls.
        Some(BoringQuicConfig {
            cert_pem: cert_pem.to_vec(),
            key_pem: key_pem.to_vec(),
            validated: false,
        })
    }
}

#[cfg(feature = "boring")]
fn validate_pem_boring(cert_pem: &[u8], key_pem: &[u8]) -> Result<(), String> {
    use boring::pkey::PKey;
    use boring::x509::X509;

    let certs = X509::stack_from_pem(cert_pem).map_err(|e| format!("cert PEM: {e}"))?;
    if certs.is_empty() {
        return Err("cert PEM produced zero X509 certificates".into());
    }
    let _key = PKey::private_key_from_pem(key_pem).map_err(|e| format!("key PEM: {e}"))?;
    // Optionally cross-check key matches leaf — best-effort.
    if let (Ok(leaf_pub), Ok(key)) = (
        certs[0].public_key(),
        PKey::private_key_from_pem(key_pem),
    ) {
        let a = leaf_pub.public_key_to_der().ok();
        let b = key.public_key_to_der().ok();
        if let (Some(a), Some(b)) = (a, b) {
            if a != b {
                return Err("certificate public key does not match private key".into());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_build_rejects_empty() {
        assert!(try_build(b"", b"").is_none());
        assert!(try_build(b"-----BEGIN CERTIFICATE-----\n", b"").is_none());
    }
}
