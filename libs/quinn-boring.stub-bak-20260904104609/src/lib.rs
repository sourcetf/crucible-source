//! QUIC/H3 certificate helpers for BoringSSL-aligned identity inspection.
//!
//! # Role in Crucible
//! Full quinn crypto provider still uses rustls at the transport layer on OpenBSD;
//! this crate supplies the required `peer_identity` API (no `todo!`) and PEM/DER
//! parsing used by `src/server/h3.rs`.
//!
//! # Helpers
//! - [`peer_identity`] / [`peer_identity_from_der`] — build a leaf-first cert chain
//! - [`parse_pem_chain`] — decode one or more `BEGIN CERTIFICATE` PEM blocks to DER
//! - [`parse_der_chain`] — accept PEM or a single DER certificate blob
//! - [`server_crypto`] — stub documenting the future BoringSSL quinn `ServerConfig` path

pub mod server_crypto;

/// Minimal X509 certificate representation (DER bytes). Leaf first in chains.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct X509 {
    pub der: Vec<u8>,
}

impl X509 {
    pub fn from_der(der: Vec<u8>) -> Self {
        Self { der }
    }

    pub fn as_der(&self) -> &[u8] {
        &self.der
    }

    /// True when `der` looks like an ASN.1 SEQUENCE (typical X.509 leaf).
    pub fn looks_like_der(&self) -> bool {
        self.der.first() == Some(&0x30)
    }
}

/// Return peer certificate chain with leaf first.
///
/// `leaf_der` may be:
/// - a single DER certificate,
/// - a PEM chain (multiple `BEGIN CERTIFICATE` blocks), or
/// - empty (returns empty vec).
///
/// When `leaf_der` is already a PEM chain, every decoded certificate becomes an
/// [`X509`] entry (DER leaves). The connection id is reserved for future Boring
/// session lookup and is currently ignored.
pub fn peer_identity(_connection_id: u64, leaf_der: &[u8]) -> Vec<X509> {
    parse_der_chain(leaf_der)
}

/// Convenience: leaf-only / chain identity from DER or PEM bytes.
pub fn peer_identity_from_der(leaf_der: &[u8]) -> Vec<X509> {
    peer_identity(0, leaf_der)
}

/// Build identity from an already-split DER chain (leaf first). Empty slices skipped.
pub fn peer_identity_from_ders(ders: impl IntoIterator<Item = impl AsRef<[u8]>>) -> Vec<X509> {
    ders.into_iter()
        .map(|d| d.as_ref().to_vec())
        .filter(|d| !d.is_empty())
        .map(X509::from_der)
        .collect()
}

/// Parse a PEM chain (`-----BEGIN CERTIFICATE-----` blocks) into DER certs (leaf first).
pub fn parse_pem_chain(pem: &[u8]) -> Vec<X509> {
    let text = match std::str::from_utf8(pem) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("-----BEGIN CERTIFICATE-----") {
        rest = &rest[start + 27..];
        let Some(end) = rest.find("-----END CERTIFICATE-----") else {
            break;
        };
        let body: String = rest[..end].chars().filter(|c| !c.is_whitespace()).collect();
        rest = &rest[end + 25..];
        if let Ok(der) = base64_decode(&body) {
            if !der.is_empty() {
                out.push(X509::from_der(der));
            }
        }
    }
    out
}

/// Parse raw DER or PEM into a chain (single DER blob → one cert; PEM → N leaves).
///
/// Concatenated DER certificates (SEQUENCE after SEQUENCE) are also split when
/// possible so `peer_identity` returns a real multi-leaf chain.
pub fn parse_der_chain(input: &[u8]) -> Vec<X509> {
    if input.is_empty() {
        return Vec::new();
    }
    if input.windows(11).any(|w| w == b"BEGIN CERTI") {
        return parse_pem_chain(input);
    }
    let split = split_der_certs(input);
    if !split.is_empty() {
        return split;
    }
    // Treat as a single DER certificate.
    vec![X509::from_der(input.to_vec())]
}

/// Alias used by some call sites.
pub fn parse_cert_chain(input: &[u8]) -> Vec<X509> {
    parse_der_chain(input)
}

/// Split concatenated DER certificates (each starts with ASN.1 SEQUENCE).
fn split_der_certs(input: &[u8]) -> Vec<X509> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < input.len() {
        // Skip whitespace between PEMs already handled; for DER skip leading zeros/padding.
        while i < input.len() && input[i] != 0x30 {
            i += 1;
        }
        if i >= input.len() {
            break;
        }
        let Some((len, hdr)) = read_asn1_len(&input[i..]) else {
            break;
        };
        let total = hdr + len;
        if total == 0 || i + total > input.len() {
            break;
        }
        out.push(X509::from_der(input[i..i + total].to_vec()));
        i += total;
    }
    if out.len() <= 1 {
        // Ambiguous single blob — caller may prefer passthrough.
        return out;
    }
    out
}

/// Read ASN.1 definite length after a SEQUENCE tag. Returns (content_len, header_len).
fn read_asn1_len(bytes: &[u8]) -> Option<(usize, usize)> {
    if bytes.first()? != &0x30 {
        return None;
    }
    let b1 = *bytes.get(1)?;
    if b1 < 0x80 {
        return Some((b1 as usize, 2));
    }
    let n = (b1 & 0x7f) as usize;
    if n == 0 || n > 4 || bytes.len() < 2 + n {
        return None;
    }
    let mut len = 0usize;
    for j in 0..n {
        len = (len << 8) | bytes[2 + j] as usize;
    }
    Some((len, 2 + n))
}

fn base64_decode(in_: &str) -> Result<Vec<u8>, ()> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut out = Vec::with_capacity(in_.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for &b in in_.as_bytes() {
        if b == b'=' {
            break;
        }
        let Some(v) = val(b) else { continue };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_identity() {
        assert!(peer_identity_from_der(&[]).is_empty());
    }

    #[test]
    fn der_passthrough() {
        let chain = peer_identity_from_der(&[0x30, 0x03, 0x01, 0x02, 0x03]);
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].der, vec![0x30, 0x03, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn pem_multi_leaf() {
        // Two minimal fake "certs" (not valid X509, but valid base64 blocks).
        let pem = b"-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nBAUG\n-----END CERTIFICATE-----\n";
        let chain = parse_pem_chain(pem);
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0].der, vec![0x01, 0x02, 0x03]);
        assert_eq!(chain[1].der, vec![0x04, 0x05, 0x06]);
        let via_peer = peer_identity(42, pem);
        assert_eq!(via_peer, chain);
    }

    #[test]
    fn peer_identity_from_ders_filters_empty() {
        let chain = peer_identity_from_ders([b"abc".as_slice(), b"", b"de"]);
        assert_eq!(chain.len(), 2);
    }
}
