//! Parse admin-supplied ECH material (PEM blocks or raw binary) for BoringSSL.
//!
//! Crucible PEM format (paste in Admin / config `ssl.ech_keys`):
//! ```text
//! -----BEGIN ECH CONFIG-----
//! <base64 ECHConfig bytes>
//! -----END ECH CONFIG-----
//! -----BEGIN ECH PRIVATE KEY-----
//! <base64 HPKE private key bytes>
//! -----END ECH PRIVATE KEY-----
//! ```
//!
//! Multiple CONFIG/KEY pairs may appear; the first pair is marked retry_config.

use anyhow::{bail, Context, Result};
use boring::hpke::HpkeKey;
use boring::ssl::SslEchKeys;

struct PemBlock {
    label: String,
    der: Vec<u8>,
}

/// Load ECH keys from PEM text or raw binary blobs.
pub fn load_ech_keys(pem: &[u8]) -> Result<SslEchKeys> {
    let blocks = parse_pem_blocks(pem)?;
    if blocks.is_empty() {
        return load_ech_from_raw(pem);
    }

    let configs: Vec<&[u8]> = blocks
        .iter()
        .filter(|b| b.label.contains("ECH CONFIG"))
        .map(|b| b.der.as_slice())
        .collect();
    let keys: Vec<&[u8]> = blocks
        .iter()
        .filter(|b| b.label.contains("ECH PRIVATE KEY") || b.label.contains("ECH KEY"))
        .map(|b| b.der.as_slice())
        .collect();

    if configs.is_empty() || keys.is_empty() {
        bail!("ECH PEM must contain ECH CONFIG and ECH PRIVATE KEY blocks");
    }
    if configs.len() != keys.len() {
        bail!(
            "ECH CONFIG count ({}) must match ECH PRIVATE KEY count ({})",
            configs.len(),
            keys.len()
        );
    }

    let mut builder = SslEchKeys::builder().context("SslEchKeys::builder")?;
    for (i, (cfg, key)) in configs.iter().zip(keys.iter()).enumerate() {
        // boring crate names this `dhkem_p256_sha256` but binds X25519-HKDF-SHA256 KEM (see hpke.rs).
        let hpke = HpkeKey::dhkem_p256_sha256(key).context("HpkeKey from ECH private key")?;
        builder
            .add_key(i == 0, cfg, hpke)
            .with_context(|| format!("SSL_ECH_KEYS_add pair {i}"))?;
    }
    Ok(builder.build())
}

fn load_ech_from_raw(raw: &[u8]) -> Result<SslEchKeys> {
    if raw.len() < 32 {
        bail!("ECH keys too short");
    }
    // Fallback: entire blob is CONFIG, no separate key — cannot initialize.
    bail!("unrecognized ECH keys format (use ECH CONFIG + ECH PRIVATE KEY PEM blocks)")
}

fn parse_pem_blocks(pem: &[u8]) -> Result<Vec<PemBlock>> {
    let text = std::str::from_utf8(pem).unwrap_or("");
    if !text.contains("-----BEGIN") {
        return Ok(Vec::new());
    }
    let mut blocks = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("-----BEGIN ") {
        rest = &rest[start + 10..];
        let label_end = rest.find("-----").context("malformed PEM BEGIN")?;
        let label = rest[..label_end].trim().to_string();
        rest = &rest[label_end + 5..];
        let end_marker = format!("-----END {label}-----");
        let body_end = rest.find(&end_marker).with_context(|| format!("missing {end_marker}"))?;
        let body: String = rest[..body_end]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        rest = &rest[body_end + end_marker.len()..];
        let der = base64_decode(&body).context("ECH PEM base64")?;
        blocks.push(PemBlock { label, der });
    }
    Ok(blocks)
}

fn base64_decode(in_: &str) -> Result<Vec<u8>> {
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
    let bytes = in_.as_bytes();
    let mut acc: u32 = 0;
    let mut bits = 0;
    for &b in bytes {
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
    fn parse_ech_pem_blocks() {
        let pem = "-----BEGIN ECH CONFIG-----\nAQID\n-----END ECH CONFIG-----\n\
                   -----BEGIN ECH PRIVATE KEY-----\nAgME\n-----END ECH PRIVATE KEY-----\n";
        let blocks = parse_pem_blocks(pem.as_bytes()).unwrap();
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].label, "ECH CONFIG");
    }
}
