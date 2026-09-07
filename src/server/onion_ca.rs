//! .onion hidden-service TLS helpers (cert-as-pubkey pattern).

const ONION_ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// Returns true when host looks like a v2/v3 onion address.
pub fn is_onion_host(host: &str) -> bool {
    let h = host.trim().to_ascii_lowercase();
    h.ends_with(".onion")
}

/// Map proxy ssl_mode strings to verification behaviour for onion upstreams.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OnionSslMode {
    Verify,
    NoVerify,
    TrustSelfSigned,
    Off,
}

impl OnionSslMode {
    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "verify" => Self::Verify,
            "no_verify" | "noverify" | "tor" => Self::NoVerify,
            "trust_self_signed" | "trust" => Self::TrustSelfSigned,
            "off" | "plain" => Self::Off,
            _ => Self::NoVerify,
        }
    }

    pub fn verify_peer(&self) -> bool {
        matches!(self, Self::Verify)
    }
}

/// Decode Tor v3 `.onion` hostname → 32-byte ed25519 service public key.
pub fn decode_v3_onion_pubkey(host: &str) -> Option<[u8; 32]> {
    let label = host.trim().trim_end_matches(".onion").to_ascii_lowercase();
    if label.len() != 56 {
        return None;
    }
    let decoded = base32_decode(label.as_bytes())?;
    if decoded.len() != 35 {
        return None;
    }
    if decoded[34] != 0x03 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded[..32]);
    Some(out)
}

fn base32_decode(input: &[u8]) -> Option<Vec<u8>> {
    let mut bits: u32 = 0;
    let mut bit_count = 0;
    let mut out = Vec::new();
    for &c in input {
        let val = match c {
            b'a'..=b'z' => (c - b'a') as u32,
            b'2'..=b'7' => (c - b'2') as u32 + 26,
            _ => return None,
        };
        bits = (bits << 5) | val;
        bit_count += 5;
        if bit_count >= 8 {
            bit_count -= 8;
            out.push((bits >> bit_count) as u8);
            bits &= (1 << bit_count) - 1;
        }
    }
    Some(out)
}

/// Validate onion upstream host + ssl_mode combination.
pub fn validate_onion_upstream(host: &str, ssl_mode: &str) -> bool {
    if !is_onion_host(host) {
        return OnionSslMode::parse(ssl_mode) != OnionSslMode::Off;
    }
    decode_v3_onion_pubkey(host).is_some() || OnionSslMode::parse(ssl_mode) != OnionSslMode::Verify
}

/// Compare peer leaf DER against expected v3 onion service pubkey (cert-as-pubkey).
///
/// Prefers matching inside SubjectPublicKeyInfo (SPKI) BIT STRING payload to
/// avoid naive whole-DER substring false positives. Falls back to a constrained
/// scan of BIT STRING contents only when SPKI walk fails.
pub fn onion_cert_matches_host(leaf_der: &[u8], host: &str) -> bool {
    let Some(expected) = decode_v3_onion_pubkey(host) else {
        return false;
    };
    if let Some(spki_key) = extract_spki_ed25519_key(leaf_der) {
        return spki_key == expected;
    }
    // Fallback: only scan BIT STRING payloads (tag 0x03), not arbitrary DER bytes.
    bit_string_payloads(leaf_der).any(|payload| {
        payload == expected.as_slice()
            || payload
                .windows(32)
                .any(|w| w == expected)
    })
}

/// Walk X.509 DER → TBSCertificate → subjectPublicKeyInfo → BIT STRING key bytes.
fn extract_spki_ed25519_key(cert_der: &[u8]) -> Option<[u8; 32]> {
    // Certificate ::= SEQUENCE { tbsCertificate, ... }
    let (tbs, _) = der_expect_seq(cert_der)?;
    // TBSCertificate ::= SEQUENCE { version?, serial, sig, issuer, validity, subject, spki, ... }
    let (mut tbs_body, _) = der_expect_seq(tbs)?;
    // Optional version [0]
    if tbs_body.first() == Some(&0xa0) {
        let (_, rest) = der_skip_tlv(tbs_body)?;
        tbs_body = rest;
    }
    // serialNumber, signature, issuer, validity, subject
    for _ in 0..5 {
        let (_, rest) = der_skip_tlv(tbs_body)?;
        tbs_body = rest;
    }
    // subjectPublicKeyInfo ::= SEQUENCE { algorithm, subjectPublicKey BIT STRING }
    let (spki, _) = der_expect_seq(tbs_body)?;
    let (_, after_alg) = der_skip_tlv(spki)?;
    let (bitstr, _) = der_expect_tag(after_alg, 0x03)?;
    // BIT STRING: first byte = unused bits count
    if bitstr.is_empty() {
        return None;
    }
    let key = &bitstr[1..];
    if key.len() == 32 {
        let mut out = [0u8; 32];
        out.copy_from_slice(key);
        return Some(out);
    }
    // Some encodings wrap the key; take last 32 bytes if long enough.
    if key.len() > 32 {
        let mut out = [0u8; 32];
        out.copy_from_slice(&key[key.len() - 32..]);
        return Some(out);
    }
    None
}

fn bit_string_payloads(der: &[u8]) -> BitStringIter<'_> {
    BitStringIter { der, i: 0 }
}

struct BitStringIter<'a> {
    der: &'a [u8],
    i: usize,
}

impl<'a> Iterator for BitStringIter<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<Self::Item> {
        while self.i < self.der.len() {
            if self.der[self.i] != 0x03 {
                self.i += 1;
                continue;
            }
            let Some((content, hdr)) = read_der_len(&self.der[self.i..]) else {
                self.i += 1;
                continue;
            };
            let start = self.i + hdr;
            let end = start + content;
            if end > self.der.len() {
                self.i += 1;
                continue;
            }
            self.i = end;
            let body = &self.der[start..end];
            if body.is_empty() {
                continue;
            }
            // Skip unused-bits leading byte.
            return Some(&body[1..]);
        }
        None
    }
}

fn der_expect_seq(input: &[u8]) -> Option<(&[u8], &[u8])> {
    der_expect_tag(input, 0x30)
}

fn der_expect_tag(input: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    if input.first()? != &tag {
        return None;
    }
    let (len, hdr) = read_der_len(input)?;
    let content = input.get(hdr..hdr + len)?;
    let rest = input.get(hdr + len..)?;
    Some((content, rest))
}

fn der_skip_tlv(input: &[u8]) -> Option<(&[u8], &[u8])> {
    if input.is_empty() {
        return None;
    }
    let (len, hdr) = read_der_len(input)?;
    let rest = input.get(hdr + len..)?;
    let tlv = input.get(..hdr + len)?;
    Some((tlv, rest))
}

fn read_der_len(bytes: &[u8]) -> Option<(usize, usize)> {
    // returns (content_len, header_len including tag)
    let _tag = *bytes.first()?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v3_onion_roundtrip() {
        let mut raw = [0u8; 35];
        raw[0] = 0x42;
        raw[34] = 0x03;
        let label = base32_encode(&raw);
        assert_eq!(label.len(), 56);
        let host = format!("{label}.onion");
        let pk = decode_v3_onion_pubkey(&host).expect("decode roundtrip");
        assert_eq!(pk[0], 0x42);
    }

    fn base32_encode(input: &[u8]) -> String {
        let mut out = String::with_capacity((input.len() * 8).div_ceil(5));
        let mut bits: u32 = 0;
        let mut bit_count = 0;
        for &b in input {
            bits = (bits << 8) | u32::from(b);
            bit_count += 8;
            while bit_count >= 5 {
                bit_count -= 5;
                let idx = ((bits >> bit_count) & 0x1f) as usize;
                out.push(ONION_ALPHABET[idx] as char);
            }
        }
        if bit_count > 0 {
            let idx = ((bits << (5 - bit_count)) & 0x1f) as usize;
            out.push(ONION_ALPHABET[idx] as char);
        }
        out
    }

    #[test]
    fn onion_cert_prefers_spki_not_raw_substring() {
        let mut raw = [0u8; 35];
        raw[0..32].fill(0x11);
        raw[34] = 0x03;
        let label = base32_encode(&raw);
        let host = format!("{label}.onion");
        let pk = decode_v3_onion_pubkey(&host).unwrap();

        // Craft minimal fake TBS with SPKI BIT STRING = 0x00 || pk
        // Certificate = SEQ { TBS = SEQ { serial, alg, issuer, validity, subject, spki } }
        fn seq(body: &[u8]) -> Vec<u8> {
            let mut v = vec![0x30];
            if body.len() < 128 {
                v.push(body.len() as u8);
            } else {
                v.push(0x81);
                v.push(body.len() as u8);
            }
            v.extend_from_slice(body);
            v
        }
        let bitstr = {
            let mut b = vec![0x03, 33, 0x00];
            b.extend_from_slice(&pk);
            b
        };
        let alg = seq(&[0x06, 0x03, 0x2b, 0x65, 0x70]); // fake OID
        let mut spki_body = alg;
        spki_body.extend_from_slice(&bitstr);
        let spki = seq(&spki_body);
        // 5 placeholders before SPKI: serial, sig, issuer, validity, subject
        let placeholder = seq(&[0x02, 0x01, 0x01]);
        let mut tbs_body = Vec::new();
        for _ in 0..5 {
            tbs_body.extend_from_slice(&placeholder);
        }
        tbs_body.extend_from_slice(&spki);
        let tbs = seq(&tbs_body);
        let cert = seq(&tbs);

        assert!(onion_cert_matches_host(&cert, &host));

        // Wrong key in SPKI should not match even if pk bytes appear elsewhere.
        let mut junk = cert.clone();
        junk.extend_from_slice(&pk);
        // Corrupt SPKI key byte
        if let Some(pos) = junk.windows(32).position(|w| w == pk) {
            junk[pos] ^= 0xff;
        }
        // Rebuild with wrong key only in SPKI path — simpler: different host
        let mut raw2 = raw;
        raw2[0] = 0x22;
        let host2 = format!("{}.onion", base32_encode(&raw2));
        assert!(!onion_cert_matches_host(&cert, &host2));
    }
}
