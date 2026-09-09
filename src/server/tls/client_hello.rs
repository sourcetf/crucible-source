//! ClientHello wire-format classifier for TLS stack routing.
//!
//! Modern TLS (1.2+, 1.3, ECH, PQC) → BoringSSL.
//! SSLv3 / IE6 `SSL_ENABLE_V2_COMPATIBLE_HELLO` → NSS.
//! Pure SSLv2 records → TomCrypt.
//!
//! **Never** rewrite TLS 1.3 ClientHello bytes (transcript integrity).

use crate::config::SslConfig;

/// Target TLS implementation for an incoming ClientHello.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HelloRoute {
    Boring,
    Nss,
    TomCrypt,
}

/// Classify peeked wire bytes before handshake (no mutation).
pub fn route(buf: &[u8]) -> HelloRoute {
    if buf.is_empty() {
        return HelloRoute::Boring;
    }

    // SSLv2-style record header: high bit of first byte set.
    if buf[0] & 0x80 != 0 {
        return classify_sslv2_record(buf);
    }

    // TLS / SSLv3 record layer: type 0x16 = handshake.
    if buf.len() >= 5 && buf[0] == 0x16 {
        let record_version = u16::from_be_bytes([buf[1], buf[2]]);
        if record_version == 0x0300 {
            return HelloRoute::Nss;
        }
        if record_version <= 0x0303 {
            return classify_tls_record(buf);
        }
    }

    HelloRoute::Boring
}

/// Apply listener knobs: legacy stacks only when compiled in **and** enabled.
pub fn resolve(route: HelloRoute, ssl: &SslConfig) -> HelloRoute {
    match route {
        HelloRoute::TomCrypt => {
            if ssl.enable_tomcrypt && cfg!(all(feature = "tls_tomcrypt", tls_tomcrypt_enabled)) {
                HelloRoute::TomCrypt
            } else {
                HelloRoute::Boring
            }
        }
        HelloRoute::Nss => {
            if ssl.enable_nss && cfg!(all(feature = "tls_nss", tls_nss_enabled)) {
                HelloRoute::Nss
            } else {
                HelloRoute::Boring
            }
        }
        HelloRoute::Boring => HelloRoute::Boring,
    }
}

fn classify_sslv2_record(buf: &[u8]) -> HelloRoute {
    // [0..2] length with MSB set, [2] msg type, [3..4] client version.
    if buf.len() < 5 || buf[2] != 0x01 {
        // Truncated / non-CLIENT-HELLO probes: never enter TomCrypt (abort risk).
        return HelloRoute::Boring;
    }
    let major = buf[3];
    let minor = buf[4];
    // IE6 SSL_ENABLE_V2_COMPATIBLE_HELLO: v2 framing, SSL 3.0 version field.
    if major == 3 && minor == 0 {
        return HelloRoute::Nss;
    }
    // SSL 2.0 proper — only when the wire hello looks complete enough to parse.
    if major == 0 && minor == 2 {
        if sslv2_client_hello_wire_complete(buf) {
            return HelloRoute::TomCrypt;
        }
        // Incomplete challenge/cipher lengths → soft-drop via Boring reject path.
        return HelloRoute::Boring;
    }
    // Other v2-framed legacy hellos (SSL 3.x in v2 wrapper).
    if major == 3 && minor <= 1 {
        return HelloRoute::Nss;
    }
    // Unknown / truncated v2 framing — never enter TomCrypt (ARGCHK abort risk).
    HelloRoute::Boring
}

/// True when SSLv2 CLIENT-HELLO has enough bytes for declared cipher/session/challenge.
fn sslv2_client_hello_wire_complete(buf: &[u8]) -> bool {
    if buf.len() < 11 {
        return false;
    }
    let cipher_len = u16::from_be_bytes([buf[5], buf[6]]) as usize;
    let session_len = u16::from_be_bytes([buf[7], buf[8]]) as usize;
    let challenge_len = u16::from_be_bytes([buf[9], buf[10]]) as usize;
    if challenge_len == 0 || challenge_len > 32 || cipher_len > 256 || session_len > 256 {
        return false;
    }
    let need = 11usize
        .saturating_add(cipher_len)
        .saturating_add(session_len)
        .saturating_add(challenge_len);
    buf.len() >= need
}

fn classify_tls_record(buf: &[u8]) -> HelloRoute {
    // Record: type(1) version(2) len(2) handshake...
    if buf.len() < 11 || buf[5] != 0x01 {
        return HelloRoute::Boring;
    }
    let client_version = u16::from_be_bytes([buf[9], buf[10]]);
    if client_version == 0x0300 {
        return HelloRoute::Nss;
    }
    // TLS 1.3 uses supported_versions (0x002b) inside extensions — always Boring.
    if has_tls13_supported_versions(buf) {
        return HelloRoute::Boring;
    }
    // TLS 1.0 / 1.1 in legacy ClientHello without TLS1.3 ext → NSS when enabled.
    if client_version <= 0x0302 {
        return HelloRoute::Nss;
    }
    HelloRoute::Boring
}

/// Scan ClientHello extensions for supported_versions containing TLS 1.3 (0x0304).
fn has_tls13_supported_versions(buf: &[u8]) -> bool {
  // Handshake: type(1) len(3) version(2) random(32) session_id_len(1) ...
    if buf.len() < 43 {
        return false;
    }
    if buf.len() <= 43 {
        return false;
    }
    let sid_len = buf[43] as usize;
    let mut off = 44 + sid_len;
    if buf.len() < off + 2 {
        return false;
    }
    let cipher_len = u16::from_be_bytes([buf[off], buf[off + 1]]) as usize;
    off += 2 + cipher_len;
    if buf.len() < off + 1 {
        return false;
    }
    let comp_len = buf[off] as usize;
    off += 1 + comp_len;
    if buf.len() < off + 2 {
        return false;
    }
    let ext_len = u16::from_be_bytes([buf[off], buf[off + 1]]) as usize;
    off += 2;
    let ext_end = off.saturating_add(ext_len);
    if ext_end > buf.len() {
        return false;
    }
    while off + 4 <= ext_end {
        let etype = u16::from_be_bytes([buf[off], buf[off + 1]]);
        let elen = u16::from_be_bytes([buf[off + 2], buf[off + 3]]) as usize;
        off += 4;
        if off + elen > ext_end {
            break;
        }
        if etype == 0x002b && elen >= 3 {
            // supported_versions: length(1) versions...
            let vlen = buf[off] as usize;
            let mut vo = off + 1;
            let vend = vo + vlen;
            while vo + 1 < vend && vo < ext_end {
                let ver = u16::from_be_bytes([buf[vo], buf[vo + 1]]);
                if ver == 0x0304 {
                    return true;
                }
                vo += 2;
            }
        }
        off += elen;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sslv2_incomplete_soft_routes_boring() {
        // Truncated probe — must NOT enter TomCrypt (ARGCHK abort risk).
        let hello = [0x80, 0x09, 0x01, 0x00, 0x02, 0x00, 0x15, 0x00, 0x16];
        assert_eq!(route(&hello), HelloRoute::Boring);
    }

    #[test]
    fn sslv2_acceptance_probe_blob_soft_routes_boring() {
        // Same truncated CMK-style probe as scripts/test_sslv2_probe.py HELLO:
        // challenge_len=16 but payload short → incomplete → Boring soft-drop.
        let hello = [
            0x80u8, 0x12, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(route(&hello), HelloRoute::Boring);
        assert!(!sslv2_client_hello_wire_complete(&hello));
    }

    #[test]
    fn sslv2_complete_routes_tomcrypt() {
        // Complete CLIENT-HELLO: cipher_len=3, session=0, challenge=16 → need 30 bytes.
        let mut hello = vec![
            0x80, 0x1c, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x00, 0x00, 0x10,
        ];
        hello.extend_from_slice(&[0x01, 0x00, 0x80]); // cipher
        hello.extend_from_slice(&[0u8; 16]); // challenge
        assert_eq!(route(&hello), HelloRoute::TomCrypt);
    }

    #[test]
    fn ie6_v2_compatible_routes_nss() {
        // v2 framing with SSL 3.0 version (IE6 SSL_ENABLE_V2_COMPATIBLE_HELLO).
        let hello = [0x80, 0x4a, 0x01, 0x03, 0x00, 0x00, 0x2f, 0x00];
        assert_eq!(route(&hello), HelloRoute::Nss);
    }

    #[test]
    fn sslv3_record_routes_nss() {
        // TLS record v3.0, minimal client hello header.
        let mut hello = vec![
            0x16, 0x03, 0x00, 0x00, 0x2c, 0x01, 0x00, 0x00, 0x28, 0x03, 0x00,
        ];
        hello.extend_from_slice(&[0u8; 32]); // random
        hello.push(0); // session id len
        hello.extend_from_slice(&[0, 2, 0, 0x2f, 0x00]); // ciphers + comp
        assert_eq!(route(&hello), HelloRoute::Nss);
    }

    #[test]
    fn tls13_outer_record_stays_boring() {
        // TLS 1.3 ClientHello: record 0x0301, client_version 0x0303, supported_versions ext.
        let mut hello = vec![
            0x16, 0x03, 0x01, 0x00, 0xc0, 0x01, 0x00, 0x00, 0xbc, 0x03, 0x03,
        ];
        hello.extend_from_slice(&[0u8; 32]);
        hello.push(0); // session id
        hello.extend_from_slice(&[0x00, 0x02, 0x13, 0x01, 0x01, 0x00]); // ciphers + comp
        // extensions total len 0x0077
        hello.extend_from_slice(&[0x00, 0x77]);
        // supported_versions ext 0x002b len 3: [2, 03, 04]
        hello.extend_from_slice(&[0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);
        hello.resize(hello.len() + 0x77 - 7, 0);
        assert_eq!(route(&hello), HelloRoute::Boring);
    }

    #[test]
    fn tls10_client_hello_routes_nss() {
        // TLS1.0 client hello in TLS record (no TLS1.3 ext).
        let mut hello = vec![
            0x16, 0x03, 0x01, 0x00, 0x2c, 0x01, 0x00, 0x00, 0x28, 0x03, 0x01,
        ];
        hello.extend_from_slice(&[0u8; 32]);
        hello.push(0);
        hello.extend_from_slice(&[0, 2, 0, 0x2f, 0x00]);
        assert_eq!(route(&hello), HelloRoute::Nss);
    }

    #[test]
    fn resolve_respects_enable_flags() {
        let ssl = SslConfig {
            cert: None,
            key: None,
            sni_name: None,
            sni_only: false,
            cert_ec: None,
            key_ec: None,
            versions: vec![],
            ciphers: vec![],
            prefer_tls13: false,
            ech: false,
            ech_keys: None,
            psk: false,
            psk_identity: None,
            psk_key: None,
            ocsp_der_path: None,
            pqc: false,
            groups: vec![],
            ech_public_name: None,
            ech_cipher_suite: None,
            ech_max_name_length: None,
            ech_advertise: true,
            early_data: false,
            enable_nss: false,
            enable_tomcrypt: false,
        };
        assert_eq!(resolve(HelloRoute::Nss, &ssl), HelloRoute::Boring);
    }

    #[test]
    fn resolve_tls10_to_nss_when_enabled() {
        let ssl = SslConfig {
            cert: None,
            key: None,
            sni_name: None,
            sni_only: false,
            cert_ec: None,
            key_ec: None,
            versions: vec![],
            ciphers: vec![],
            prefer_tls13: false,
            ech: false,
            ech_keys: None,
            psk: false,
            psk_identity: None,
            psk_key: None,
            ocsp_der_path: None,
            pqc: false,
            groups: vec![],
            ech_public_name: None,
            ech_cipher_suite: None,
            ech_max_name_length: None,
            ech_advertise: true,
            early_data: false,
            enable_nss: true,
            enable_tomcrypt: true,
        };
        // NSS only when the tls_nss feature (and linked shim) is present.
        let expect = if cfg!(all(feature = "tls_nss", tls_nss_enabled)) {
            HelloRoute::Nss
        } else {
            HelloRoute::Boring
        };
        assert_eq!(resolve(HelloRoute::Nss, &ssl), expect);
    }
}


/// 早期规格 8：从 ClientHello 提取 SNI（server_name 扩展，type 0x0000）。
/// 输入为 TLS record 起始的 peek 缓冲（type 0x16）。失败返回 None。
pub fn parse_sni(buf: &[u8]) -> Option<String> {
    if buf.len() < 43 || buf[0] != 0x16 {
        return None;
    }
    let hs_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    let end = (5 + hs_len).min(buf.len());
    let mut p = 5 + 38; // hs type+len + version + random
    if p + 2 > end || buf[p - 2] != 0x01 {
        return None;
    }
    let sid_len = u16::from_be_bytes([buf[p], buf[p + 1]]) as usize;
    p += 2 + sid_len;
    if p + 2 > end {
        return None;
    }
    let cs_len = u16::from_be_bytes([buf[p], buf[p + 1]]) as usize;
    p += 2 + cs_len;
    if p >= end {
        return None;
    }
    p += 1; // compression
    if p + 2 > end {
        return None;
    }
    let ext_len = u16::from_be_bytes([buf[p], buf[p + 1]]) as usize;
    p += 2;
    let ext_end = (p + ext_len).min(end);
    while p + 4 <= ext_end {
        let etype = u16::from_be_bytes([buf[p], buf[p + 1]]);
        let elen = u16::from_be_bytes([buf[p + 2], buf[p + 3]]) as usize;
        let (s, e) = (p + 4, (p + 4 + elen).min(ext_end));
        if etype == 0x0000 && e > s + 5 {
            // server_name_list: u16 list_len, entry: u8 type + u16 len + name
            let list = &buf[s..e];
            if list[0..3] == [0x00, 0x00, 0x00] || (list[0] == 0 && list[1] == 0) {
                let nlen = u16::from_be_bytes([list[1], list[2]]) as usize;
                if nlen >= 1 && 3 + nlen <= list.len() {
                    return Some(String::from_utf8_lossy(&list[3..3 + nlen]).into_owned());
                }
            }
        }
        p = e;
    }
    None
}
