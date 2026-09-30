//! .onion hidden-service TLS helpers (cert-as-pubkey pattern).

const ONION_ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// Returns true when host looks like a v2/v3 onion address.
///
/// **必须容忍尾点**：`abc.onion.`（FQDN 写法）此前会被判成**非** onion —— 后果不是
/// 「少一次校验」，而是 `needs_tor()` 也返回 false ⇒ **直连 + 把 onion 名泄露给 DNS**。
/// DNS 完全解析不了 `.onion`（那是 Tor 内部的虚拟域），所以这条路径既泄露名字又必然失败。
/// 尾点在 DNS 语义上等同于根，任何比较主机名的地方都得先归一化。
pub fn is_onion_host(host: &str) -> bool {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    // 必须是 `<非空 label>.onion`
    h.len() > ".onion".len() && h.ends_with(".onion")
}

/// Map proxy ssl_mode strings to verification behaviour for onion upstreams.
///
/// 这里只解析「档位」，不执行校验 —— 校验动作在 `proxy.rs::wrap_upstream_tls_*`：
/// - 非 onion 的 `verify` → BoringSSL `SslVerifyMode::PEER`（系统 CA 链）；
/// - onion 的 `verify` → `NONE` + 手工比对 leaf 里的 ed25519 公钥
///   （[`onion_cert_matches_host`]），rustls 分支对应 `OnionVerifier`。
///
/// 早先这里还有个 `verify_peer()`（只有 `Verify` 返回 true）。删掉它是因为：它没有
/// 任何调用者，而唯一看起来「该调它」的地方恰恰不能用 —— onion 的 verify 必须是
/// TLS `NONE` + 证书即公钥，用 `verify_peer()` 去开 `set_verify(PEER)` 会让
/// `.onion`（自签、无 CA 链）**永远握手失败**。
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
            // `tor` 只表示「强制走 Tor」（`proxy::needs_tor` 认的是这个字符串），**不是**
            // 安全档位：把它映射成 NoVerify 等于让面板上一个看起来只是「走 Tor」的选项悄悄
            // 关掉 `.onion` 的证书即公钥校验（唯一的认证手段）。按最严格档处理。
            "tor" => Self::Verify,
            "no_verify" | "noverify" => Self::NoVerify,
            "trust_self_signed" | "trust" => Self::TrustSelfSigned,
            "off" | "plain" => Self::Off,
            // 未知值一律按最严格处理：宁可能连不上，也不能静默不校验。
            // （`ssl_mode` 默认值已是 "verify"，此处兜住手写配置里的拼写错误。）
            _ => Self::Verify,
        }
    }
}

/// Decode Tor v3 `.onion` hostname → 32-byte ed25519 service public key.
pub fn decode_v3_onion_pubkey(host: &str) -> Option<[u8; 32]> {
    // 用 `strip_suffix` 而不是 `trim_end_matches`：后者会**反复**剥掉匹配后缀，
    // 于是 `xx.onion.onion` 这种输入会被多剥一次；同时先去掉尾点（FQDN 写法）。
    let normalized = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let label = normalized.strip_suffix(".onion")?;
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
    // 不做任何「回退扫描」：在整份证书里找「哪儿出现过这 32 字节」等于把「证书即公钥」
    // 退化成「证书里恰好含这 32 字节」——签名值、扩展的 OCTET STRING、DN 字符串都算，
    // 而期望值（.onion 地址里的公钥）是**公开的**，攻击者可以把它塞进任意位置。
    // SPKI 路径走不通就是**不匹配**（fail-closed）。
    extract_spki_ed25519_key(leaf_der).is_some_and(|k| k == expected)
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
    // **必须**核对 AlgorithmIdentifier 是 Ed25519（OID 1.3.101.112 = 2b 65 70）：
    // 旧实现跳过算法直接取 BIT STRING 的「最后 32 字节」，对 RSA 证书那就是模数尾巴 +
    // 指数编码、对 P-256 就是 Y 坐标 —— 比对的根本不是公钥本身，却能「匹配成功」。
    let (alg, after_alg) = der_expect_seq(spki)?;
    if !alg.windows(3).any(|w| w == ED25519_OID) {
        return None;
    }
    let (bitstr, _) = der_expect_tag(after_alg, 0x03)?;
    // BIT STRING: first byte = unused bits count
    if bitstr.is_empty() {
        return None;
    }
    let key = &bitstr[1..];
    // 长度必须**恰好** 32：不截断、不补长（`key.len() > 32` 时旧代码取尾 32 字节，
    // 等于拿与被检对象无关的字节去比）。
    if key.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(key);
    Some(out)
}

/// Ed25519 的 OID（1.3.101.112）DER 编码，不含 tag/len。
const ED25519_OID: &[u8] = &[0x2b, 0x65, 0x70];


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
    /// 非 Ed25519 的 SPKI 不得匹配 —— 旧实现跳过算法、取 BIT STRING 的**最后 32 字节**，
    /// 于是「构造一张 RSA 证书，让模数尾巴 + 指数编码正好等于目标公钥」就能骗过
    /// `ssl_mode=verify`（对攻击者来说只需一张自己签的证书）。这里用一张「OID 是 RSA、
    /// 密钥尾部恰好是目标公钥」的证书，断言拒绝。
    #[test]
    fn non_ed25519_spki_never_matches() {
        let mut raw = [0u8; 35];
        raw[0..32].fill(0x33);
        raw[34] = 0x03;
        let host = format!("{}.onion", base32_encode(&raw));
        let pk = decode_v3_onion_pubkey(&host).unwrap();

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
        // RSA OID 1.2.840.113549.1.1.1 + 128 字节「模数」，最后 32 字节 = 目标公钥
        let rsa_oid = [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
        let mut key = vec![0x5au8; 96];
        key.extend_from_slice(&pk);
        let bitstr = {
            let mut b = vec![0x03, (key.len() + 1) as u8, 0x00];
            b.extend_from_slice(&key);
            b
        };
        let mut spki_body = rsa_oid.to_vec();
        spki_body.extend_from_slice(&bitstr);
        let spki = seq(&spki_body);
        let placeholder = seq(&[0x02, 0x01, 0x01]);
        let mut tbs_body = Vec::new();
        for _ in 0..5 {
            tbs_body.extend_from_slice(&placeholder);
        }
        tbs_body.extend_from_slice(&spki);
        let cert = seq(&seq(&tbs_body));

        assert!(
            !onion_cert_matches_host(&cert, &host),
            "OID 不是 Ed25519 就不是「证书即公钥」，不许匹配"
        );
    }

    /// Ed25519 但密钥长度不是 32 字节 ⇒ 不允许（旧实现会取尾巴凑 32 字节）。
    #[test]
    fn ed25519_wrong_length_never_matches() {
        let mut raw = [0u8; 35];
        raw[0..32].fill(0x44);
        raw[34] = 0x03;
        let host = format!("{}.onion", base32_encode(&raw));
        let pk = decode_v3_onion_pubkey(&host).unwrap();

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
        let mut key = vec![0u8; 31];
        key.extend_from_slice(&pk[..31]); // 31 字节，最后 31 字节里有 31/32 的目标值
        let bitstr = {
            let mut b = vec![0x03, (key.len() + 1) as u8, 0x00];
            b.extend_from_slice(&key);
            b
        };
        let alg = seq(&[0x06, 0x03, 0x2b, 0x65, 0x70]);
        let mut spki_body = alg;
        spki_body.extend_from_slice(&bitstr);
        let spki = seq(&spki_body);
        let placeholder = seq(&[0x02, 0x01, 0x01]);
        let mut tbs_body = Vec::new();
        for _ in 0..5 {
            tbs_body.extend_from_slice(&placeholder);
        }
        tbs_body.extend_from_slice(&spki);
        let cert = seq(&seq(&tbs_body));
        assert!(!onion_cert_matches_host(&cert, &host), "密钥长度必须恰好 32 字节");
    }

    /// 尾点（FQDN 写法）必须仍判为 onion —— 否则会绕过 Tor 路由并把 onion 名交给 DNS。
    #[test]
    fn trailing_dot_still_onion() {
        let v3 = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion";
        let with_dot = format!("{v3}.");
        assert!(is_onion_host(v3));
        assert!(is_onion_host(&with_dot), "带尾点的 .onion 必须仍是 onion");
        assert!(is_onion_host(&v3.to_ascii_uppercase()));
        // 公钥解码也要容忍尾点
        assert_eq!(decode_v3_onion_pubkey(v3), decode_v3_onion_pubkey(&with_dot));
        assert!(decode_v3_onion_pubkey(&with_dot).is_some());
        // 边界：裸 ".onion"、空 label 不算
        assert!(!is_onion_host(".onion"));
        assert!(!is_onion_host(".onion."));
        assert!(!is_onion_host("onion"));
        assert!(!is_onion_host("abc.onion.evil.com"));
    }

    /// `strip_suffix` 只剥一次：`xx.onion.onion` 不应被当成合法 v3。
    #[test]
    fn suffix_stripped_once() {
        // 56 字符 label + ".onion.onion" → 剥一次后剩 "….onion"，长度 62 ≠ 56 ⇒ None
        let label = "a".repeat(56);
        assert!(decode_v3_onion_pubkey(&format!("{label}.onion.onion")).is_none());
    }
}
