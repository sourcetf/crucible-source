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

/// 把 peek 里**连续的 TLS handshake record**（content type 0x16）拼成一条
/// handshake 消息（含 4 字节 type+length）。
///
/// RFC 8446 §5.1：握手消息可以跨多个 TLS record 分片，record 边界与消息边界无关。
/// 旧实现只看第一个 record：SNI / `supported_versions` 落在第二个 record 时会被判成
/// 「没有」，于是 `sni_only` 误杀正常客户端、`prefer_tls13` 把 1.3 客户端压到 1.2。
///
/// 只使用 peek 中已经收到的完整 record；**最后一个不完整 record 的已收字节也保留**
/// （partial）：调用方至少能解析到截断点之前的内容（例如 SNI 常在扩展区最前面），
/// 未收全的部分由调用方的「完整性」判据另行处理（fail-closed）。
fn reassemble_client_hello(peek: &[u8]) -> Option<Vec<u8>> {
    if peek.len() < 5 || peek[0] != 0x16 {
        return None;
    }
    let mut out: Vec<u8> = Vec::new();
    let mut p = 0usize;
    while p + 5 <= peek.len() && peek[p] == 0x16 {
        let len = u16::from_be_bytes([peek[p + 3], peek[p + 4]]) as usize;
        let start = p + 5;
        let end = start.saturating_add(len);
        if end > peek.len() {
            // 该 record 未收全：保留已收部分（见上面的 partial 说明）。
            out.extend_from_slice(&peek[start..]);
            break;
        }
        out.extend_from_slice(&peek[start..end]);
        p = end;
        if out.len() >= 4 {
            if out[0] != 0x01 {
                return None;
            }
            let hl = ((out[1] as usize) << 16) | ((out[2] as usize) << 8) | out[3] as usize;
            if out.len() >= 4 + hl {
                out.truncate(4 + hl);
                return Some(out);
            }
        }
        // 握手消息上限 2^24；peek 本身有上限，这里显式兜底防无界累积。
        if out.len() > 16 * 1024 * 1024 {
            return None;
        }
    }
    if out.len() >= 4 && out[0] == 0x01 {
        Some(out)
    } else {
        None
    }
}

/// 在**完整/partial 的 ClientHello handshake 字节**（从 handshake type 开始）里扫描
/// `supported_versions` 是否包含 TLS 1.3 (0x0304)。
///
/// 偏移（handshake 视图）：type(0) len(1..4) legacy_version(4..6) random(6..38)
/// session_id_len(38) …
fn handshake_has_tls13(hs: &[u8]) -> bool {
    if hs.len() < 39 {
        return false;
    }
    let sid_len = hs[38] as usize;
    let mut off = 39 + sid_len;
    if hs.len() < off + 2 {
        return false;
    }
    let cipher_len = u16::from_be_bytes([hs[off], hs[off + 1]]) as usize;
    off += 2 + cipher_len;
    if hs.len() < off + 1 {
        return false;
    }
    let comp_len = hs[off] as usize;
    off += 1 + comp_len;
    if hs.len() < off + 2 {
        return false;
    }
    let ext_len = u16::from_be_bytes([hs[off], hs[off + 1]]) as usize;
    off += 2;
    let ext_end = off.saturating_add(ext_len).min(hs.len());
    while off + 4 <= ext_end {
        let etype = u16::from_be_bytes([hs[off], hs[off + 1]]);
        let elen = u16::from_be_bytes([hs[off + 2], hs[off + 3]]) as usize;
        off += 4;
        if off + elen > ext_end {
            break;
        }
        if etype == 0x002b && elen >= 3 {
            // supported_versions: length(1) versions...
            let vlen = hs[off] as usize;
            let mut vo = off + 1;
            // 版本列表的两个字节都必须落在 **扩展数据内**（vlen 与 elen 无一致性约束，
            // 攻击者可控；旧条件曾让 `vo` 落到 ext_end-1 并读越界一字节）。
            let vend = (vo + vlen).min(ext_end);
            while vo + 2 <= vend {
                let ver = u16::from_be_bytes([hs[vo], hs[vo + 1]]);
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

/// ClientHello 是否**完整可见**（单 record 收全，或跨 record 分片已全部收到）。
///
/// `prefer_tls13` 用它决定「能不能根据 wire 下结论」：不完整时必须回库默认，
/// 不能把一个 1.3 客户端误判成 1.2（见 boring_path::pick_version_profile）。
pub(crate) fn client_hello_is_complete(buf: &[u8]) -> bool {
    let Some(hs) = reassemble_client_hello(buf) else {
        return false;
    };
    if hs.len() < 4 || hs[0] != 0x01 {
        return false;
    }
    let hl = ((hs[1] as usize) << 16) | ((hs[2] as usize) << 8) | hs[3] as usize;
    hs.len() >= 4 + hl
}

/// Scan ClientHello extensions for supported_versions containing TLS 1.3 (0x0304).
///
/// `pub(crate)`：`boring_path` 的 `prefer_tls13` 分流复用它（两套 SSL_CTX 按
/// ClientHello 选择，与 legacy 分流同一套 wire 探测，见 G-12）。
///
/// 支持跨 record 分片的握手消息（见 [`reassemble_client_hello`]）；调用方若需要
/// 「只有完整 ClientHello 才能下结论」的语义，应先用 [`client_hello_is_complete`]。
pub(crate) fn has_tls13_supported_versions(buf: &[u8]) -> bool {
    // 快路径：**首个 record 自身**已包含完整 ClientHello（注意不能拿 peek 总长度
    // 判断：跨 record 分片时总长度也会「够」，但 `buf[5..]` 中间夹着下一条 record
    // 头，直接按 handshake 布局解析会错位 —— 这是本函数第一版的真实 bug）。
    if buf.len() >= 9 && buf[0] == 0x16 && buf[5] == 0x01 {
        let hl = ((buf[6] as usize) << 16) | ((buf[7] as usize) << 8) | buf[8] as usize;
        let rec_end = 5 + u16::from_be_bytes([buf[3], buf[4]]) as usize;
        if rec_end >= 9 + hl && rec_end <= buf.len() {
            return handshake_has_tls13(&buf[5..9 + hl]);
        }
    }
    match reassemble_client_hello(buf) {
        Some(hs) => handshake_has_tls13(&hs),
        None => false,
    }
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

    /// 回归：supported_versions 扩展的 1 字节 vlen 与 2 字节 elen 不一致、
    /// 且扩展正好结束在缓冲区末尾时，旧实现会读越界一字节（`buf[vo + 1]`）panic。
    /// 这个 hello 的布局刻意构造成：ext_len 使 ext_end == buf.len()，elen = 8（偶数）
    /// 让 vo 落到 ext_end-1，vlen = 8 让循环条件 `vo + 1 < vend` 继续成立。
    #[test]
    fn malformed_supported_versions_does_not_panic() {
        let mut hello = vec![
            0x16, 0x03, 0x01, 0x00, 0x38, // record
            0x01, 0x00, 0x00, 0x36, // handshake header
            0x03, 0x03, // client_version（非 0x0300 → 走到 supported_versions 扫描）
        ];
        hello.extend_from_slice(&[0u8; 32]); // random
        hello.push(0x00); // session_id_len
        hello.extend_from_slice(&[0x00, 0x00]); // cipher_suites_len = 0
        hello.push(0x00); // compression_methods_len = 0
        hello.extend_from_slice(&[0x00, 0x0c]); // extensions_len = 12 → ext_end == 61 == len
        hello.extend_from_slice(&[0x00, 0x2b]); // supported_versions
        hello.extend_from_slice(&[0x00, 0x08]); // elen = 8（其后只有 7 字节！）
        hello.push(0x08); // vlen = 8，与 elen 不一致
        hello.extend_from_slice(&[0u8; 7]); // 剩余版本字节
        assert_eq!(hello.len(), 61);
        // 不 panic 且按默认路径回 Boring（GREASE 版本 0x0000，不是 0x0304）。
        assert_eq!(route(&hello), HelloRoute::Boring);
    }

    /// 构造带任意扩展的最小 ClientHello（record 起始）。
    fn hello_with_exts(exts: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut ext = Vec::new();
        for (t, body) in exts {
            ext.extend_from_slice(&t.to_be_bytes());
            ext.extend_from_slice(&(body.len() as u16).to_be_bytes());
            ext.extend_from_slice(body);
        }
        let mut hs = Vec::new();
        hs.extend_from_slice(&[0x03, 0x03]);
        hs.extend_from_slice(&[0u8; 32]);
        hs.push(0x00); // session id
        hs.extend_from_slice(&2u16.to_be_bytes());
        hs.extend_from_slice(&[0x13, 0x01]);
        hs.push(1);
        hs.push(0x00);
        hs.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        hs.extend_from_slice(&ext);
        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&((4 + hs.len()) as u16).to_be_bytes());
        rec.push(0x01);
        let hl = hs.len();
        rec.extend_from_slice(&[(hl >> 16) as u8, (hl >> 8) as u8, hl as u8]);
        rec.extend_from_slice(&hs);
        rec
    }

    fn sni_ext(name: &str) -> (u16, Vec<u8>) {
        let nb = name.as_bytes();
        let mut ed = Vec::new();
        ed.extend_from_slice(&((1 + 2 + nb.len()) as u16).to_be_bytes());
        ed.push(0x00);
        ed.extend_from_slice(&(nb.len() as u16).to_be_bytes());
        ed.extend_from_slice(nb);
        (0x0000, ed)
    }

    fn versions_ext(versions: &[u16]) -> (u16, Vec<u8>) {
        let mut ed = vec![(versions.len() * 2) as u8];
        for v in versions {
            ed.extend_from_slice(&v.to_be_bytes());
        }
        (0x002b, ed)
    }

    /// 把单 record 的 ClientHello 拆成两条握手 record（RFC 8446 §5.1 允许的分片）。
    fn split_records(full: &[u8], at: usize) -> Vec<u8> {
        assert_eq!(full[0], 0x16);
        let hs = &full[5..];
        let at = at.min(hs.len());
        let (a, b) = hs.split_at(at);
        let mut out = Vec::new();
        out.extend_from_slice(&[0x16, 0x03, 0x01]);
        out.extend_from_slice(&(a.len() as u16).to_be_bytes());
        out.extend_from_slice(a);
        out.extend_from_slice(&[0x16, 0x03, 0x01]);
        out.extend_from_slice(&(b.len() as u16).to_be_bytes());
        out.extend_from_slice(b);
        out
    }

    /// 回归：SNI 落在第二个 record 时也必须解析出来 —— 否则 sni_only 会把
    /// 跨 record 分片的正常客户端静默丢弃（旧实现只看第一个 record）。
    #[test]
    fn sni_detected_across_record_fragments() {
        let full = hello_with_exts(&[sni_ext("frag.example")]);
        for at in [1usize, 10, 20, 40, 60] {
            let frag = split_records(&full, at);
            assert_eq!(
                parse_sni(&frag).as_deref(),
                Some("frag.example"),
                "split at {at}: SNI lost across records"
            );
        }
    }

    /// 回归：`supported_versions` 落在第二个 record 时 prefer_tls13 的 wire 探测
    /// 也必须看到 1.3（旧实现只看第一个 record ⇒ 1.3 客户端被压到 1.2 上下文）。
    #[test]
    fn tls13_version_detected_across_record_fragments() {
        let full = hello_with_exts(&[sni_ext("frag.example"), versions_ext(&[0x0304, 0x0303])]);
        assert!(has_tls13_supported_versions(&full));
        for at in [1usize, 10, 20, 40, 60] {
            let frag = split_records(&full, at);
            assert!(
                has_tls13_supported_versions(&frag),
                "split at {at}: TLS1.3 supported_versions lost across records"
            );
            assert_eq!(parse_sni(&frag).as_deref(), Some("frag.example"));
        }
        // 只给第一个分片（第二个 record 尚未到达）：不能谎报 1.3（fail-closed）；
        // SNI 若已在第一片里则应仍可解析。
        let first_only = &split_records(&full, 20)[..25 + 20];
        assert!(!has_tls13_supported_versions(first_only));
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
        // 用 ..Default::default()：字段多，逐个列举会在每次新增字段时断掉（SslConfig 的
        // Default 与 serde 默认值严格一致，见其文档）。
        let ssl = SslConfig::default();
        assert_eq!(resolve(HelloRoute::Nss, &ssl), HelloRoute::Boring);
    }

    #[test]
    fn resolve_tls10_to_nss_when_enabled() {
        let ssl = SslConfig {
            enable_nss: true,
            enable_tomcrypt: true,
            ..SslConfig::default()
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
///
/// 支持握手消息跨 record 分片（见 [`reassemble_client_hello`]）：旧实现只解析
/// 第一个 record，SNI 落在第二个 record 时 `sni_only` 会把正常客户端静默丢弃。
pub fn parse_sni(buf: &[u8]) -> Option<String> {
    if buf.len() < 5 || buf[0] != 0x16 {
        return None;
    }
    // 快路径：**首个 record 自身**已包含完整 ClientHello（不能按 peek 总长度判断，
    // 跨 record 分片时直接按 handshake 布局解析会错位；见 has_tls13 的说明）。
    if buf.len() >= 9 && buf[5] == 0x01 {
        let hl = ((buf[6] as usize) << 16) | ((buf[7] as usize) << 8) | buf[8] as usize;
        let rec_end = 5 + u16::from_be_bytes([buf[3], buf[4]]) as usize;
        if rec_end >= 9 + hl && rec_end <= buf.len() {
            return parse_sni_handshake(&buf[5..9 + hl]);
        }
    }
    let hs = reassemble_client_hello(buf)?;
    parse_sni_handshake(&hs)
}

/// 在 handshake 字节（从 type 开始）里解析 SNI。
fn parse_sni_handshake(hs: &[u8]) -> Option<String> {
    if hs.len() < 4 || hs[0] != 0x01 {
        return None;
    }
    let hl = ((hs[1] as usize) << 16) | ((hs[2] as usize) << 8) | hs[3] as usize;
    let end = hs.len().min(4 + hl);
    // 握手头(4) + 版本(2) + random(32) = session_id_len 偏移 38
    let mut p = 38;
    if p + 1 > end {
        return None;
    }
    // session_id 是 **1 字节长度** + N 字节（u8 session_id_len），不是 u16。
    // 旧实现按 u16 读并 `p += 2 + sid_len`，从这一位起所有后续字段全部错位：
    // cipher_suites_len 会被读成 0x0200 之类的值，扩展区永远走不到。
    let sid_len = hs[p] as usize;
    p += 1 + sid_len;
    if p + 2 > end {
        return None;
    }
    let cs_len = u16::from_be_bytes([hs[p], hs[p + 1]]) as usize;
    p += 2 + cs_len;
    if p >= end {
        return None;
    }
    // compression_methods 同样是 **1 字节长度** + N 字节。旧实现只 `p += 1`
    // 跳过长度字节，却把 `compression_methods[0]` 当成扩展区长度的高位来读，
    // ext_len 得到一个荒唐的值，扩展循环一次都进不去。
    let comp_len = hs[p] as usize;
    p += 1 + comp_len;
    if p + 2 > end {
        return None;
    }
    let ext_len = u16::from_be_bytes([hs[p], hs[p + 1]]) as usize;
    p += 2;
    let ext_end = (p + ext_len).min(end);
    while p + 4 <= ext_end {
        let etype = u16::from_be_bytes([hs[p], hs[p + 1]]);
        let elen = u16::from_be_bytes([hs[p + 2], hs[p + 3]]) as usize;
        let (s, e) = (p + 4, (p + 4 + elen).min(ext_end));
        if etype == 0x0000 && e >= s + 5 {
            // extension_data = ServerNameList:
            //   u16 list_len | u8 name_type | u16 name_len | name
            //
            // 旧实现要求 `list[0]==0 && list[1]==0`（即 list_len 恰为 0）才算命中，
            // 并用 `list[1..3]` 当 name_len——字段偏移整体错位。真实的 ClientHello
            // list_len 是 0x000c 之类的非零值，于是**永远匹配不上**，
            // SNI 解析对任何真实客户端都返回 None（与上面握手类型的偏移 bug 叠加，
            // 使 sni_only 与 port_reuse 的 SNI 分流彻底失效）。
            let list = &hs[s..e];
            if list[2] == 0x00 {
                // name_type == 0 (host_name)
                let nlen = u16::from_be_bytes([list[3], list[4]]) as usize;
                if nlen >= 1 && 5 + nlen <= list.len() {
                    let raw = &list[5..5 + nlen];
                    // SNI 是**攻击者可控**的字节串，且 parse_sni 的返回值会被上层直接
                    // 写进日志（例如 port_reuse 的 `SNI={sni}`）。控制字符（NUL/CR/LF…）
                    // 里一个换行就能在日志中**伪造整行**，所以这里只放行可打印 ASCII：
                    // 真实 HostName 只可能是 ASCII（IDN 走 punycode）。非法即 None ——
                    // 消费方（sni_only / port_reuse 分流）本来就把「取不到 SNI」当拒绝，
                    // 因此这是 fail-closed，不改变这些场景的放行/丢弃结论。
                    if raw.iter().all(|b| (0x21..=0x7e).contains(b)) {
                        return Some(String::from_utf8_lossy(raw).into_owned());
                    }
                    return None;
                }
            }
        }
        p = e;
    }
    None
}

#[cfg(test)]
mod sni_tests {
    use super::parse_sni;

    /// 构造一个**真实布局**的最小 TLS ClientHello（可选带 SNI 扩展）。
    ///
    /// `random_byte30` 刻意可控：旧实现检查的正是 random 的第 31 个字节
    /// （`buf[p-2]` 且 p=43），只有它等于 0x01 才会继续，概率 1/256。
    fn build_client_hello(sni: Option<&str>, random_byte30: u8) -> Vec<u8> {
        let mut random = [0u8; 32];
        random[30] = random_byte30;

        let mut ext = Vec::new();
        if let Some(name) = sni {
            let nb = name.as_bytes();
            // extension_data = ServerNameList: u16 list_len | u8 type | u16 len | name
            let mut ed = Vec::new();
            ed.extend_from_slice(&((1 + 2 + nb.len()) as u16).to_be_bytes());
            ed.push(0x00); // host_name
            ed.extend_from_slice(&(nb.len() as u16).to_be_bytes());
            ed.extend_from_slice(nb);
            ext.extend_from_slice(&0x0000u16.to_be_bytes()); // ext type = server_name
            ext.extend_from_slice(&(ed.len() as u16).to_be_bytes());
            ext.extend_from_slice(&ed);
        }

        let mut hs = Vec::new();
        hs.extend_from_slice(&[0x03, 0x03]); // client_version
        hs.extend_from_slice(&random);
        hs.push(0x00); // session_id_len
        hs.extend_from_slice(&2u16.to_be_bytes());
        hs.extend_from_slice(&[0x00, 0x2f]); // cipher_suites
        hs.push(1); // compression_methods_len
        hs.push(0x00);
        hs.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        hs.extend_from_slice(&ext);

        let mut rec = Vec::new();
        rec.push(0x16); // handshake record
        rec.extend_from_slice(&[0x03, 0x01]); // record version
        rec.extend_from_slice(&((4 + hs.len()) as u16).to_be_bytes());
        rec.push(0x01); // handshake type = ClientHello
        let hl = hs.len();
        rec.extend_from_slice(&[(hl >> 16) as u8, (hl >> 8) as u8, hl as u8]);
        rec.extend_from_slice(&hs);
        rec
    }

    /// 回归：random[30] != 0x01 时必须仍能解析出 SNI。
    /// 旧实现（检查 random 第 31 字节）在这里返回 None——sni_only 会误杀这些客户端。
    #[test]
    fn sni_parsed_regardless_of_random_byte() {
        assert_eq!(
            parse_sni(&build_client_hello(Some("localhost"), 0x00)).as_deref(),
            Some("localhost")
        );
        assert_eq!(
            parse_sni(&build_client_hello(Some("v.qq.com"), 0xff)).as_deref(),
            Some("v.qq.com")
        );
        assert_eq!(
            parse_sni(&build_client_hello(Some("crucible.local"), 0x01)).as_deref(),
            Some("crucible.local")
        );
    }

    #[test]
    fn sni_absent_returns_none() {
        assert_eq!(parse_sni(&build_client_hello(None, 0x01)), None);
    }

    /// SNI 里塞控制字符/非 ASCII 必须被拒（None）：这些字节会被上层写进日志，
    /// 一个 `\n` 就能伪造日志行；真实 HostName 只可能是可打印 ASCII。
    #[test]
    fn sni_rejects_control_and_non_ascii() {
        assert_eq!(parse_sni(&build_client_hello(Some("bad\nname"), 0x00)), None);
        assert_eq!(parse_sni(&build_client_hello(Some("a\rb"), 0x00)), None);
        assert_eq!(parse_sni(&build_client_hello(Some("nul\0byte"), 0x00)), None);
        // 非 ASCII（UTF-8 多字节）同样拒绝：IDN 走 punycode，不会是裸 UTF-8。
        assert_eq!(parse_sni(&build_client_hello(Some("café"), 0x00)), None);
        // 正对照：正常主机名照旧解析。
        assert_eq!(
            parse_sni(&build_client_hello(Some("v.qq.com"), 0x00)).as_deref(),
            Some("v.qq.com")
        );
    }
}
