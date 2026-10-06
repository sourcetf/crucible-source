//! 早期规格 1b：OCSP 智能获取——免手动指定 ocsp_der_path。
//!
//! 流程：① 从 `ssl.cert` 全链材料找 issuer（subject == leaf.issuer）；
//! ② 链内缺失时从叶子 AIA caIssuers URL 下载 issuer（DER X509 / PKCS7 内嵌证书
//!    双解析）；③ 手工 DER 编码 RFC 6960 OCSPRequest（CertID = SHA1(issuer name
//!    DER) + SHA1(issuer SPKI BIT STRING 内容) + leaf 序列号；BoringSSL 已剥离
//!    请求构建 API）；④ boring TLS POST → 完整 OCSPResponse 即装订物；
//! ⑤ 缓存 state/ocsp/{host}.der + 进程内存（TTL 取响应 nextUpdate，缺省 23h，
//!    到期前 1h 重拉）；网络失败回退旧缓存。
//!
//! 线程模型（关键）：握手路径**绝不触网**。acceptor 冷构建只读本地缓存；
//! 网络获取全部经 [`StapleSlot`] 的后台 detached 线程完成，取回后写入槽，
//! 后续握手回调即自动装订新响应（无需重建 acceptor）。
//!
//! 目录约定：缓存落在 `state/ocsp/`（与 tor_hs/php/dns/go_shm 的 `state/<feature>/`
//! 一致）。本仓库没有通用的「程序目录/状态目录」解析助手（`tor_hs::state_dir`
//! 与 `apps::*::abs_path` 均为各自模块私有），故此处沿用既有 CWD 相对约定。

use anyhow::{Context, Result};
use boring::hash::{hash, MessageDigest};
use boring::x509::X509;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// 响应无 nextUpdate 时的兜底 TTL（与历史行为一致：23h）。
const FALLBACK_TTL: Duration = Duration::from_secs(23 * 3600);
/// 到期前提前重拉的余量。
const RENEW_MARGIN: Duration = Duration::from_secs(3600);
/// OCSP 出网预算：responder 是第三方，可能不响应 / 极慢 / 返回超大 body。
/// 不设限时唯一续期线程会被一个坏 responder **永久卡死**，随后**所有**证书的
/// OCSP 续期一起停摆（tls-core P2）。冷路径，取值宽松但必须有限。
const OCSP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const OCSP_IO_TIMEOUT: Duration = Duration::from_secs(15);
/// 响应体上限：正常 OCSPResponse / caIssuers 证书都远小于此；超限即判对端异常并放弃
/// （防止 `read_to_end` 被恶意/故障对端用无限 body 撑爆内存）。
const OCSP_MAX_BODY: usize = 256 * 1024;
/// SHA-1 + NULL 的 **AlgorithmIdentifier 内容**（OID 2.16.840.1.101.3.4.2.26 + NULL），
/// **不含** 外层 `30 len`。
///
/// 旧常量是 11 字节的 `30 0F 06 05 ...`，即「一个完整 SEQUENCE 的头 + 内容」，
/// 但 `build_ocsp_request` 又用 `der_tlv(0x30, SHA1_ALGID)` 在它外面**再套一层**
/// SEQUENCE：实际产出变成 `30 0B 30 0F <TWO> <NULL>` —— 内层 SEQUENCE 声明长度
/// 0x0F(15) 而其后只有 9 字节内容。这不是合法 DER（`openssl asn1parse` 直接报
/// "ASN1_get_object:too long"），responder 只能回 `malformedRequest`：
/// **自动 OCSP 抓取对任何真实 CA 都从未成功过一次**（换只手写编码也没救，
/// 因为 BoringSSL 已移除请求构建 API，而校验路径只看响应、不看请求）。
///
/// 修法：常量只保留内容，让 `der_tlv(0x30, …)` 补上正确的长度头。
/// 已验证：修正后请求与 `openssl ocsp -reqout` 的输出**逐字节一致**。
const SHA1_ALGID_BODY: &[u8] = &[0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00];

/// 进程内存缓存：cache_key -> 已装订响应。
/// 有效期完全由响应自身 nextUpdate 推导（见 [`fresh_for`]），不写死 TTL。
static CACHE: Lazy<Mutex<HashMap<String, Cached>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

#[derive(Clone)]
struct Cached {
    der: Vec<u8>,
    /// 抓取时刻（UNIX 秒）。
    fetched_unix: i64,
    /// 响应 nextUpdate（UNIX 秒）；None = 响应未携带 nextUpdate。
    next_update_unix: Option<i64>,
}

/// OCSP 缓存目录（`state/ocsp`；与 tor_hs/php/dns/go_shm 的 state/<feature>/ 约定一致）。
fn cache_dir() -> std::path::PathBuf {
    std::path::Path::new("state").join("ocsp")
}

/// 证书指纹（SHA-256 前 16 字节 hex）——缓存键与缓存文件名都用它。
///
/// 旧实现用 **leaf DER 长度** 当指纹（`format!("{host}:{}", leaf_der.len())`），
/// 缓存文件名干脆只有 host：
/// - 同密钥类型的续期证书 DER 长度几乎不变（`certbot renew` 后仍是同样的字段布局），
///   于是新证书会命中旧证书的缓存条目，把 **A 证书的 OCSPResponse 装订到 B 证书上**；
///   客户端按 CertID 校验必然对不上（must-staple 直接握手失败），而续期线程要等
///   缓存「不新鲜」（最长 23h）才会重拉；
/// - 同一 host 上并存两张证书（RSA + ECDSA `cert_ec`、两个 listener）时同理。
fn leaf_fingerprint(leaf_der: &[u8]) -> String {
    match hash(MessageDigest::sha256(), leaf_der) {
        Ok(d) => d.iter().take(16).map(|b| format!("{b:02x}")).collect(),
        Err(_) => "00000000000000000000000000000000".to_string(),
    }
}

/// 缓存文件：`state/ocsp/{host}-{指纹}.der`（指纹进文件名，杜绝跨证书复用）。
fn cache_file_for(host: &str, fingerprint: &str) -> std::path::PathBuf {
    cache_dir().join(format!("{}-{}.der", sanitize(host), fingerprint))
}

/// 旧版（无指纹）缓存文件路径：`state/ocsp/{host}.der`。
/// 只用于**带 CertID 校验**的兼容读取（见 [`load_disk_cache`]）。
fn legacy_cache_file(host: &str) -> std::path::PathBuf {
    cache_dir().join(format!("{}.der", sanitize(host)))
}

/// 当前 UNIX 秒（时钟异常回退 0）。
fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// 该缓存条目还「新鲜」多久（返回 None = 已过期，必须重拉）。
/// 有 nextUpdate 时以它为准（到期前 RENEW_MARGIN 即视为过期）；
/// 无 nextUpdate 时退回 FALLBACK_TTL。
fn fresh_for(c: &Cached) -> Option<Duration> {
    let margin = RENEW_MARGIN.as_secs() as i64;
    match c.next_update_unix {
        Some(nu) => {
            let left = nu - now_unix();
            if left <= margin {
                return None;
            }
            Some(Duration::from_secs((left - margin) as u64))
        }
        None => {
            let age = now_unix() - c.fetched_unix;
            let ttl = FALLBACK_TTL.as_secs() as i64;
            if age + margin >= ttl {
                return None;
            }
            Some(Duration::from_secs((ttl - age - margin) as u64))
        }
    }
}

/// 响应是否**已过期**（nextUpdate 明确存在且已过）。
///
/// 与 [`fresh_for`] 的区别：`fresh_for` 把「临近 nextUpdate（RENEW_MARGIN 内）」也算
/// 不新鲜以便提前重拉；这里只判「确凿过期」。过期响应**绝不能装订**：must-staple
/// 客户端会因 staple 无效直接握手失败，普通客户端也拿到无用的 staple。宁可保留旧槽
/// （可能仍有效）或留空（客户端自行查询 OCSP），也不要用一份过期响应去覆盖它。
fn hard_expired(next_update_unix: Option<i64>, now: i64) -> bool {
    matches!(next_update_unix, Some(nu) if nu <= now)
}

/// 从 OCSPResponse 提取 nextUpdate（UNIX 秒）。
/// OCSPResponse{status, [0]{ResponseBytes{oid, OCTET STRING BasicOCSPResponse}}}；
/// BasicOCSPResponse{tbsResponseData ResponseData, ...}；
/// ResponseData{version?, responderID, producedAt, SEQUENCE OF SingleResponse, ...}；
/// SingleResponse{certID, certStatus, thisUpdate, [0] EXPLICIT nextUpdate OPTIONAL}。
fn parse_next_update(resp: &[u8]) -> Option<i64> {
    let basic = ocsp_basic_response(resp)?;
    // BasicOCSPResponse SEQUENCE → tbsResponseData SEQUENCE
    let (t, _, bh) = der_head(basic, 0)?;
    if t != 0x30 {
        return None;
    }
    let (t, rd_len, rh) = der_head(basic, bh)?;
    if t != 0x30 {
        return None;
    }
    let rd_start = bh + rh;
    let rd_end = (rd_start + rd_len).min(basic.len());
    let mut p = rd_start;
    // version [0] EXPLICIT（可选）
    if basic.get(p) == Some(&0xA0) {
        p = der_next(basic, p)?;
    }
    p = der_next(basic, p)?; // responderID
    p = der_next(basic, p)?; // producedAt
    // responses SEQUENCE OF SingleResponse
    let (t, _, sh) = der_head(basic, p)?;
    if t != 0x30 {
        return None;
    }
    let mut q = p + sh;
    while q < rd_end {
        let (t, sr_len, srh) = der_head(basic, q)?;
        if t != 0x30 {
            break;
        }
        let sr_end = (q + srh + sr_len).min(rd_end);
        // SingleResponse：certID / certStatus / thisUpdate 各跳过一个元素。
        let mut r = q + srh;
        r = der_next(basic, r)?;
        r = der_next(basic, r)?;
        r = der_next(basic, r)?;
        // nextUpdate [0] EXPLICIT GeneralizedTime（可选）
        if basic.get(r) == Some(&0xA0) {
            let (_, _, nh) = der_head(basic, r)?;
            let (gt, glen, gh) = der_head(basic, r + nh)?;
            if gt == 0x18 {
                // 时间串必须整体落在缓冲区内：der_head 的短长度形式不做越界检查，
                // 直接切片会在畸形响应上 panic（这条路径在 acceptor 冷构建里也会走到）。
                let s_start = r + nh + gh;
                let s_end = match s_start.checked_add(glen) {
                    Some(e) if e <= basic.len() => e,
                    _ => return None,
                };
                let s = std::str::from_utf8(&basic[s_start..s_end]).ok()?;
                if let Some(v) = parse_generalized_time(s) {
                    return Some(v);
                }
            }
        }
        if sr_end <= q {
            break;
        }
        q = sr_end;
    }
    None
}

/// OCSPResponse 外层 [0] EXPLICIT 内的 BasicOCSPResponse 字节。
fn ocsp_basic_response(resp: &[u8]) -> Option<&[u8]> {
    let (t, _, h) = der_head(resp, 0)?;
    if t != 0x30 {
        return None;
    }
    let mut p = der_next(resp, h)?; // responseStatus
    let (t, _, eh) = der_head(resp, p)?;
    if t != 0xA0 {
        return None;
    }
    let (t, _, rh) = der_head(resp, p + eh)?; // ResponseBytes SEQUENCE
    if t != 0x30 {
        return None;
    }
    let mut q = der_next(resp, p + eh + rh)?; // responseType OID
    let (t, olen, oh) = der_head(resp, q)?;
    if t != 0x04 {
        return None;
    }
    // 内容必须整体在缓冲区内：der_head 对短长度形式只读长度字节、不验证是否越界，
    // 直接切片会在**畸形/截断响应**上 panic（这里的输入是网络抓回或磁盘缓存的文件）。
    let start = q + oh;
    let end = match start.checked_add(olen) {
        Some(e) if e <= resp.len() => e,
        _ => return None,
    };
    Some(&resp[start..end])
}

/// GeneralizedTime `YYYYMMDDHHMMSS[.fff]Z` → UNIX 秒（只接受 UTC 的 `Z` 形式）。
///
/// 旧实现要求第 15 个字节就是 `Z`，于是 `20240101120000.000Z`（部分 responder 会带
/// 小数秒）解析失败 → 整条响应被当作「无 nextUpdate」→ 退回 23h 兜底 TTL：一个
/// 1 小时后就过期的响应会被继续装订最多 22 小时（客户端按 nextUpdate 判过期 → 失败）。
fn parse_generalized_time(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() < 15 || b[14] != b'Z' && b[14] != b'.' && b[14] != b',' {
        return None;
    }
    if b[14] != b'Z' {
        // 小数秒：'.' / ',' + 至少 1 位数字 + 'Z'（小数部分忽略，秒是最小粒度）。
        let frac = &b[15..];
        if frac.len() < 2 || *frac.last()? != b'Z' {
            return None;
        }
        if !frac[..frac.len() - 1].iter().all(|c| c.is_ascii_digit()) {
            return None;
        }
    }
    let num = |r: std::ops::Range<usize>| -> Option<i64> { s.get(r)?.parse().ok() };
    let (y, mo, d) = (num(0..4)?, num(4..6)?, num(6..8)?);
    let (h, mi, sec) = (num(8..10)?, num(10..12)?, num(12..14)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    // 民用日期 → UNIX 秒（Howard Hinnant days_from_civil）。
    let y = if mo <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Some(days * 86400 + h * 3600 + mi * 60 + sec)
}

// ------------------------------------------------------------ DER 小工具

/// 读 DER TLV 头：返回 (tag, content_len, header_len)。
fn der_head(b: &[u8], off: usize) -> Option<(u8, usize, usize)> {
    if off + 2 > b.len() {
        return None;
    }
    let tag = b[off];
    let first = b[off + 1] as usize;
    if first < 0x80 {
        Some((tag, first, 2))
    } else {
        let n = first & 0x7F;
        if n == 0 || n > 4 || off + 2 + n > b.len() {
            return None;
        }
        let mut len = 0usize;
        for k in 0..n {
            len = (len << 8) | b[off + 2 + k] as usize;
        }
        if off + 2 + n + len > b.len() {
            return None;
        }
        Some((tag, len, 2 + n))
    }
}

/// 跳过一个完整 DER 元素。
fn der_next(b: &[u8], off: usize) -> Option<usize> {
    let (_, len, h) = der_head(b, off)?;
    Some(off + h + len)
}

/// TLV 构造。
fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let l = content.len();
    if l < 0x80 {
        out.push(l as u8);
    } else if l <= 0xFF {
        out.extend_from_slice(&[0x81, l as u8]);
    } else {
        out.extend_from_slice(&[0x82, (l >> 8) as u8, (l & 0xFF) as u8]);
    }
    out.extend_from_slice(content);
    out
}

/// 叶子序列号 INTEGER 内容（DER 原样，含前导 0x00 语义保留）。
fn extract_serial(cert_der: &[u8]) -> Option<Vec<u8>> {
    let (_, _, h0) = der_head(cert_der, 0)?;
    let mut p = h0;
    let (_, _, h1) = der_head(cert_der, p)?;
    p += h1; // 进 TBS 内容
    if cert_der.get(p) == Some(&0xA0) {
        p = der_next(cert_der, p)?; // version [0]
    }
    let (tag, len, h) = der_head(cert_der, p)?;
    if tag != 0x02 {
        return None;
    }
    Some(cert_der[p + h..p + h + len].to_vec())
}

/// issuer SPKI 的 BIT STRING 内容（issuerKeyHash = SHA1(该内容)）。
fn extract_spki_bits(cert_der: &[u8]) -> Option<Vec<u8>> {
    let (_, _, h0) = der_head(cert_der, 0)?;
    let mut p = h0;
    let (_, _, h1) = der_head(cert_der, p)?;
    p += h1;
    if cert_der.get(p) == Some(&0xA0) {
        p = der_next(cert_der, p)?;
    }
    p = der_next(cert_der, p)?; // serial
    p = der_next(cert_der, p)?; // sigalg
    p = der_next(cert_der, p)?; // issuer
    p = der_next(cert_der, p)?; // validity
    p = der_next(cert_der, p)?; // subject
    let (tag, len, h) = der_head(cert_der, p)?;
    if tag != 0x30 {
        return None;
    }
    let spki = &cert_der[p + h..p + h + len];
    // SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }
    //
    // 旧实现在这里只读了外层 SEQUENCE 的头（`ha`）就去看下一个 TLV —— 但紧随其后的
    // 是 **AlgorithmIdentifier（SEQUENCE, 0x30）**，不是 BIT STRING。于是
    // `bt != 0x03` 恒成立、`extract_spki_bits` 对**任何**证书都返回 None ⇒
    // `build_ocsp_request` 的 `?` 直接让 `obtain()` 返回 None ⇒
    // 「自动 OCSP 抓取」在**任何**配置下都不可能成功（与请求 DER 编码是同一条链上的
    // 两个独立缺陷）。必须**跳过 AlgId 整个 TLV**（用 `der_next`）再读 BIT STRING。
    let q = der_next(spki, 0)?;
    let (bt, blen, bh) = der_head(spki, q)?;
    if bt != 0x03 {
        return None;
    }
    if blen == 0 {
        return None;
    }
    let start = q + bh + 1; // 首字节 = 未用位数（unused bits）
    Some(spki[start..q + bh + blen].to_vec())
}

// ------------------------------------------------------------ AIA 提取

/// AIA：返回 (OCSP URL 列表, CA Issuers URL 列表)。
pub fn extract_aia(cert_der: &[u8]) -> (Vec<String>, Vec<String>) {
    // accessMethod OID 前缀（去掉外层 06 08 后的内容）：
    // OCSP = 2B 06 01 05 05 07 30 01；caIssuers = …30 02
    const OCSP_M: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01];
    const CAI_M: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02];
    let (mut ocsp, mut cai) = (Vec::new(), Vec::new());
    let mut i = 0usize;
    while i + 11 <= cert_der.len() {
        if cert_der[i] != 0x06 || cert_der[i + 1] != 0x08 {
            i += 1;
            continue;
        }
        let method = &cert_der[i + 2..i + 10];
        let is_ocsp = method == OCSP_M;
        let is_cai = method == CAI_M;
        if !is_ocsp && !is_cai {
            i += 1;
            continue;
        }
        // accessLocation [6] primitive：0x86 len + URL（AIA 内紧随其后）
        let seg_end = (i + 200).min(cert_der.len());
        let seg = &cert_der[i + 10..seg_end];
        if let Some(q) = seg.iter().position(|&b| b == 0x86) {
            // seg[q] 可能就是最后一个字节：先取长度字节再切片，否则越界 panic。
            if let Some(&l) = seg.get(q + 1) {
                let l = l as usize;
                if q + 2 + l <= seg.len() {
                    let url = String::from_utf8_lossy(&seg[q + 2..q + 2 + l]).into_owned();
                    if url.starts_with("http") {
                        if is_ocsp {
                            ocsp.push(url);
                        } else {
                            cai.push(url);
                        }
                    }
                }
            }
        }
        i += 10;
    }
    ocsp.sort();
    ocsp.dedup();
    cai.sort();
    cai.dedup();
    (ocsp, cai)
}

/// 链内找 issuer（subject DER == leaf.issuer DER 且非自身）。
pub fn find_issuer_in_pem(cert_pem: &[u8], leaf: &X509) -> Option<X509> {
    let chain = X509::stack_from_pem(cert_pem).ok()?;
    let issuer_der = leaf.issuer_name().to_der().ok()?;
    for c in &chain {
        if c.issuer_name().to_der().ok()? == c.subject_name().to_der().ok()? {
            continue; // 自签名根，不作为中间链 issuer
        }
        if c.subject_name().to_der().ok()? == issuer_der {
            if let (Ok(leaf_d), Ok(c_d)) = (leaf.to_der(), c.to_der()) {
                if leaf_d == c_d {
                    continue;
                }
            }
            return Some(c.clone());
        }
    }
    None
}

// ------------------------------------------------------------ OCSP 请求构建

/// 纯函数部分：由三个已算好的字段组装完整 OCSPRequest DER。
///
/// 拆出来是为了能用**确定性测试向量**钉住编码（`build_ocsp_request` 需要 X509 对象，
/// 单测里不好构造）。回归见 `tests::ocsp_request_der_matches_golden_vector`。
///
/// RFC 6960 的嵌套（**五层** SEQUENCE，缺一层都不是合法请求；旧的实现只有四层，
/// 产出的其实是一个裸 TBSRequest —— responder 只能回 `malformedRequest`）：
/// ```text
/// OCSPRequest          SEQUENCE { tbsRequest }
///   TBSRequest         SEQUENCE { requestList }
///     requestList      SEQUENCE OF Request
///       Request        SEQUENCE { reqCert }
///         CertID       SEQUENCE { hashAlgorithm, issuerNameHash, issuerKeyHash, serialNumber }
///           hashAlgorithm  AlgorithmIdentifier = SHA-1 + NULL
/// ```
fn encode_ocsp_request(name_hash: &[u8], key_hash: &[u8], serial: &[u8]) -> Vec<u8> {
    // CertID 的内容：AlgId(TLV) + issuerNameHash + issuerKeyHash + serialNumber。
    let mut certid_body = der_tlv(0x30, SHA1_ALGID_BODY);
    certid_body.extend(der_tlv(0x04, name_hash));
    certid_body.extend(der_tlv(0x04, key_hash));
    certid_body.extend(der_tlv(0x02, serial));
    let certid = der_tlv(0x30, &certid_body); // CertID
    let request = der_tlv(0x30, &certid); // Request
    let request_list = der_tlv(0x30, &request); // requestList（SEQUENCE OF）
    let tbs = der_tlv(0x30, &request_list); // TBSRequest
    der_tlv(0x30, &tbs) // OCSPRequest ← 这一层旧实现漏了
}

/// 手工 DER 编码 OCSPRequest（CertID = SHA1；RFC 6960）。
pub fn build_ocsp_request(
    leaf: &X509,
    issuer_name_der: &[u8],
    issuer_spki_bits: &[u8],
) -> Result<Vec<u8>> {
    let name_hash = hash(MessageDigest::sha1(), issuer_name_der)?;
    let key_hash = hash(MessageDigest::sha1(), issuer_spki_bits)?;
    let serial = extract_serial(&leaf.to_der()?).context("leaf serial parse")?;
    Ok(encode_ocsp_request(&name_hash, &key_hash, &serial))
}

// ------------------------------------------------------------ 阻塞 HTTP(S)（boring）

/// 对端地址解析（v4/v6 都要能连）：`(host, port)` 可能解析出多个地址，
/// 逐个尝试而不是只取第一个 —— AIA URL 的域名常有 AAAA+A，首个不可达时
/// 旧实现直接放弃（IPv6-only 环境里 v4 优先会全灭）。
fn resolve_addrs(host: &str, port: u16) -> Result<Vec<std::net::SocketAddr>> {
    use std::net::ToSocketAddrs;
    let addrs: Vec<std::net::SocketAddr> = (host, port)
        .to_socket_addrs()
        .with_context(|| format!("ocsp resolve {host}:{port}"))?
        .collect();
    if addrs.is_empty() {
        anyhow::bail!("ocsp: no address for {host}:{port}");
    }
    Ok(addrs)
}

/// 阻塞 HTTP(S) GET/POST（冷路径专用）：`https=true` 走 boring TLS，否则**明文**
/// HTTP。
///
/// 为什么需要明文分支：RFC 6960 的 AIA `ocsp` / `caIssuers` URL 常见 `http://`
/// （GlobalSign、DigiCert 的 OCSP responder 至今如此，见本机实测：
/// `http://ocsp.globalsign.com/...`）。旧实现**不看 scheme**、一律先做 TLS 握手，
/// 于是所有 `http://` responder 都在握手阶段失败（对 80 端口做 TLS 会收到明文
/// HTTP 响应 → `record layer failure`），自动装订对这批 CA 从未成功。
/// `SimpleUrl::https` 字段解析出来了却没有任何消费点 —— 这正是那条「解析了但没用」
/// 的沉默降级。
fn http_req(
    host: &str,
    port: u16,
    https: bool,
    method: &str,
    path: &str,
    ctype: Option<&str>,
    body: Option<&[u8]>,
) -> Result<Vec<u8>> {
    use std::io::{Read, Write};
    // connect 必须有超时（旧实现 `TcpStream::connect` 会一直阻塞到内核 TCP 超时，
    // 单条坏 responder 即可冻结整个续期线程）；连上后读/写也要有超时，否则对端
    // 收下请求后不回字节，`read_to_end` 同样永久阻塞。
    let addr = resolve_addrs(host, port)?;
    let mut last_err: Option<anyhow::Error> = None;
    let tcp = addr.iter().find_map(|a| {
        match std::net::TcpStream::connect_timeout(a, OCSP_CONNECT_TIMEOUT) {
            Ok(t) => Some(t),
            Err(e) => {
                last_err = Some(anyhow::Error::new(e).context(format!("ocsp connect {host}:{port}")));
                None
            }
        }
    });
    let tcp = tcp.ok_or_else(|| {
        last_err.unwrap_or_else(|| anyhow::anyhow!("ocsp connect {host}:{port}: no address worked"))
    })?;
    tcp.set_read_timeout(Some(OCSP_IO_TIMEOUT))?;
    tcp.set_write_timeout(Some(OCSP_IO_TIMEOUT))?;
    let path = if path.is_empty() { "/" } else { path };
    let cl = body.map(|b| b.len()).unwrap_or(0);
    // ⚠️ 头部块必须以**空行**结束（`…\r\n\r\n`）。旧实现最后一段是
    // `Content-Type: …\r\n`（或没有 Content-Type 时以 `Content-Length: …\r\n` 收尾），
    // **从不发那个空行** —— 严格实现的 responder（如 `openssl ocsp -port`）直接判
    // `error parsing HTTP header: missing end of line`、按协议错误处理；宽松的
    // （Cloudflare 之类）会自动补一个空行从而「看起来能跑」，所以这个缺陷长期不可见。
    // 实测：本地 responder 日志里能看到我们的 `POST / HTTP/1.1` 但读不到完整头。
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nAccept: application/ocsp-response\r\nConnection: close\r\nContent-Length: {cl}\r\n{}\r\n",
        if ctype.is_some() {
            format!("Content-Type: {}\r\n", ctype.unwrap())
        } else {
            String::new()
        }
    );
    // 有界读取：`read_to_end` 无上限，一个返回无限流的 responder 可把内存撑爆。
    // 正常 OCSPResponse/证书链都远小于 OCSP_MAX_BODY。
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    if https {
        let mut b = boring::ssl::SslConnector::builder(boring::ssl::SslMethod::tls())?;
        b.set_alpn_protos(b"\x08http/1.1")?;
        let ssl = b.build().configure()?.into_ssl(host)?;
        let mut tls = boring::ssl::SslStream::new(ssl, tcp)?;
        tls.write_all(req.as_bytes())?;
        if let Some(b) = body {
            tls.write_all(b)?;
        }
        tls.flush()?;
        loop {
            let n = tls.read(&mut chunk)?;
            if n == 0 {
                break;
            }
            if buf.len() + n > OCSP_MAX_BODY {
                anyhow::bail!("ocsp response body exceeds {OCSP_MAX_BODY} bytes");
            }
            buf.extend_from_slice(&chunk[..n]);
        }
    } else {
        let mut plain = tcp;
        plain.write_all(req.as_bytes())?;
        if let Some(b) = body {
            plain.write_all(b)?;
        }
        plain.flush()?;
        loop {
            let n = plain.read(&mut chunk)?;
            if n == 0 {
                break;
            }
            if buf.len() + n > OCSP_MAX_BODY {
                anyhow::bail!("ocsp response body exceeds {OCSP_MAX_BODY} bytes");
            }
            buf.extend_from_slice(&chunk[..n]);
        }
    }
    let head_end = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .context("bad http response")?;
    let status = String::from_utf8_lossy(
        &buf[..buf.windows(2).position(|w| w == b"\r\n").unwrap_or(0)],
    );
    if !status.contains(" 200 ") {
        anyhow::bail!("ocsp http {}", status.trim());
    }
    Ok(buf[head_end + 4..].to_vec())
}

// ------------------------------------------------------------ 响应校验

/// OCSPResponse 外层 status 必须为 0（successful），且外层 SEQUENCE 必须长度自洽。
///
/// 旧实现只看「tag == SEQUENCE」与 responseStatus 两个字节，不看外层声明长度是否
/// 落在缓冲区内 —— 而 DER **短长度形式**（内容 < 128 字节）的 `der_head` 不做越界
/// 检查，于是一个声明长度超出缓冲区的响应（截断的小响应、构造的垃圾文件）也能通过
/// 这道检查，随后被当成有效装订物发给客户端（客户端回源校验失败，
/// must-staple 部署直接握手失败）。
fn ocsp_response_ok(der: &[u8]) -> bool {
    let (t, l, h) = match der_head(der, 0) {
        Some(x) => x,
        None => return false,
    };
    if t != 0x30 || h + l > der.len() {
        return false;
    }
    if der.get(h) != Some(&0x0A) {
        return false;
    }
    let (_, l, hh) = match der_head(der, h) {
        Some(x) => x,
        None => return false,
    };
    l == 1 && der.get(h + hh) == Some(&0)
}

/// OCSPResponse 中所有 SingleResponse 的 `CertID.serialNumber`（DER INTEGER 内容）。
///
/// 用于核对「这份响应确实是关于**这张**证书的」（CertID 的其余三个字段是 issuer
/// 相关，序列号是最便宜、最直接的比对项）。解析不出来时返回空表，调用方据此保持
/// 宽容（只在能确定不匹配时才拒绝），避免误杀格式特殊的响应。
fn response_serials(resp: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let Some(basic) = ocsp_basic_response(resp) else {
        return out;
    };
    let Some((t, _, bh)) = der_head(basic, 0) else {
        return out;
    };
    if t != 0x30 {
        return out;
    }
    let Some((t, rd_len, rh)) = der_head(basic, bh) else {
        return out;
    };
    if t != 0x30 {
        return out;
    }
    let rd_start = bh + rh;
    let rd_end = (rd_start + rd_len).min(basic.len());
    let mut p = rd_start;
    // version [0] EXPLICIT（可选）
    if basic.get(p) == Some(&0xA0) {
        match der_next(basic, p) {
            Some(n) => p = n,
            None => return out,
        }
    }
    // responderID + producedAt
    match der_next(basic, p) {
        Some(n) => p = n,
        None => return out,
    }
    match der_next(basic, p) {
        Some(n) => p = n,
        None => return out,
    }
    let Some((t, _, sh)) = der_head(basic, p) else {
        return out;
    };
    if t != 0x30 {
        return out;
    }
    let mut q = p + sh;
    while q < rd_end {
        let Some((t, sr_len, srh)) = der_head(basic, q) else {
            break;
        };
        if t != 0x30 {
            break;
        }
        let sr_end = (q + srh + sr_len).min(rd_end);
        // certID ::= SEQUENCE { hashAlg, issuerNameHash, issuerKeyHash, serialNumber }
        if let Some((ct, clen, ch)) = der_head(basic, q + srh) {
            if ct == 0x30 {
                let cid_start = q + srh + ch;
                let cid_end = (cid_start + clen).min(basic.len());
                let mut c = cid_start;
                let mut ok = true;
                for _ in 0..3 {
                    match der_next(basic, c) {
                        Some(n) if n <= cid_end => c = n,
                        _ => {
                            ok = false;
                            break;
                        }
                    }
                }
                if ok {
                    if let Some((st, slen, sh2)) = der_head(basic, c) {
                        if st == 0x02 && c + sh2 + slen <= basic.len() {
                            out.push(basic[c + sh2..c + sh2 + slen].to_vec());
                        }
                    }
                }
            }
        }
        if sr_end <= q {
            break;
        }
        q = sr_end;
    }
    out
}

/// DER INTEGER 内容比较：去掉前导 0x00 后逐字节相同
/// （同一序列号在证书与 CertID 里都可能带/不带正数补零）。
fn same_serial(a: &[u8], b: &[u8]) -> bool {
    if a.is_empty() || b.is_empty() {
        return false;
    }
    strip_leading_zeros(a) == strip_leading_zeros(b)
}

/// 去掉 DER INTEGER 内容的前导 0x00（正数补零）。
///
/// 写成独立 `fn` 而不是闭包：闭包的返回引用**不会**自动获得
/// 「返回值的生命周期来自参数」这条推导（elision 只对 `fn` 生效），
/// 写成 `|s: &[u8]| -> &[u8]` 会直接编译失败（lifetime may not live long enough）。
fn strip_leading_zeros(s: &[u8]) -> &[u8] {
    let mut v = s;
    while v.len() > 1 && v[0] == 0 {
        v = &v[1..];
    }
    v
}

/// 这份响应是否覆盖 `leaf`（CertID 序列号匹配）。`None` = 无法判定。
fn response_covers_leaf(resp: &[u8], leaf_serial: &[u8]) -> Option<bool> {
    let serials = response_serials(resp);
    if serials.is_empty() {
        return None;
    }
    Some(serials.iter().any(|s| same_serial(s, leaf_serial)))
}

// ------------------------------------------------------------ 智能入口

fn sanitize(host: &str) -> String {
    host.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' { c } else { '_' })
        .collect()
}

/// 从 PKCS7/DER body 提取与 leaf.issuer 匹配的 issuer 证书。
fn parse_issuer_from_body(body: &[u8], leaf: &X509) -> Option<X509> {
    if let Ok(cert) = X509::from_der(body) {
        if cert.subject_name().to_der().ok()? == leaf.issuer_name().to_der().ok()? {
            return Some(cert);
        }
    }
    // PKCS7：内嵌证书为连续 DER X.509——扫描 30 82 候选并逐一解析匹配
    let issuer_der = leaf.issuer_name().to_der().ok()?;
    let mut i = 0usize;
    while i + 4 <= body.len() {
        if body[i] == 0x30 && body[i + 1] == 0x82 {
            let len = ((body[i + 2] as usize) << 8) | body[i + 3] as usize;
            if i + 4 + len > body.len() {
                i += 1;
                continue;
            }
            if let Ok(cert) = X509::from_der(&body[i..i + 4 + len]) {
                if cert.subject_name().to_der().ok()? == issuer_der {
                    return Some(cert);
                }
            }
            i += 4 + len;
        } else {
            i += 1;
        }
    }
    None
}

/// 智能获取入口（同步、**阻塞**）：缓存 → 链内 issuer → caIssuers 下载 →
/// OCSP POST → 校验 → 缓存落盘。任何失败返回 None（调用方保持无装订语义）。
///
/// 只在后台刷新/续期线程里调用——握手路径必须走 [`StapleSlot::cached_or_spawn`]。
pub fn obtain(host: &str, leaf: &X509, chain_pem: &[u8]) -> Option<Vec<u8>> {
    let leaf_der = leaf.to_der().ok()?;
    let fingerprint = leaf_fingerprint(&leaf_der);
    let cache_key = cache_key_of(host, leaf);
    let (ocsp_urls, cai_urls) = extract_aia(&leaf_der);
    let ocsp_url = ocsp_urls.first()?.clone();
    let issuer = match find_issuer_in_pem(chain_pem, leaf) {
        Some(c) => Some(c),
        None => {
            // caIssuers 下载（阻塞）
            let url = cai_urls.first()?;
            let u = parse_simple(url)?;
            let body = http_req(&u.host, u.port, u.https, "GET", &u.path, None, None).ok()?;
            parse_issuer_from_body(&body, leaf)
        }
    }?;
    let issuer_der = issuer.to_der().ok()?;
    let name_der = issuer.subject_name().to_der().ok()?;
    let spki = extract_spki_bits(&issuer_der)?;
    let req = build_ocsp_request(leaf, &name_der, &spki).ok()?;
    let u = parse_simple(&ocsp_url)?;
    let resp = http_req(&u.host, u.port, u.https, "POST", &u.path,
                        Some("application/ocsp-request"), Some(&req))
        .ok()?;
    if !ocsp_response_ok(&resp) {
        return None;
    }
    // 响应必须覆盖**这张**证书（CertID 序列号）。缓存键已按证书指纹隔离，这里是
    // 最后一道：responder 返回别的证书的 SingleResponse / 中间环节串了响应时，
    // 绝不能装订出去（客户端按 CertID 校验失败 → must-staple 直接握手失败）。
    let leaf_serial = extract_serial(&leaf_der)?;
    if response_covers_leaf(&resp, &leaf_serial) == Some(false) {
        log::warn!("ocsp: {host} 响应 CertID 序列号与站点证书不符，丢弃本次响应");
        return None;
    }
    let entry = Cached {
        fetched_unix: now_unix(),
        next_update_unix: parse_next_update(&resp),
        der: resp.clone(),
    };
    // 过期响应绝不落盘、绝不入缓存、绝不上槽：否则续期线程会 `slot.set` 一份客户端
    // 必拒的 staple，而且下次 tick 之前都无法恢复（tls-core P2）。返回 None 让调用方
    // 保留旧槽（可能仍有效）或维持无装订。
    if hard_expired(entry.next_update_unix, now_unix()) {
        log::warn!("ocsp: {host} responder 返回**已过期**响应（nextUpdate 已过），丢弃且不装订");
        return None;
    }
    let dir = cache_dir();
    let _ = std::fs::create_dir_all(&dir);
    // 原子落盘：崩溃/断电留下的截断文件会被下次启动当成有效缓存（见 write_cache_atomic）。
    if let Err(e) = write_cache_atomic(&cache_file_for(host, &fingerprint), &resp) {
        log::warn!("ocsp: {host} 缓存落盘失败: {e}");
    }
    if let Some(ttl) = fresh_for(&entry) {
        log::info!(
            "ocsp: fetched {} bytes for {host} (nextUpdate in ~{}s)",
            resp.len(),
            ttl.as_secs()
        );
    } else {
        log::warn!("ocsp: fetched response for {host} is already stale at nextUpdate");
    }
    CACHE.lock().insert(cache_key, entry);
    Some(resp)
}

/// 原子写入缓存：先写同目录临时文件再 rename。
///
/// 直接 `fs::write` 在写到一半时崩溃/断电会留下**截断的** OCSPResponse 文件，
/// 而校验侧（[`ocsp_response_ok`]）对外层长度的检查本来就偏弱（DER 短长度形式
/// 不做越界检查），截断文件有被当成有效缓存装订出去的风险。rename 是原子的：
/// 要么是完整的新文件，要么还是旧的。
fn write_cache_atomic(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, data)?;
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// 冷路径启动时把磁盘缓存读回内存（不触网）。
///
/// 读**先按证书指纹命名**的文件；为兼容升级前留下的 `state/ocsp/{host}.der`，
/// 回退读旧文件但要求其 CertID 与本站证书序列号匹配（旧文件名不含证书身份，
/// 无法排除是别的证书的响应——这就是本次修复要堵的「A 证书装订到 B 上」）。
fn load_disk_cache(host: &str, leaf: &X509) -> Option<Vec<u8>> {
    let leaf_der = leaf.to_der().ok()?;
    let fingerprint = leaf_fingerprint(&leaf_der);
    let path = cache_file_for(host, &fingerprint);
    let (path, der) = match std::fs::read(&path) {
        Ok(der) if !der.is_empty() => (path, der),
        _ => {
            let legacy = legacy_cache_file(host);
            let der = std::fs::read(&legacy).ok()?;
            if der.is_empty() || !ocsp_response_ok(&der) {
                return None;
            }
            let serial = extract_serial(&leaf_der)?;
            if response_covers_leaf(&der, &serial) == Some(false) {
                log::warn!(
                    "ocsp: {host} 旧缓存 {} 的 CertID 与当前证书不符，忽略（等待重新获取）",
                    legacy.display()
                );
                return None;
            }
            (legacy, der)
        }
    };
    if !ocsp_response_ok(&der) {
        return None;
    }
    let entry = Cached {
        fetched_unix: file_mtime_unix(&path).unwrap_or_else(now_unix),
        next_update_unix: parse_next_update(&der),
        der: der.clone(),
    };
    CACHE.lock().insert(cache_key_of(host, leaf), entry);
    Some(der)
}

/// 文件 mtime → UNIX 秒（读不到返回 None）。
fn file_mtime_unix(path: &std::path::Path) -> Option<i64> {
    let md = std::fs::metadata(path).ok()?;
    let t = md.modified().ok()?;
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => Some(d.as_secs() as i64),
        Err(_) => None,
    }
}

/// 握手回调持有的装订槽：`der` 为当前可装订的 OCSPResponse。
/// 由 select-certificate 回调的闭包以 `Arc` 持有，随 acceptor 生命周期存在。
///
/// 写入方只有后台续期线程；读方是握手回调——单锁即可，无阻塞语义。
pub struct StapleSlot {
    der: Mutex<Option<Vec<u8>>>,
}

impl StapleSlot {
    /// 从磁盘缓存初始化（**不触网**）；无缓存则 der 为空，稍后由续期线程补。
    fn from_disk(host: &str, leaf: &X509) -> Arc<Self> {
        let der = load_disk_cache(host, leaf);
        Arc::new(StapleSlot {
            der: Mutex::new(der),
        })
    }

    /// 当前可装订的响应（无则 None）。握手路径只调这个——纯内存读，不触网。
    pub fn current(&self) -> Option<Vec<u8>> {
        self.der.lock().clone()
    }

    fn set(&self, der: Vec<u8>) {
        *self.der.lock() = Some(der);
    }
}

/// 缓存键：host + **证书指纹**（换证书即失效；长度不同不算换证书——见
/// [`leaf_fingerprint`] 里旧实现「按 DER 长度」导致的跨证书复用）。
fn cache_key_of(host: &str, leaf: &X509) -> String {
    let fp = leaf
        .to_der()
        .map(|d| leaf_fingerprint(&d))
        .unwrap_or_else(|_| "noder".to_string());
    format!("{host}:{fp}")
}

// ------------------------------------------------------------ 后台续期循环

/// 已注册的装订目标（冷路径注册，续期线程据此重拉）。
struct Target {
    host: String,
    leaf: X509,
    chain: Vec<u8>,
    slot: Arc<StapleSlot>,
}

static TARGETS: Lazy<Mutex<Vec<Target>>> = Lazy::new(|| Mutex::new(Vec::new()));
static RENEWAL_STARTED: AtomicBool = AtomicBool::new(false);
/// 续期线程轮询间隔。
const RENEWAL_TICK: Duration = Duration::from_secs(60);

/// 冷路径入口：为一个 host/leaf 准备装订槽并登记后台续期。
///
/// 返回 `None` 表示该证书「不具备自动获取条件」（叶子无 AIA OCSP URL，或链里
/// 找不到 issuer 且无 caIssuers 可下），调用方应保持无装订语义。
/// 返回 `Some(slot)` 时槽内可能已有磁盘缓存，也可能为空（由后台线程补上）。
pub fn prepare_stapling(host: &str, leaf: &X509, chain_pem: &[u8]) -> Option<Arc<StapleSlot>> {
    // 前置检查（纯本地解析，不触网）：没有 OCSP URL 就不必注册。
    let leaf_der = leaf.to_der().ok()?;
    let (ocsp_urls, cai_urls) = extract_aia(&leaf_der);
    if ocsp_urls.is_empty() {
        log::info!("ocsp: {host} leaf has no AIA OCSP responder; stapling disabled");
        return None;
    }
    if find_issuer_in_pem(chain_pem, leaf).is_none() && cai_urls.is_empty() {
        log::info!("ocsp: {host} no issuer in chain and no caIssuers URL; stapling disabled");
        return None;
    }
    let slot = StapleSlot::from_disk(host, leaf);
    // `register_target` **返回权威槽**：若同 host+leaf 已注册过，返回的是**已注册那个**，
    // 而不是我们刚建的新的。否则续期线程写旧槽、握手回调读新槽 ⇒ staple 冻结在
    // 「构建时的磁盘缓存值」，过期后一直发旧的（must-staple 客户端直接失败）。
    // 每次 `LiveConfig` 重载都会清空 acceptor 缓存 ⇒ 冷构建会反复发生，所以这条必须成立。
    let slot = register_target(host, leaf, chain_pem, &slot);
    Some(slot)
}

/// 注册一个续期目标（按 host+leaf 去重）并确保续期线程已启动。
/// 只应在 acceptor 冷构建路径调用。
fn register_target(
    host: &str,
    leaf: &X509,
    chain_pem: &[u8],
    slot: &Arc<StapleSlot>,
) -> Arc<StapleSlot> {
    let key = cache_key_of(host, leaf);
    {
        let mut t = TARGETS.lock();
        // 已注册 ⇒ 返回**已注册的那个槽**（调用方/握手回调必须与续期线程用同一个槽）。
        // 并发冷构建时同理：先注册者胜出，后者拿到同一个槽，不会出现「两个槽一读一写」。
        if let Some(existing) = t.iter().find(|x| cache_key_of(&x.host, &x.leaf) == key) {
            return Arc::clone(&existing.slot);
        }
        t.push(Target {
            host: host.to_string(),
            leaf: leaf.to_owned(),
            chain: chain_pem.to_vec(),
            slot: Arc::clone(slot),
        });
    }
    ensure_renewal_loop();
    Arc::clone(slot)
}

/// 启动后台续期线程（幂等）。线程先立刻扫一遍（补齐首次缺失），随后每
/// [`RENEWAL_TICK`] 扫描一次：对缓存缺失或已临近 nextUpdate 的目标同步重拉。
/// 全部发生在**握手路径之外**。
fn ensure_renewal_loop() {
    if RENEWAL_STARTED.swap(true, Ordering::AcqRel) {
        return;
    }
    let spawned = std::thread::Builder::new()
        .name("ocsp-renewal".into())
        .spawn(|| {
            loop {
                let targets: Vec<(String, X509, Vec<u8>, Arc<StapleSlot>)> = TARGETS
                    .lock()
                    .iter()
                    .map(|t| {
                        (
                            t.host.clone(),
                            t.leaf.to_owned(),
                            t.chain.clone(),
                            Arc::clone(&t.slot),
                        )
                    })
                    .collect();
                for (host, leaf, chain, slot) in targets {
                    let key = cache_key_of(&host, &leaf);
                    let needs = match CACHE.lock().get(&key) {
                        Some(c) => fresh_for(c).is_none(),
                        None => true,
                    };
                    if !needs {
                        continue;
                    }
                    // 续期线程内同步抓取（与握手完全解耦）。
                    if let Some(der) = obtain(&host, &leaf, &chain) {
                        slot.set(der);
                    }
                }
                std::thread::sleep(RENEWAL_TICK);
            }
        });
    if let Err(e) = spawned {
        RENEWAL_STARTED.store(false, Ordering::Release);
        log::warn!("ocsp: cannot spawn renewal thread: {e}");
    }
}

struct SimpleUrl {
    host: String,
    port: u16,
    path: String,
    https: bool,
}

fn parse_simple(url: &str) -> Option<SimpleUrl> {
    let https = url.starts_with("https://");
    let rest = url.strip_prefix("https://").or_else(|| url.strip_prefix("http://"))?;
    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().ok()?),
        None => (hostport.to_string(), if https { 443 } else { 80 }),
    };
    Some(SimpleUrl {
        host,
        port,
        path: path.to_string(),
        https,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 已过 nextUpdate 的响应必须被判为「硬过期」（据此拒绝装订），
    /// 而没有 nextUpdate 或未到期的不能误判（否则会永远不装订）。
    #[test]
    fn hard_expired_only_when_next_update_passed() {
        let now = 1_000_000i64;
        assert!(hard_expired(Some(now - 1), now), "已过 nextUpdate 必须判过期");
        assert!(hard_expired(Some(now), now), "恰好到点即过期");
        assert!(!hard_expired(Some(now + 1), now), "未到期不得误判");
        assert!(!hard_expired(None, now), "无 nextUpdate 不能凭此判过期");
    }

    /// GeneralizedTime：`Z` 形式与带小数秒的形式都要能用（旧实现遇到小数秒就
    /// 退回 23h 兜底 TTL，可能把已过 nextUpdate 的响应继续装订出去）。
    #[test]
    fn generalized_time_parses_z_and_fractional() {
        let base = parse_generalized_time("20240101120000Z").expect("plain Z");
        assert_eq!(base, parse_generalized_time("20240101120000.000Z").expect("fraction"));
        assert_eq!(base, parse_generalized_time("20240101120000,5Z").expect("comma fraction"));
        // 非法/非 UTC 形式一律 None（不能猜）。
        assert!(parse_generalized_time("20240101120000").is_none());
        assert!(parse_generalized_time("20240101120000+0100").is_none());
        assert!(parse_generalized_time("20240101120000.Z").is_none());
        assert!(parse_generalized_time("20241301120000Z").is_none()); // 月份 13
        assert!(parse_generalized_time("").is_none());
    }

    #[test]
    fn serial_compare_ignores_der_padding() {
        assert!(same_serial(&[0x00, 0x7f, 0x01], &[0x7f, 0x01]));
        assert!(same_serial(&[0x01], &[0x01]));
        assert!(!same_serial(&[0x00, 0x7f, 0x01], &[0x7f, 0x02]));
        assert!(!same_serial(&[], &[0x01]));
    }

    /// 截断的响应不能通过有效性检查（否则会被当作有效缓存装订出去）。
    #[test]
    fn truncated_response_is_rejected() {
        // 自洽的最小外壳：SEQUENCE { ENUMERATED 0 }（内容 5 字节，短长度形式）
        let ok = [0x30u8, 0x05, 0x0A, 0x01, 0x00, 0x00, 0x00];
        assert!(ocsp_response_ok(&ok));
        // 声明 0x50 字节内容、实际只有 3 字节：DER 短长度形式不做越界检查，
        // 旧实现只比 tag + responseStatus，会把这个判成「有效」（本次修复补上长度自洽）。
        let bogus = [0x30u8, 0x50, 0x0A, 0x01, 0x00];
        assert!(!ocsp_response_ok(&bogus));
        // 长长度形式声明的内容越界（截断文件）同样必须拒绝。
        let cut = [0x30u8, 0x82, 0x01, 0x00, 0x0A, 0x01, 0x00];
        assert!(!ocsp_response_ok(&cut));
        // 连 responseStatus 都不完整。
        let short = [0x30u8, 0x05, 0x0A, 0x01];
        assert!(!ocsp_response_ok(&short));
    }

    /// **编码回归（P1）**：OCSPRequest 必须是合法 DER——旧实现把「完整 SEQUENCE 头 +
    /// 内容」的错误常量又套了一层 `der_tlv(0x30, …)`，产出
    /// `30 … 30 0F <9 字节>`：内层声明 15 字节内容、其后只有 9 字节。
    /// `openssl asn1parse` 直接报 `ASN1_get_object:too long`，responder 只能回
    /// `malformedRequest(1)` ⇒ **自动 OCSP 抓取对任何真实 CA 从未成功**。
    ///
    /// 向量是照 `openssl ocsp -reqout`（对本机真实 GlobalSign 链）的输出逐字节抄下来的
    /// 结构：`SEQUENCE{ SEQUENCE{ SEQUENCE{ SEQUENCE{ AlgId, OCTET, OCTET, INTEGER } } } }`。
    /// 断言三件事：
    ///   1. 每个 TLV 的长度自洽（可被 `der_head` 完整走完，不会越界）；
    ///   2. AlgorithmIdentifier 是 `30 09 06 05 2B 0E 03 02 1A 05 00`（9 字节内容）；
    ///   3. 整串总长 = 5 个 header + 4 个 TLV 内容（用已知字段长度算出来的常数 71）。
    #[test]
    fn ocsp_request_der_matches_golden_vector() {
        let name_hash = [0x11u8; 20];
        let key_hash = [0x22u8; 20];
        let serial = [0x01u8, 0x02, 0x03, 0x04];
        let req = encode_ocsp_request(&name_hash, &key_hash, &serial);

        // ① AlgorithmIdentifier：必须是 30 09（不是旧的 30 0F），内容 OID+SHA1+NULL。
        //    偏移：5 层 SEQUENCE 头（各 2 字节）+ CertID 头 ⇒ AlgId 在 req[10..12]。
        assert_eq!(
            &req[10..12],
            &[0x30, 0x09],
            "AlgorithmIdentifier 头必须是 30 09（旧实现的 30 0F 声明了不存在的内容）"
        );
        assert_eq!(&req[12..14], &[0x06, 0x05]);
        assert_eq!(&req[14..19], &[0x2B, 0x0E, 0x03, 0x02, 0x1A]); // OID 1.3.14.3.2.26
        assert_eq!(&req[19..21], &[0x05, 0x00]); // NULL

        // ② 整串能被 DER 头**逐层**走完（长度自洽，无 `too long`）。
        //    RFC 6960 的嵌套是 5 层 SEQUENCE：OCSPRequest/TBSRequest/requestList/Request/CertID。
        let mut off = 0usize;
        for depth in 0..5 {
            let (t, l, h) = der_head(&req, off).expect("每一层都必须能解析出 TLV 头");
            assert_eq!(t, 0x30, "第 {depth} 层必须是 SEQUENCE");
            assert!(
                off + h + l <= req.len(),
                "第 {depth} 层声明的内容越界：off={off} len={l} total={}",
                req.len()
            );
            off += h;
        }
        // 走到最内层（CertID 内容起点）看到的必须正是 AlgId。
        assert_eq!(&req[off..off + 2], &[0x30, 0x09]);
        assert_eq!(off, 10, "五层 SEQUENCE 头之后应恰好是 CertID 内容");

        // ③ 已知长度：serial 4 字节 + 两个 20 字节 OCTET + AlgId 11 ⇒ 71 字节
        //    （与 `openssl ocsp -reqout` 对本机真实链的输出**逐字节一致**，实测比对过）。
        assert_eq!(req.len(), 71, "OCSPRequest 结构长度不对（字段被多套/少套了一层）");
    }

    /// `parse_simple` 必须把 **scheme** 带出来：`http://` 的 AIA URL 要用明文 HTTP 抓，
    /// 旧实现解析出 `https` 字段却**没有任何消费点**、一律先做 TLS 握手 ⇒ 对 80 端口
    /// 做 TLS 必然 `record layer failure`，GlobalSign/DigiCert 这类 `http://` responder
    /// 的自动装订从未成功过（本机实测：`openssl s_client -connect ocsp.globalsign.com:80`
    /// 与真实 responder 直连均失败）。
    #[test]
    fn parse_simple_preserves_scheme_and_port() {
        let u = parse_simple("http://ocsp.globalsign.com/gsgccr46ovtlsca2025").unwrap();
        assert!(!u.https, "http:// 必须解析为明文");
        assert_eq!(u.host, "ocsp.globalsign.com");
        assert_eq!(u.port, 80);
        assert_eq!(u.path, "/gsgccr46ovtlsca2025");

        let u = parse_simple("https://ocsp.example.com:8443/ocsp").unwrap();
        assert!(u.https);
        assert_eq!(u.port, 8443);
        assert_eq!(u.path, "/ocsp");

        // 无路径/无端口 的默认值。
        let u = parse_simple("https://x.example").unwrap();
        assert_eq!((u.port, u.path.as_str()), (443, "/"));
        assert!(parse_simple("ftp://x/y").is_none());
    }

    /// **联网**端到端（默认 `#[ignore]`，需要外网 + 真实 CA 证书链）：
    /// 用 `obtain()` 对真实 responder 走完整流程（AIA 解析 → issuer 查找 → 请求编码 →
    /// 明文/HTTPS 抓取 → 响应校验 → CertID 匹配）。
    ///
    /// 跑法（证书链来自任意公共站点，`openssl s_client -showcerts` 导出为 PEM）：
    /// ```text
    /// CRUCIBLE_OCSP_TEST_CHAIN=/path/fullchain.pem CRUCIBLE_OCSP_TEST_HOST=mirrors.aliyun.com \
    ///   cargo test --release --bin webserver ocsp_live -- --ignored --nocapture
    /// ```
    /// 修复前 `build_ocsp_request` 产出非法 DER（responder 回 `malformedRequest`），
    /// 本用例必然失败（`obtain` 返回 None）；修复后应拿到一份通过
    /// `ocsp_response_ok` + CertID 匹配的响应。
    #[test]
    #[ignore]
    fn ocsp_live_obtain_against_real_responder() {
        let chain_path = std::env::var("CRUCIBLE_OCSP_TEST_CHAIN")
            .expect("需要 CRUCIBLE_OCSP_TEST_CHAIN=<fullchain.pem>");
        let host = std::env::var("CRUCIBLE_OCSP_TEST_HOST").unwrap_or_else(|_| "test".into());
        let pem = std::fs::read(&chain_path).expect("read chain");
        let leaf = X509::from_pem(&pem).expect("leaf parse");
        let der = obtain(&host, &leaf, &pem).expect(
            "obtain() 返回 None —— 请求编码/抓取/校验任一步失败（修复前正是这条会失败）",
        );
        assert!(ocsp_response_ok(&der), "拿回的响应未通过基本校验");
        let serial = extract_serial(&leaf.to_der().unwrap()).unwrap();
        assert_ne!(
            response_covers_leaf(&der, &serial),
            Some(false),
            "响应 CertID 与站点证书不匹配"
        );
        eprintln!(
            "[ocsp-live] host={host} response={} bytes nextUpdate={:?}",
            der.len(),
            parse_next_update(&der)
        );
    }

    /// 同一 DER **长度**的两张证书必须得到不同指纹（旧实现按长度做缓存键，
    /// 于是续期证书会命中旧证书的 OCSPResponse）。
    #[test]
    fn fingerprint_distinguishes_equal_length_certs() {
        let a = vec![0x11u8; 1024];
        let mut b = vec![0x11u8; 1024];
        b[512] = 0x22;
        assert_eq!(a.len(), b.len());
        assert_ne!(leaf_fingerprint(&a), leaf_fingerprint(&b));
        assert_eq!(leaf_fingerprint(&a), leaf_fingerprint(&a.clone()));
        assert_eq!(leaf_fingerprint(&a).len(), 32);
    }

    /// 缓存文件名必须带证书指纹（同 host 的不同证书不能共用文件）。
    #[test]
    fn cache_file_name_carries_fingerprint() {
        let p1 = cache_file_for("example.com", "aaaa");
        let p2 = cache_file_for("example.com", "bbbb");
        assert_ne!(p1, p2);
        assert!(p1.to_string_lossy().ends_with("example.com-aaaa.der"));
        // host 里的路径分隔符被 sanitize 掉（文件名只剩一个组件，无法穿越目录）。
        let hostile = cache_file_for("../evil", "aa");
        let name = hostile.file_name().unwrap().to_string_lossy().to_string();
        assert!(!name.contains('/') && !name.contains('\\'), "name={name}");
        assert_eq!(hostile.parent(), p1.parent());
    }
}
