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
const SHA1_ALGID: &[u8] = &[
    0x30, 0x0F, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00,
]; // SHA-1 + NULL

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

/// 缓存文件路径。
fn cache_file(host: &str) -> std::path::PathBuf {
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
                let s = std::str::from_utf8(&basic[r + nh + gh..r + nh + gh + glen]).ok()?;
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
    q += oh;
    Some(&resp[q..q + olen])
}

/// GeneralizedTime `YYYYMMDDHHMMSSZ` → UNIX 秒（只接受 Z 结尾的 UTC 形式）。
fn parse_generalized_time(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() < 15 || b[14] != b'Z' {
        return None;
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
    let (_, _, ha) = der_head(spki, 0)?;
    let mut q = ha;
    let (bt, blen, bh) = der_head(spki, q)?;
    if bt != 0x03 {
        return None;
    }
    let start = q + bh + 1; // 首字节 = 未用位数
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
            let l = seg[q + 1] as usize;
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

/// 手工 DER 编码 OCSPRequest（CertID = SHA1；RFC 6960）。
pub fn build_ocsp_request(
    leaf: &X509,
    issuer_name_der: &[u8],
    issuer_spki_bits: &[u8],
) -> Result<Vec<u8>> {
    let name_hash = hash(MessageDigest::sha1(), issuer_name_der)?;
    let key_hash = hash(MessageDigest::sha1(), issuer_spki_bits)?;
    let serial = extract_serial(&leaf.to_der()?).context("leaf serial parse")?;

    let mut certid = der_tlv(0x30, SHA1_ALGID);
    certid.extend(der_tlv(0x04, &name_hash));
    certid.extend(der_tlv(0x04, &key_hash));
    certid.extend(der_tlv(0x02, &serial));
    let request = der_tlv(0x30, &certid);
    let request_list = der_tlv(0x30, &request);
    let tbs = der_tlv(0x30, &request_list);
    Ok(der_tlv(0x30, &tbs))
}

// ------------------------------------------------------------ 阻塞 HTTPS（boring）

/// 阻塞 HTTPS GET/POST（boring SslStream over std TcpStream；冷路径专用）。
fn https_req(
    host: &str,
    port: u16,
    method: &str,
    path: &str,
    ctype: Option<&str>,
    body: Option<&[u8]>,
) -> Result<Vec<u8>> {
    use std::io::{Read, Write};
    let tcp = std::net::TcpStream::connect((host, port))
        .with_context(|| format!("ocsp connect {host}:{port}"))?;
    let mut b = boring::ssl::SslConnector::builder(boring::ssl::SslMethod::tls())?;
    b.set_alpn_protos(b"\x08http/1.1")?;
    let ssl = b.build().configure()?.into_ssl(host)?;
    let mut tls = boring::ssl::SslStream::new(ssl, tcp)?;
    let path = if path.is_empty() { "/" } else { path };
    let cl = body.map(|b| b.len()).unwrap_or(0);
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nAccept: application/ocsp-response\r\nConnection: close\r\nContent-Length: {cl}\r\n{}",
        if ctype.is_some() {
            format!("Content-Type: {}\r\n", ctype.unwrap())
        } else {
            String::new()
        }
    );
    tls.write_all(req.as_bytes())?;
    if let Some(b) = body {
        tls.write_all(b)?;
    }
    tls.flush()?;
    let mut buf = Vec::new();
    tls.read_to_end(&mut buf)?;
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

/// OCSPResponse 外层 status 必须为 0（successful）。
fn ocsp_response_ok(der: &[u8]) -> bool {
    let (_, _, h) = match der_head(der, 0) {
        Some(x) => x,
        None => return false,
    };
    if der.get(h) != Some(&0x0A) {
        return false;
    }
    let (_, l, hh) = match der_head(der, h) {
        Some(x) => x,
        None => return false,
    };
    l == 1 && der.get(h + hh) == Some(&0)
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
    let cache_key = format!("{host}:{}", leaf_der.len());
    let (ocsp_urls, cai_urls) = extract_aia(&leaf_der);
    let ocsp_url = ocsp_urls.first()?.clone();
    let issuer = match find_issuer_in_pem(chain_pem, leaf) {
        Some(c) => Some(c),
        None => {
            // caIssuers 下载（阻塞）
            let url = cai_urls.first()?;
            let u = parse_simple(url)?;
            let body = https_req(&u.host, u.port, "GET", &u.path, None, None).ok()?;
            parse_issuer_from_body(&body, leaf)
        }
    }?;
    let issuer_der = issuer.to_der().ok()?;
    let name_der = issuer.subject_name().to_der().ok()?;
    let spki = extract_spki_bits(&issuer_der)?;
    let req = build_ocsp_request(leaf, &name_der, &spki).ok()?;
    let u = parse_simple(&ocsp_url)?;
    let resp = https_req(&u.host, u.port, "POST", &u.path,
                         Some("application/ocsp-request"), Some(&req))
        .ok()?;
    if !ocsp_response_ok(&resp) {
        return None;
    }
    let dir = cache_dir();
    let _ = std::fs::create_dir_all(&dir);
    let _ = std::fs::write(cache_file(host), &resp);
    let entry = Cached {
        fetched_unix: now_unix(),
        next_update_unix: parse_next_update(&resp),
        der: resp.clone(),
    };
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

/// 冷路径启动时把磁盘缓存读回内存（不触网）。
fn load_disk_cache(host: &str, cache_key: &str) -> Option<Vec<u8>> {
    let path = cache_file(host);
    let der = std::fs::read(&path).ok()?;
    if der.is_empty() || !ocsp_response_ok(&der) {
        return None;
    }
    let entry = Cached {
        fetched_unix: file_mtime_unix(&path).unwrap_or_else(now_unix),
        next_update_unix: parse_next_update(&der),
        der: der.clone(),
    };
    CACHE.lock().insert(cache_key.to_string(), entry);
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
        let key = cache_key_of(host, leaf);
        let der = load_disk_cache(host, &key);
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

/// 缓存键：host + leaf DER 长度（换证书即失效）。
fn cache_key_of(host: &str, leaf: &X509) -> String {
    format!("{host}:{}", leaf.to_der().map(|d| d.len()).unwrap_or(0))
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
    register_target(host, leaf, chain_pem, &slot);
    Some(slot)
}

/// 注册一个续期目标（按 host+leaf 去重）并确保续期线程已启动。
/// 只应在 acceptor 冷构建路径调用。
fn register_target(host: &str, leaf: &X509, chain_pem: &[u8], slot: &Arc<StapleSlot>) {
    let key = cache_key_of(host, leaf);
    {
        let mut t = TARGETS.lock();
        let dup = t.iter().any(|x| cache_key_of(&x.host, &x.leaf) == key);
        if !dup {
            t.push(Target {
                host: host.to_string(),
                leaf: leaf.to_owned(),
                chain: chain_pem.to_vec(),
                slot: Arc::clone(slot),
            });
        }
    }
    ensure_renewal_loop();
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
