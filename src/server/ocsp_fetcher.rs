//! 早期规格 1b：OCSP 智能获取——免手动指定 ocsp_der_path。
//!
//! 流程：① 从 `ssl.cert` 全链材料找 issuer（subject == leaf.issuer）；
//! ② 链内缺失时从叶子 AIA caIssuers URL 下载 issuer（DER X509 / PKCS7 内嵌证书
//!    双解析）；③ 手工 DER 编码 RFC 6960 OCSPRequest（CertID = SHA1(issuer name
//!    DER) + SHA1(issuer SPKI BIT STRING 内容) + leaf 序列号；BoringSSL 已剥离
//!    请求构建 API）；④ boring TLS POST → 完整 OCSPResponse 即装订物；
//! ⑤ 缓存 state/ocsp/{host}.der + 进程内存 23h（到期前 1h 重拉）；网络失败回退
//!    旧缓存。全部阻塞 IO——仅在 acceptor 冷构建路径调用（每配置版本一次）。

use anyhow::{Context, Result};
use boring::hash::{hash, MessageDigest};
use boring::x509::X509;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

const REFRESH_AFTER: Duration = Duration::from_secs(23 * 3600);
const SHA1_ALGID: &[u8] = &[
    0x30, 0x0F, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00,
]; // SHA-1 + NULL

static CACHE: Lazy<Mutex<HashMap<String, (Vec<u8>, Instant)>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

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

/// 智能获取入口（同步，冷路径一次性）：缓存 → 链内 issuer → caIssuers 下载 →
/// OCSP POST → 校验 → 缓存落盘。任何失败返回 None（调用方保持无装订语义）。
pub fn obtain(host: &str, leaf: &X509, chain_pem: &[u8]) -> Option<Vec<u8>> {
    let leaf_der = leaf.to_der().ok()?;
    let cache_key = format!("{host}:{}", leaf_der.len());
    if let Some((der, at)) = CACHE.lock().get(&cache_key) {
        if at.elapsed() < REFRESH_AFTER {
            return Some(der.clone());
        }
    }
    let (ocsp_urls, cai_urls) = extract_aia(&leaf_der);
    let ocsp_url = ocsp_urls.first()?.clone();
    let issuer = match find_issuer_in_pem(chain_pem, leaf) {
        Some(c) => Some(c),
        None => {
            // caIssuers 下载（阻塞，冷路径一次）
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
    let dir = std::path::Path::new("state/ocsp");
    let _ = std::fs::create_dir_all(dir);
    let _ = std::fs::write(dir.join(format!("{}.der", sanitize(host))), &resp);
    CACHE.lock().insert(cache_key, (resp.clone(), Instant::now()));
    Some(resp)
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
