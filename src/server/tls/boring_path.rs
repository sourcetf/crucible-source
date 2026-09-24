//! Primary TLS path — BoringSSL (TCP + QUIC foundation).
//!
//! Handles modern TLS 1.2/1.3, ECH, post-quantum hybrid groups (X25519MLKEM768),
//! session tickets, and optional TLS-PSK hooks for H3.

use crate::config::{ListenerConfig, SslConfig};
use crate::server::live_config::LiveConfig;
use crate::server::prefixed_stream::PrefixedStream;
use crate::server::ssl_material;
use crate::server::{h1, h2};
use anyhow::{Context, Result};
use boring::pkey::PKey;
use boring::ssl::{SslAcceptor, SslAcceptorBuilder, SslMethod, SslVersion};
use boring::x509::X509;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_boring::SslStream;

pub fn active_stack() -> &'static str {
    if cfg!(feature = "tls_boring") {
        "boringssl"
    } else if cfg!(feature = "tls_rustls") {
        "rustls-fallback"
    } else {
        "none"
    }
}

pub fn legacy_modules() -> &'static str {
    use std::sync::OnceLock;
    static CACHED: OnceLock<String> = OnceLock::new();
    let s = CACHED.get_or_init(|| {
        let mut mods = Vec::new();
        if cfg!(all(feature = "tls_nss", tls_nss_enabled)) {
            mods.push("nss");
        }
        if cfg!(all(feature = "tls_tomcrypt", tls_tomcrypt_enabled)) {
            mods.push("tomcrypt");
        }
        if mods.is_empty() {
            "none".to_string()
        } else {
            mods.join(",")
        }
    });
    s.as_str()
}

pub fn build_acceptor(ssl: &SslConfig, lc: &ListenerConfig) -> Result<SslAcceptor> {
    let mut builder = SslAcceptor::mozilla_modern(SslMethod::tls())?;
    // boring 的 mozilla_modern 预设带 SSL_OP_NO_TLSV1_3,不清掉 TLS1.3 永远握手失败(
    // set_min/max_proto_version 不会复位该 option 位)。§6 主路径要求 1.2/1.3 全开。
    builder.clear_options(boring::ssl::SslOptions::NO_TLSV1_3);
    apply_versions(&mut builder, ssl)?;
    load_identity(&mut builder, ssl)?;
    // 早期规格 3：0-RTT 默认关闭；early_data=true 才显式开启（boring 无安全封装，
    // 直调 BoringSSL C API SSL_CTX_set_early_data_enabled）。
    if ssl.early_data {
        unsafe {
            boring_sys::SSL_CTX_set_early_data_enabled(builder.as_ptr(), 1);
        }
        log::info!("tls: early data (0-RTT) enabled");
    }
    apply_ciphers(&mut builder, ssl)?;
    apply_groups(&mut builder, ssl)?;
    apply_ech(&mut builder, ssl)?;
    apply_ocsp(&mut builder, ssl)?;
    apply_psk(&mut builder, ssl)?;
    apply_alpn(&mut builder, lc)?;
    Ok(builder.build())
}

fn apply_versions(builder: &mut SslAcceptorBuilder, ssl: &SslConfig) -> Result<()> {
    if ssl.versions.is_empty() {
        if ssl.prefer_tls13 {
            builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
            builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;
        }
        return Ok(());
    }
    // BoringSSL path: TLS 1.2/1.3 only. TLS 1.0/1.1/SSLv3 route to NSS via ClientHello peek.
    let mut min = SslVersion::TLS1_3;
    let mut max = SslVersion::TLS1_2;
    for v in &ssl.versions {
        let ver = parse_version(v)?;
        if version_rank(ver) < version_rank(min) {
            min = ver;
        }
        if version_rank(ver) > version_rank(max) {
            max = ver;
        }
    }
    builder.set_min_proto_version(Some(min))?;
    builder.set_max_proto_version(Some(max))?;
    Ok(())
}

fn version_rank(v: SslVersion) -> u8 {
    match v {
        SslVersion::TLS1_2 => 2,
        SslVersion::TLS1_3 => 3,
        _ => 2,
    }
}

fn parse_version(s: &str) -> Result<SslVersion> {
    match s.to_ascii_uppercase().replace(['.', '_'], "").as_str() {
        "TLSV13" | "TLS13" => Ok(SslVersion::TLS1_3),
        "TLSV12" | "TLS12" => Ok(SslVersion::TLS1_2),
        "TLSV11" | "TLS11" | "TLSV10" | "TLS10" | "TLSV1" | "TLS1" | "SSLV3" | "SSL3" => {
            anyhow::bail!(
                "{s}: legacy TLS versions are handled by NSS/TomCrypt, not BoringSSL"
            )
        }
        other => anyhow::bail!("unsupported TLS version: {other}"),
    }
}

fn load_identity(builder: &mut SslAcceptorBuilder, ssl: &SslConfig) -> Result<()> {
    let cert_pem = ssl_material::load_bytes(ssl.cert.as_deref().context("ssl.cert")?)?;
    let key_pem = ssl_material::load_bytes(ssl.key.as_deref().context("ssl.key")?)?;
    let cert = X509::from_pem(&cert_pem)?;
    let key = PKey::private_key_from_pem(&key_pem)?;
    builder.set_certificate(&cert)?;
    builder.set_private_key(&key)?;
    builder.check_private_key()?;

    // RSA + ECDSA dual certificate (BoringSSL selects by client sigalgs).
    // Calling set_certificate/set_private_key again for a different key type
    // registers an alternate chain — do NOT use add_extra_chain_cert (that is
    // intermediate-only and breaks EC leaf selection).
    if let (Some(ec_cert), Some(ec_key)) = (&ssl.cert_ec, &ssl.key_ec) {
        let ec_cert_pem = ssl_material::load_bytes(ec_cert)?;
        let ec_key_pem = ssl_material::load_bytes(ec_key)?;
        let ec_x509 = X509::from_pem(&ec_cert_pem)?;
        let ec_pkey = PKey::private_key_from_pem(&ec_key_pem)?;
        builder.set_certificate(&ec_x509)?;
        builder.set_private_key(&ec_pkey)?;
        builder.check_private_key()?;
    }
    Ok(())
}

/// BoringSSL 内置的 TLS1.3 套件名（`ssl_cipher.cc` 的 kCiphers 里 algorithm_mkey ==
/// SSL_kGENERIC 的三条；除此之外没有任何 TLS1.3 套件）。
const TLS13_SUITES: &[&str] = &[
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
];

/// psk=true 时追加的 PSK/ECDHE-PSK 套件族（早期规格 13）。
///
/// 名字必须是 BoringSSL **确实有**的那些：它没有 PSK-AES128-**GCM**-SHA256 之类的
/// GCM 型 PSK 套件（那些是 OpenSSL 的名字），此前这里的 6 个名字里 5 个不存在 ——
/// 非严格解析会静默忽略未知名字，于是「管理员显式配了套件列表」时 psk 实际一个都没加上。
/// 待办的「全量套件目录」会把 PSK 也从目录里筛出来（见 WORKLOG §17），届时这段可去掉。
const PSK_SUITE_TAIL: &str = ":PSK-AES128-CBC-SHA:PSK-AES256-CBC-SHA:ECDHE-PSK-AES128-CBC-SHA:ECDHE-PSK-AES256-CBC-SHA:ECDHE-PSK-CHACHA20-POLY1305";

fn apply_ciphers(builder: &mut SslAcceptorBuilder, ssl: &SslConfig) -> Result<()> {
    let (mut list, dropped) = if ssl.ciphers.is_empty() {
        ("ALL:!eNULL:!SSLv3".to_string(), Vec::new())
    } else {
        split_tls13_suites(&ssl.ciphers.join(":"))
    };
    // TLS1.3 套件名**不能**经 SSL_CTX_set_cipher_list 生效：BoringSSL 的可配置套件表
    // （ssl_cipher.cc 的 co_list）只含 TLS≤1.2 套件，TLS1.3 名字匹配不到条目 → 被
    // 静默忽略；若列表里**只有** TLS1.3 名字，结果为空 → SSL_R_NO_CIPHER_MATCH →
    // set_cipher_list 报错 → build_acceptor 失败 → 这个监听口的**每个**连接都软失败
    //（客户端只看到连接被关闭）。boring 明确写着 BoringSSL 没有 set_ciphersuites，
    // 所以 TLS1.3 套件集合在库内固定：要限制 TLS1.3 只能用 ssl.versions。
    // 这里如实告警 + 剔除；剔除后没有 1.2 套件可配时回落默认列表，不把监听口配死。
    if !dropped.is_empty() {
        log::error!(
            "ssl.ciphers 中的 TLS1.3 套件 {:?} 无法配置（BoringSSL 未实现 set_ciphersuites，\
             TLS1.3 固定为 AES-128-GCM/AES-256-GCM/CHACHA20-POLY1305）；限制 TLS1.3 请用 \
             ssl.versions。已从 TLS≤1.2 套件列表中剔除",
            dropped
        );
    }
    if list.trim_matches(':').is_empty() {
        log::error!("ssl.ciphers 剔除 TLS1.3 套件后无剩余套件，回落默认列表 ALL:!eNULL:!SSLv3");
        list = "ALL:!eNULL:!SSLv3".to_string();
    }
    if ssl.psk {
        list.push_str(PSK_SUITE_TAIL);
    }
    builder.set_cipher_list(&list)?;
    Ok(())
}

/// 把配置里的套件串拆开，返回 (TLS≤1.2 套件串, 被剔除的 TLS1.3 套件名)。
///
/// 分隔符按 BoringSSL 非严格模式接受的形式（`:`/`,`/空白/`;`）切开再统一用 `:` 拼回；
/// 条目上的 `!`/`-`/`+`/`@` 修饰符不参与名字匹配（剔除整条：对固定套件做排除同样无效）。
fn split_tls13_suites(spec: &str) -> (String, Vec<String>) {
    let mut kept: Vec<&str> = Vec::new();
    let mut dropped: Vec<String> = Vec::new();
    for item in spec.split([':', ',', ';', ' ', '\t', '\n']).filter(|s| !s.is_empty()) {
        let name = item.trim_start_matches(['!', '-', '+', '@']);
        if TLS13_SUITES.iter().any(|s| s.eq_ignore_ascii_case(name)) {
            dropped.push(item.to_string());
        } else {
            kept.push(item);
        }
    }
    (kept.join(":"), dropped)
}

#[cfg(test)]
mod ciphers_tests {
    use super::split_tls13_suites;

    /// TLS1.3 套件名不能进 set_cipher_list（BoringSSL 会忽略；只剩它们时整条列表报错
    /// → 监听口每个连接都失败）。
    #[test]
    fn tls13_suite_names_are_stripped() {
        let (kept, dropped) =
            split_tls13_suites("TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256");
        assert_eq!(kept, "ECDHE-RSA-AES128-GCM-SHA256");
        assert_eq!(dropped, vec!["TLS_AES_128_GCM_SHA256".to_string()]);

        // 只有 TLS1.3 名字 → 剔除后为空（调用方回落默认列表，而不是把口配死）。
        let (kept, dropped) =
            split_tls13_suites("TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256");
        assert!(kept.is_empty());
        assert_eq!(dropped.len(), 2);

        // 修饰符 + 大小写。
        let (kept, dropped) = split_tls13_suites("!tls_aes_128_gcm_sha256");
        assert!(kept.is_empty());
        assert_eq!(dropped.len(), 1);

        // 前缀相近的 TLS1.2 名字不受影响。
        let (kept, dropped) = split_tls13_suites("TLS_RSA_WITH_AES_128_GCM_SHA256");
        assert_eq!(kept, "TLS_RSA_WITH_AES_128_GCM_SHA256");
        assert!(dropped.is_empty());
    }
}

/// Post-quantum hybrid + explicit group list (BoringSSL `SSL_CTX_set1_groups_list`).
fn apply_groups(builder: &mut SslAcceptorBuilder, ssl: &SslConfig) -> Result<()> {
    let list = if !ssl.groups.is_empty() {
        ssl.groups.join(":")
    } else if ssl.pqc {
        "X25519MLKEM768:X25519:P-256:P-384".to_string()
    } else {
        return Ok(());
    };
    builder.set_curves_list(&list)?;
    Ok(())
}

/// 应用 ECH 密钥。
///
/// 三条路径，优先级从高到低：
///   1. `ssl.ech_keys` 显式配置 → 用管理员材料（原行为不变）；
///   2. 未配置 → **自动配置**（规格 §16 1.a）：先复用 `state/ech/ech_keys.pem`
///      里已生成且仍匹配当前 public-name/suite/max-name-length 的配置，
///      不匹配则用真实 X25519 keypair 重新生成并落盘；
///   3. 自动配置失败（如未填 `ech_public_name`）→ 仅 warn，不阻断 TLS。
///
/// 早期实现只走路径 1：`ech_keys` 没配就直接放弃，于是「ECH 自动配置」实际不存在。
fn apply_ech(builder: &mut SslAcceptorBuilder, ssl: &SslConfig) -> Result<()> {
    if !ssl.ech && !ssl.ech_advertise {
        return Ok(());
    }
    if let Some(keys_path) = ssl.ech_keys.as_deref() {
        match ssl_material::load_bytes(keys_path) {
            Ok(pem) => {
                if let Err(e) = apply_ech_keys(builder, &pem) {
                    log::warn!("ECH keys invalid ({keys_path}): {e:#}; continuing without ECH");
                }
            }
            Err(e) => {
                log::warn!("ECH keys unavailable ({keys_path}): {e:#}; continuing without ECH");
            }
        }
        return Ok(());
    }

    // 自动配置路径（规格 §16 1.a）
    match crate::server::ech_auto::ensure_from_config(
        ssl.ech_public_name.as_deref(),
        ssl.ech_cipher_suite.as_deref(),
        ssl.ech_max_name_length,
    ) {
        Ok(mat) => {
            let pem = mat.to_pem();
            match apply_ech_keys(builder, pem.as_bytes()) {
                Ok(()) => log::info!(
                    "ECH 自动配置就绪 (reused={} public_name={} config_list_b64_len={})",
                    mat.reused,
                    ssl.ech_public_name.as_deref().unwrap_or("?"),
                    mat.config_list_base64().len()
                ),
                Err(e) => log::warn!("ECH 自动配置装载失败: {e:#}; continuing without ECH"),
            }
        }
        Err(e) => {
            log::warn!(
                "ECH 自动配置不可用（配置 ssl.ech_public_name 后可用）: {e:#}; continuing without ECH"
            );
        }
    }
    Ok(())
}

fn apply_ech_keys(builder: &mut SslAcceptorBuilder, pem: &[u8]) -> Result<()> {
    let keys = crate::server::tls::ech_pem::load_ech_keys(pem).context("ECH keys PEM")?;
    builder.set_ech_keys(&keys).context("set_ech_keys")?;
    Ok(())
}

/// P1-8（§16.16/§22.7）+ 早期规格 1b：server 端 OCSP stapling。
///
/// 两种来源，**静态路径优先**：
/// 1. `ssl.ocsp_der_path` 已配置 → 原行为不变（读文件 → 剥 PEM → 回调装订）。
/// 2. 未配置 → 自动获取：从 `ssl.cert` 全链 + 叶子 AIA 解析出 OCSP 目标，
///    经 `ocsp_fetcher::prepare_stapling` 建槽（只读本地 `state/ocsp` 缓存，**不触网**），
///    真正的网络抓取由 `ocsp_fetcher` 的后台续期线程完成，取回后回调自动装订。
///
/// 两条路径都失败时仅 warn，绝不阻断 TLS。
fn apply_ocsp(builder: &mut SslAcceptorBuilder, ssl: &SslConfig) -> Result<()> {
    if let Some(path) = ssl.ocsp_der_path.as_deref() {
        return apply_ocsp_static(builder, path);
    }
    apply_ocsp_auto(builder, ssl)
}

/// 静态路径（`ssl.ocsp_der_path`）——历史行为，逐字节保持不变。
fn apply_ocsp_static(builder: &mut SslAcceptorBuilder, path: &str) -> Result<()> {
    let raw = match ssl_material::load_bytes(path) {
        Ok(d) if !d.is_empty() => d,
        Ok(_) => {
            log::warn!("ssl.ocsp_der_path={path} 为空；OCSP stapling 关闭");
            return Ok(());
        }
        Err(e) => {
            log::warn!("ssl.ocsp_der_path={path} 不可读: {e:#}；OCSP stapling 关闭");
            return Ok(());
        }
    };
    let der = pem_to_der(&raw).unwrap_or(raw);
    let der_len = der.len();
    builder.enable_ocsp_stapling();
    builder.set_select_certificate_callback(move |mut ch| {
        let _ = ch.ssl_mut().set_ocsp_status(&der);
        Ok(())
    });
    log::info!("ocsp stapling enabled ({} bytes from {path})", der_len);
    Ok(())
}

/// 自动获取路径（早期规格 1b）：`ocsp_der_path` 未配置时启用。
/// 叶子无 AIA / 链不完整 → 静默保持无装订（与静态路径缺文件同语义）。
fn apply_ocsp_auto(builder: &mut SslAcceptorBuilder, ssl: &SslConfig) -> Result<()> {
    let (Some(cert_path), Some(host)) = (ssl.cert.as_deref(), ssl.ocsp_host()) else {
        return Ok(());
    };
    let cert_pem = match ssl_material::load_bytes(cert_path) {
        Ok(b) => b,
        Err(e) => {
            log::warn!("ocsp auto: ssl.cert 不可读: {e:#}；OCSP stapling 关闭");
            return Ok(());
        }
    };
    let leaf = match X509::from_pem(&cert_pem) {
        Ok(x) => x,
        Err(e) => {
            log::warn!("ocsp auto: leaf 解析失败: {e:#}；OCSP stapling 关闭");
            return Ok(());
        }
    };
    // 全链材料（叶 + 中间链）——issuer 查找与 caIssuers 兜底都用它。
    let Some(slot) = crate::server::ocsp_fetcher::prepare_stapling(&host, &leaf, &cert_pem) else {
        return Ok(());
    };
    builder.enable_ocsp_stapling();
    // 回调内只读槽内快照（纯内存）；网络刷新在后台线程，握手永不阻塞。
    builder.set_select_certificate_callback(move |mut ch| {
        if let Some(der) = slot.current() {
            let _ = ch.ssl_mut().set_ocsp_status(&der);
        }
        Ok(())
    });
    log::info!("ocsp stapling enabled (auto-fetch, host={host})");
    Ok(())
}

/// 极简 PEM→DER：剥 BEGIN/END 之间的 base64；非 PEM 原样返回（None）。
fn pem_to_der(raw: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(raw).ok()?;
    if !text.contains("-----BEGIN") {
        return None;
    }
    let start = text.find("-----BEGIN")?;
    let nl = text[start..].find('\n')? + start + 1;
    let end = text[nl..].find("-----END")? + nl;
    let body: String = text[nl..end].chars().filter(|c| !c.is_whitespace()).collect();
    b64_decode(&body)
}

fn b64_decode(input: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            b'=' => Some(0),
            _ => None,
        }
    }
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut i = 0;
    while i + 4 <= bytes.len() {
        let a = val(bytes[i])?;
        let b = val(bytes[i + 1])?;
        let c = val(bytes[i + 2])?;
        let d = val(bytes[i + 3])?;
        out.push((a << 2) | (b >> 4));
        if bytes[i + 2] != b'=' {
            out.push((b << 4) | (c >> 2));
        }
        if bytes[i + 3] != b'=' {
            out.push((c << 6) | d);
        }
        i += 4;
    }
    Some(out)
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    let nib = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    if b.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(b.len() / 2);
    let mut i = 0;
    while i + 1 < b.len() {
        out.push((nib(b[i])? << 4) | nib(b[i + 1])?);
        i += 2;
    }
    Some(out)
}

/// TLS-PSK server hook（§16.16）。
/// P1-10：材料来源优先级 ssl.psk_key（配置：hex / base64 / 文件路径）> env
/// CRUCIBLE_TLS_PSK（保留兼容）；配置 psk_identity 后严格匹配 identity。
/// H3/QUIC 侧 PSK 涉及 quinn-boring 内部，另行移交（见 REVIEW-MASTER 移交清单）。
fn apply_psk(builder: &mut SslAcceptorBuilder, ssl: &SslConfig) -> Result<()> {
    if !ssl.psk {
        return Ok(());
    }
    // 拒绝确定性占位 PSK（audit High）——材料必须真实配置。
    let secret: Vec<u8> = if let Some(k) = ssl.psk_key.as_deref() {
        psk_material(k)?
    } else {
        match std::env::var("CRUCIBLE_TLS_PSK") {
            Ok(s) if !s.is_empty() => s.into_bytes(),
            _ => {
                log::warn!("ssl.psk=true 但未配置 ssl.psk_key / CRUCIBLE_TLS_PSK；不装 PSK 回调");
                return Ok(());
            }
        }
    };
    let identity = ssl.psk_identity.clone();
    builder.set_psk_server_callback(move |_ssl, ident, psk| {
        // 配置了 identity 时严格匹配：任意 identity 都能换出同一 PSK 是弱语义。
        if let Some(want) = &identity {
            match ident {
                Some(got) if got.eq_ignore_ascii_case(want.as_bytes()) => {}
                _ => return Ok(0),
            }
        }
        if psk.is_empty() {
            return Ok(0);
        }
        let n = secret.len().min(psk.len());
        psk[..n].copy_from_slice(&secret[..n]);
        Ok(n)
    });
    Ok(())
}

/// P1-10：PSK 材料解析——含路径特征（/ 或 .）先按文件处理；否则偶长 hex >
/// base64 > 文件路径兜底。
fn psk_material(spec: &str) -> Result<Vec<u8>> {
    let s = spec.trim();
    if s.contains('/') || s.contains('.') {
        if let Ok(v) = ssl_material::load_bytes(s) {
            return Ok(v);
        }
    }
    if s.len() >= 2 && s.len() % 2 == 0 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        if let Some(v) = hex_decode(s) {
            return Ok(v);
        }
    }
    if let Some(v) = b64_decode(s) {
        if !v.is_empty() {
            return Ok(v);
        }
    }
    ssl_material::load_bytes(s).map_err(|e| anyhow::anyhow!("ssl.psk_key: {e:#}"))
}

fn apply_alpn(builder: &mut SslAcceptorBuilder, lc: &ListenerConfig) -> Result<()> {
    // 任务 2 实测发现（P1）：set_alpn_protos 是【客户端】API——服务端用它永远不会
    // 回应 ALPN，浏览器在 TLS 上全部回落 HTTP/1.1（h2 形同虚设）。服务端必须装
    // select 回调，并从客户端列表内回显所选协议（RFC 7301 要求回显原字节）。
    let offer_h2 = lc.allows_h2();
    let offer_h1 = lc.allows_h1();
    builder.set_alpn_select_callback(move |_ssl, client_protos: &[u8]| {
        // wire 格式：u8 len + name，逐段扫描；记录 h2 / http/1.1 的命中区间。
        let mut h2_span: Option<&[u8]> = None;
        let mut h1_span: Option<&[u8]> = None;
        let mut i = 0usize;
        while i < client_protos.len() {
            let l = client_protos[i] as usize;
            let end = match i.checked_add(1 + l) {
                Some(e) if e <= client_protos.len() => e,
                _ => break,
            };
            let name = &client_protos[i + 1..end];
            match name {
                b"h2" if offer_h2 => h2_span = Some(name),
                b"http/1.1" if offer_h1 => h1_span = Some(name),
                _ => {}
            }
            i = end;
        }
        // 服务端固定偏好 h2（有则选 h2，否则 http/1.1；都没提供 → NOACK 不带 ALPN）。
        h2_span.or(h1_span).ok_or(boring::ssl::AlpnError::NOACK)
    });
    Ok(())
}

// P2-4：按（listener + SslConfig 全字段指纹）缓存 SslAcceptor——旧实现每连接重新
// load PEM/解析双证/装 ECH keys，session ticket 复用全部失效。缓存上限 64，超限清空。
// 注意：PSK 若经环境变量注入，env 变化不会反映到指纹（配置 ssl.psk_key 即可热生效）。
static ACCEPTOR_CACHE: Lazy<Mutex<HashMap<u64, Arc<SslAcceptor>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
const ACCEPTOR_CACHE_CAP: usize = 64;

/// 清空 acceptor 缓存。
///
/// 指纹只覆盖配置字符串，缓存又永不失效，因此「同一路径上换证书」这类
/// 内容变化（certbot 续期、面板覆盖 ssl.cert / ssl.ech_keys）不会命中新指纹，
/// 进程会继续用旧证书直到重启。热路径（accept_and_serve 每连接查一次）不适合
/// 加 stat，所以在配置重载这个低频点显式清空——由 `LiveConfig::reload` 调用。
pub fn clear_acceptor_cache() {
    let mut map = ACCEPTOR_CACHE.lock();
    let n = map.len();
    map.clear();
    if n > 0 {
        log::info!("tls: acceptor cache cleared ({n} entries) — certificates/config re-read on next handshake");
    }
}

fn acceptor_fingerprint(ssl: &SslConfig, lc: &ListenerConfig) -> u64 {
    let mut h = DefaultHasher::new();
    ssl.cert.hash(&mut h);
    ssl.key.hash(&mut h);
    ssl.cert_ec.hash(&mut h);
    ssl.key_ec.hash(&mut h);
    ssl.versions.hash(&mut h);
    ssl.ciphers.hash(&mut h);
    ssl.prefer_tls13.hash(&mut h);
    ssl.ech.hash(&mut h);
    ssl.ech_keys.hash(&mut h);
    ssl.psk.hash(&mut h);
    ssl.psk_identity.hash(&mut h);
    ssl.psk_key.hash(&mut h);
    ssl.ocsp_der_path.hash(&mut h);
    ssl.pqc.hash(&mut h);
    ssl.groups.hash(&mut h);
    lc.port.hash(&mut h);
    lc.allows_h1().hash(&mut h);
    lc.allows_h2().hash(&mut h);
    h.finish()
}

/// 缓存版 acceptor 构建（accept 热路径用；build_acceptor 供首建/测试直连）。
pub fn build_acceptor_cached(ssl: &SslConfig, lc: &ListenerConfig) -> Result<Arc<SslAcceptor>> {
    let fp = acceptor_fingerprint(ssl, lc);
    if let Some(a) = ACCEPTOR_CACHE.lock().get(&fp) {
        return Ok(Arc::clone(a));
    }
    let a = Arc::new(build_acceptor(ssl, lc)?);
    let mut map = ACCEPTOR_CACHE.lock();
    if map.len() >= ACCEPTOR_CACHE_CAP {
        map.clear();
    }
    map.insert(fp, Arc::clone(&a));
    Ok(a)
}

pub async fn accept_and_serve(
    stream: TcpStream,
    peek: Vec<u8>,
    ssl: &SslConfig,
    lc: ListenerConfig,
    peer: SocketAddr,
    live: Arc<LiveConfig>,
) -> Result<()> {
    // Incomplete SSLv2 probes are routed here to avoid TomCrypt abort — soft-close.
    if !peek.is_empty() && peek[0] & 0x80 != 0 {
        log::info!(
            "boringssl soft-drop non-TLS/incomplete SSLv2-framed peek peer={peer} len={}",
            peek.len()
        );
        drop(stream);
        return Ok(());
    }
    let acceptor = build_acceptor_cached(ssl, &lc)?;
    let io = PrefixedStream::new(stream, peek);
    let tls = tokio_boring::accept(&acceptor, io)
        .await
        .map_err(|e| anyhow::anyhow!("boringssl accept failed: {e:?}"))?;
    dispatch_alpn(tls, live, lc, peer).await
}

async fn dispatch_alpn(
    tls: SslStream<PrefixedStream>,
    live: Arc<LiveConfig>,
    lc: ListenerConfig,
    peer: SocketAddr,
) -> Result<()> {
    let alpn = tls.ssl().selected_alpn_protocol().map(|p| p.to_vec());
    if alpn.as_deref() == Some(b"h2") && lc.allows_h2() {
        h2::serve_tls(tls, live, lc, peer).await
    } else {
        h1::serve_tls(tls, live, lc, peer).await
    }
}
