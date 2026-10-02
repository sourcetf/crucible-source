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
use boring::ssl::{SslAcceptor, SslAcceptorBuilder, SslMethod, SslVersion, NameType};
use boring::x509::{X509, X509Ref};
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_boring::SslStream;

pub fn build_acceptor(ssl: &SslConfig, lc: &ListenerConfig) -> Result<SslAcceptor> {
    let mut builder = SslAcceptor::mozilla_modern(SslMethod::tls())?;
    // boring 的 mozilla_modern 预设带 SSL_OP_NO_TLSV1_3,不清掉 TLS1.3 永远握手失败(
    // set_min/max_proto_version 不会复位该 option 位)。§6 主路径要求 1.2/1.3 全开。
    builder.clear_options(boring::ssl::SslOptions::NO_TLSV1_3);
    apply_versions(&mut builder, ssl)?;
    // OCSP 是**逐证书**一份：先规划（真实/cover 各一份），再让 load_identity 在
    // 「ECH 接受与否」的决策点装对应那份（见 OcspPlan 的说明）。
    let ocsp = plan_ocsp(ssl);
    load_identity(&mut builder, ssl, &ocsp)?;
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
    apply_ocsp(&mut builder, ssl, &ocsp)?;
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

fn load_identity(builder: &mut SslAcceptorBuilder, ssl: &SslConfig, ocsp: &OcspPlan) -> Result<()> {
    let cert_pem = ssl_material::load_bytes(ssl.cert.as_deref().context("ssl.cert")?)?;
    let key_pem = ssl_material::load_bytes(ssl.key.as_deref().context("ssl.key")?)?;
    let cert = X509::from_pem(&cert_pem)?;
    let key = PKey::private_key_from_pem(&key_pem)?;

    // ⚠️ 本 BoringSSL 只有**一个** legacy credential 槽：
    // `SSL_CTX_use_certificate` 的文档原文是 "Each of these functions configures the single
    // "legacy credential"... To select between multiple certificates, use
    // SSL_CREDENTIAL_new_x509"，而本 build 并未导出那套 API。所以**同一层里重复
    // set_certificate 是覆盖、不是「按密钥类型各存一张」**（原注释写的「备用链」是错的）。
    //
    // 由此推出两条硬约束（配置期已 fail-fast，见 config.rs）：
    //   * 内层与外层必须**配成同一组密钥类型**：每层实际生效的是最后设置的那张，两层类型
    //     不一致时 ECH 接受前后会把证书类型换掉，只支持一种类型的客户端两条路径各失败一边。
    //   * 因此下面「容器用 cover、回调换 real」在类型上天然一致（都被最后那张 EC 或都 RSA）。
    //
    // 备用 EC 证书（`ssl.cert_ec`）：与 `cert` 同层，后设置的生效。
    let ec_pair = match (&ssl.cert_ec, &ssl.key_ec) {
        (Some(c), Some(k)) => {
            let ec_x509 = X509::from_pem(&ssl_material::load_bytes(c)?)?;
            let ec_pkey = PKey::private_key_from_pem(&ssl_material::load_bytes(k)?)?;
            Some((ec_x509, ec_pkey))
        }
        _ => None,
    };

    // ECH 外层（cover）证书：容器默认证书设为 cover —— **不带 ECH 的客户端**（以及
    // ECH 被拒后回退的客户端）按 `ech_public_name` 校验证书，走的就是这一张。
    let cover = match (&ssl.ech_cover_cert, &ssl.ech_cover_key) {
        (Some(c), Some(k)) => {
            let cc = X509::from_pem(&ssl_material::load_bytes(c)?)?;
            let ck = PKey::private_key_from_pem(&ssl_material::load_bytes(k)?)?;
            Some((cc, ck))
        }
        _ => None,
    };

    // 外层 cover 的**备用 EC 证书**。见上：本 BoringSSL 单 credential 槽，同层后设置的生效；
    // 外层配 EC 是为了让「外层生效的那张」与「内层生效的那张」是同一种密钥类型
    // —— 否则 ECH 接受前后证书类型会变，只支持一种类型的客户端必有一边失败。
    let cover_ec = match (&ssl.ech_cover_cert_ec, &ssl.ech_cover_key_ec) {
        (Some(c), Some(k)) => {
            let x = X509::from_pem(&ssl_material::load_bytes(c)?)?;
            let p = PKey::private_key_from_pem(&ssl_material::load_bytes(k)?)?;
            Some((x, p))
        }
        _ => None,
    };

    // ECH（RFC 9849）部署约束 —— 全部**配置期 fail-fast**，不做静默降级：
    //
    // ① 外层（cover）与内层（真实）必须是**两张不同的证书**。若用同一张，任何连接
    //    （含不做 ECH 的探测者）看到的证书都一样，ECH 就失去意义 —— 中间人凭证书即可
    //    关联出「这台主机在服务哪个真实域名」。
    // ② cover 证书必须**覆盖 `ech_public_name`**：客户端未用 ECH、或 ECH 被拒时看到的是
    //    外层名，它按 public_name 校验证书；cover 不覆盖它 ⇒ 回退路径直接校验失败。
    // ③ cover 与 OCSP 装订**同时开启**时直接报错：staple 是**逐证书的单份 DER**
    //    （`set_ocsp_status` 只装一份），而我们会在两套证书之间切换 ⇒ 必然有一边拿到
    //    不匹配的 staple：严格客户端校验失败、宽松客户端**撤回检查静默失效**（比不装订更糟）。
    //    与其错配，不如明确要求二选一。
    if let Some((cc, _ck)) = &cover {
        let public_name = ssl
            .ech_public_name
            .as_deref()
            .context("ECH cover 需要 ssl.ech_public_name（RFC 9849 的 public_name）")?
            .trim()
            .to_string();
        if cert.to_der()? == cc.to_der()? {
            anyhow::bail!(
                "ECH: cover 证书与真实证书是**同一张**（DER 完全相同）—— RFC 9849 要求内外层分离；\
同一张证书会让 ECH 失去意义（中间人凭证书即可关联真实域名）"
            );
        }
        if !cert_covers(cc, &public_name) {
            anyhow::bail!(
                "ECH: cover 证书不覆盖 ech_public_name={public_name} —— 未使用 ECH / ECH 被拒的\
客户端会按 public_name 校验证书，必然失败"
            );
        }
        if ssl.ocsp_der_path.is_some() {
            anyhow::bail!(
                "ECH cover 证书与 ssl.ocsp_der_path 不能同时配置：OCSP staple 是逐证书的单份 DER，\
两套证书间切换必然有一边错配（严格客户端校验失败、宽松客户端撤回检查静默失效）。请二选一"
            );
        }
        // ④ 内外层必须**配成同一组密钥类型**。理由见文件上方关于「单 credential 槽」的说明：
        //    每层实际生效的是**最后设置的那张**，若内层有 EC 而外层没有（或反之），ECH 接受
        //    前后证书类型会变（cover=RSA → real=EC），只提供单一类型的客户端会在两条路径里
        //    各失败一边；更糟的是**内层可能因此被逼出来**（外层只有 RSA 时，容器里唯一的 EC
        //    证书是内层那张 —— §21.34 在 127.0.0.1:18443 上实测复现过：ECH/非 ECH+RSA/
        //    非 ECH+仅 ECDSA 三条探针拿到**完全相同**的内层指纹）。
        if ec_pair.is_some() != cover_ec.is_some() {
            anyhow::bail!(
                "ECH: ssl.cert_ec 与 ssl.ech_cover_cert_ec 必须**同时配或同时不配** —— 本 BoringSSL\
 的 SSL_CTX_use_certificate 只有单个 credential 槽（是覆盖、不是按类型各存一张），每层生效的\
是最后设置的那张。内外层密钥类型不一致时，ECH 接受前后证书类型会变：只支持一种类型的客户端在\
「ECH / 非 ECH」两条路径里必有一边失败，且外层缺 EC 时容器里偏巧就是**内层**那张 EC 证书（\
主动探测者换一组 sigalgs 即可确认真实域名）"
            );
        }
        if let Some((cec, _)) = &cover_ec {
            // 外层 EC 也必须覆盖 public_name（它是外层生效的那张）
            if !cert_covers(cec, &public_name) {
                anyhow::bail!(
                    "ECH: ech_cover_cert_ec 不覆盖 ech_public_name={public_name} —— 外层按 \
public_name 校验证书，必然失败"
                );
            }
            // 与内层 EC 不能是同一张（同 ① 的理由，只是换成 EC 那一对）
            if let Some((inner_ec, _)) = &ec_pair {
                if inner_ec.to_der()? == cec.to_der()? {
                    anyhow::bail!(
                        "ECH: ech_cover_cert_ec 与 ssl.cert_ec 是**同一张** —— 内外层必须分离"
                    );
                }
            }
        }
    }

    match &cover {
        Some((cc, ck)) => {
            builder.set_certificate(cc)?;
            builder.set_private_key(ck)?;
            builder.check_private_key()?;
        }
        None => {
            builder.set_certificate(&cert)?;
            builder.set_private_key(&key)?;
            builder.check_private_key()?;
        }
    }
    // 容器上的证书（非 ECH 路径生效的那张）：配了 cover 时是**外层**，否则是内层。
    // 单 credential 槽 ⇒ 同层「后设置者生效」，所以这里放的必须是外层那一组
    // （把内层的 EC 放进来就是 §21.34 的内层泄漏）。
    let container_ec = if cover.is_some() {
        cover_ec.as_ref().or(ec_pair.as_ref())
    } else {
        ec_pair.as_ref()
    };
    if let Some((ec_x509, ec_pkey)) = container_ec {
        // 同一层再 set 一次 = 覆盖（本 BoringSSL 单 credential 槽；`add_extra_chain_cert`
        // 只是追加中间证书、不会成为叶证书，别用它）。
        builder.set_certificate(ec_x509)?;
        builder.set_private_key(ec_pkey)?;
        builder.check_private_key()?;
    }

    if cover.is_some() {
        // RFC 9849：证书选择判据是 **ECH 是否被接受**（`SSL_ech_accepted`），
        // **不能用域名比较** —— 按名字判等于「谁把 SNI 写成真实名，谁就拿到真实证书」，
        // 那既让 cover 形同虚设，又向主动探测者确认了「本机持有该域名的证书」。
        //
        // * `ech_accepted() == true`：客户端用了 ECH 且解密成功，服务端看到的是**内层真实名**
        //   ⇒ 用真实证书（TLS1.3 下证书对被动观察者加密，MITM 看不到）。
        // * `false`（客户端没发 ECH，或发了但被拒后回退）：一律用 **cover**。
        //   —— 包括「SNI 恰好是真实名」的探测连接：它们只配看到外层证书。
        // 注：本回调在 **ECH 处理之后**运行（实测：ECH 客户端在此处已能看到内层名）。
        let real_cert = cert.clone();
        let real_key = key.clone();
        let real_ec = ec_pair.as_ref().map(|(c, k)| (c.clone(), k.clone()));
        // OCSP 是逐证书一份：把两份材料（可能为空=不装订）一起搬进回调
        let ocsp_real = ocsp.real.as_ref().map(|s| s.bytes()).flatten();
        let ocsp_cover = ocsp.cover.as_ref().map(|s| s.bytes()).flatten();
        builder.set_servername_callback(move |s, _alert| {
            if !s.ech_accepted() {
                // 未接受 ECH：保持容器默认（cover）证书 —— 但 **staple 必须换成 cover 的**：
                // 容器上装的是真实证书那份（apply_ocsp 的默认动作），装在 cover 上就是错配。
                match &ocsp_cover {
                    Some(der) => {
                        let _ = s.set_ocsp_status(der);
                    }
                    // cover 没有自己的 staple ⇒ **清空**：不装订是安全的（客户端自行查询），
                    // 留着真实证书那份才是错的。
                    None => {
                        let _ = s.set_ocsp_status(&[]);
                    }
                }
                return Ok(());
            }
            // ECH 被接受：换成真实证书，并把 staple 换成真实证书那份
            if let Some(der) = &ocsp_real {
                let _ = s.set_ocsp_status(der);
            }
            if s.set_certificate(&real_cert).is_err() || s.set_private_key(&real_key).is_err() {
                log::warn!("ech: ECH 已接受但切换真实证书失败（保持 cover）");
                return Err(boring::ssl::SniError::ALERT_FATAL);
            }
            if let Some((ec_c, ec_k)) = &real_ec {
                // 备用 EC 链同样切成真实的，否则 ECDSA 客户端拿到不匹配的链
                let _ = s.set_certificate(ec_c);
                let _ = s.set_private_key(ec_k);
            }
            // 日志不脱敏（本地存储安全，用户明确要求）：内层名便于排障。
            log::debug!(
                "ech: accepted ⇒ 真实证书（服务端看到内层名 {:?}）",
                s.servername(NameType::HOST_NAME)
            );
            Ok(())
        });
    }
    Ok(())
}

/// 名字匹配（通配符感知，RFC 6125 §6.4.3 的简化：只支持最左 `*.`）。
fn dns_name_matches(pattern: &str, name: &str) -> bool {
    let p = pattern.trim().trim_end_matches('.').to_ascii_lowercase();
    let n = name.trim().trim_end_matches('.').to_ascii_lowercase();
    if p == n {
        return true;
    }
    if let Some(rest) = p.strip_prefix("*.") {
        // 通配符只匹配**一个**标签：`*.example.com` 匹配 `a.example.com`，不匹配
        // `a.b.example.com`、也不匹配 `example.com` 本身。
        return match n.split_once('.') {
            Some((_, tail)) => tail == rest,
            None => false,
        };
    }
    false
}

/// 证书是否覆盖该名字：**SAN 优先**，CN 仅作兼容回退（现代 CA 一律走 SAN）。
fn cert_covers(cert: &X509Ref, name: &str) -> bool {
    if let Some(sans) = cert.subject_alt_names() {
        for gn in sans.iter() {
            if let Some(dns) = gn.dnsname() {
                if dns_name_matches(dns, name) {
                    return true;
                }
            }
        }
    }
    if let Some(cn) = cert
        .subject_name()
        .entries_by_nid(boring::nid::Nid::COMMONNAME)
        .next()
    {
        if let Ok(s) = std::str::from_utf8(cn.data().as_slice()) {
            if dns_name_matches(s, name) {
                return true;
            }
        }
    }
    false
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
/// 从 [`cipher_catalog`] 里筛出来 —— 不再手工维护名字：以前那份常量里 6 个名字有 5 个
/// 是 OpenSSL 的、BoringSSL 没有，而解析失败是静默忽略的，于是"显式配套件列表"时 psk 一个都没生效。
fn psk_tail() -> String {
    let mut s = String::new();
    for n in crate::server::tls::cipher_catalog::psk_suites() {
        s.push(':');
        s.push_str(&n);
    }
    s
}

fn apply_ciphers(builder: &mut SslAcceptorBuilder, ssl: &SslConfig) -> Result<()> {
    // 配置里写了 BoringSSL 不认的套件名：不再静默剔除 —— 那会让"我配了它"变成
    // "它其实没生效"（psk 族就栽在这上面）。加载期就报错并指名，让运维改对。
    for raw in &ssl.ciphers {
        let name = raw.trim();
        if !name.is_empty() && !crate::server::tls::cipher_catalog::is_acceptable(name) {
            anyhow::bail!(
                "ssl.ciphers 里的 {name:?} 不是 BoringSSL 支持的套件名（可用目录见 /api/tls/ciphers 或面板）"
            );
        }
    }
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
        list.push_str(&psk_tail());
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

/// 应用 ECH 密钥（**仅当 `ssl.ech = true`**；关掉就是一点 ECH 材料都不装）。
///
/// 三条路径，优先级从高到低：
///   1. `ssl.ech_keys` 显式配置 → 用管理员材料（原行为不变）；
///   2. 未配置 → **自动配置**（规格 §16 1.a）：先复用 `state/ech/ech_keys.pem`
///      里已生成且仍匹配当前 public-name/suite/max-name-length 的配置，
///      不匹配则用真实 X25519 keypair 重新生成并落盘；
///   3. 自动配置失败（如未填 `ech_public_name`）→ 仅 warn，不阻断 TLS。
///
/// 早期实现只走路径 1：`ech_keys` 没配就直接放弃，于是「ECH 自动配置」实际不存在。
/// `ech_advertise` 不参与这里的开关判断，它只决定「配置要不要发到 HTTPS(type65) 记录」，
/// 见 `SslConfig::ech_advertise_enabled`。
fn apply_ech(builder: &mut SslAcceptorBuilder, ssl: &SslConfig) -> Result<()> {
    // 判据只能是 `ssl.ech`。旧写法 `!ssl.ech && !ssl.ech_advertise` 有真实后果：
    // `ech_advertise` 的 serde 默认值是 **true**，于是只要 `ech_public_name` 配了
    // （它同时是 `SslConfig::ocsp_host()` 的身份来源），**显式关掉** ECH 的 listener
    // 也会继续走到下面的自动配置 —— 生成密钥、装进 acceptor，ECH 被实际打开。
    // 开关必须名副其实。反向情形（`ech = true` 但材料不全）仍要走到下面的 warn：
    // 那是「开了却没生效」，必须吵（见回归测试 ech_false_disables_ech_even_with_public_name）。
    if !ssl.ech {
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
/// 一份 OCSP staple 的来源：静态文件内容，或后台自动续期的槽。
enum StapleSource {
    Static(Vec<u8>),
    Auto(std::sync::Arc<crate::server::ocsp_fetcher::StapleSlot>),
}

impl StapleSource {
    fn bytes(&self) -> Option<Vec<u8>> {
        match self {
            StapleSource::Static(b) => Some(b.clone()),
            StapleSource::Auto(s) => s.current(),
        }
    }
}

/// **逐证书**的 OCSP 装订规划。
///
/// ECH 会在 **cover** 与 **真实** 证书之间切换，而 OCSP 响应是与证书**一一对应**的
/// （`SSL_set_ocsp_status` 装的是单份 DER）⇒ 必须各准备一份：
/// * `real`  —— 配给 `ssl.cert`（ECH 被接受、使用内层真实证书时用）；
/// * `cover` —— 配给 `ssl.ech_cover_cert`（未用 ECH / ECH 被拒时用）。
///
/// 某一侧没有材料时**不装订那一侧**：**不装订是安全的**（客户端会自行查询 OCSP），
/// 而装了**不匹配**的那份才是有害的（严格客户端校验失败；宽松客户端撤回检查静默失效）。
struct OcspPlan {
    real: Option<StapleSource>,
    cover: Option<StapleSource>,
}

fn ocsp_static_from(path: &str) -> Option<StapleSource> {
    match ssl_material::load_bytes(path) {
        Ok(d) if !d.is_empty() => {
            let der = pem_to_der(&d).unwrap_or(d);
            log::info!("ocsp stapling: {} bytes from {path}", der.len());
            Some(StapleSource::Static(der))
        }
        Ok(_) => {
            log::warn!("ssl.ocsp 材料 {path} 为空；该证书不装订");
            None
        }
        Err(e) => {
            log::warn!("ssl.ocsp 材料 {path} 不可读: {e:#}；该证书不装订");
            None
        }
    }
}

/// 自动获取路径：`(host, 证书路径)` → 后台续期槽。
fn ocsp_auto_slot(host: &str, cert_path: &str) -> Option<StapleSource> {
    let cert_pem = ssl_material::load_bytes(cert_path).ok()?;
    let leaf = X509::from_pem(&cert_pem).ok()?;
    crate::server::ocsp_fetcher::prepare_stapling(host, &leaf, &cert_pem)
        .map(StapleSource::Auto)
}

/// 为真实证书与 cover 证书各规划一份 staple（见 [`OcspPlan`] 的说明）。
fn plan_ocsp(ssl: &SslConfig) -> OcspPlan {
    // 真实证书：显式路径优先，否则自动获取（沿用既有语义：host 取 ssl.ocsp_host()）。
    let real = if let Some(p) = ssl.ocsp_der_path.as_deref() {
        ocsp_static_from(p)
    } else {
        match (ssl.cert.as_deref(), ssl.ocsp_host()) {
            (Some(c), Some(h)) => ocsp_auto_slot(&h, c),
            _ => None,
        }
    };

    // cover 证书：只在配了 cover 时规划。
    let cover = if let (Some(cover_cert), Some(public_name)) = (
        ssl.ech_cover_cert.as_deref(),
        ssl.ech_public_name.as_deref(),
    ) {
        if let Some(p) = ssl.ech_cover_ocsp_der_path.as_deref() {
            ocsp_static_from(p)
        } else {
            // 自动探测用 **public_name**（cover 证书服务的就是这个名字）
            let slot = ocsp_auto_slot(public_name.trim(), cover_cert);
            if slot.is_none() {
                log::info!(
                    "ocsp: cover 证书未配置且无法自动获取 staple ⇒ cover 路径不装订（不装订是安全的：客户端会自行查询 OCSP）"
                );
            }
            slot
        }
    } else {
        None
    };

    OcspPlan { real, cover }
}

fn apply_ocsp(builder: &mut SslAcceptorBuilder, ssl: &SslConfig, ocsp: &OcspPlan) -> Result<()> {
    // 配了 cover 时：装订在 **servername 回调**里按 ech_accepted 分派（见 load_identity）；
    // 这里只开启装订能力，**不**注册 select_certificate 装订（否则会先装上真实证书那份，
    // 而 cover 路径无从纠正 —— select_certificate 早于 servername 且只能注册一次）。
    if ssl.ech_cover_cert.is_some() {
        if ocsp.real.is_none() && ocsp.cover.is_none() {
            return Ok(());
        }
        builder.enable_ocsp_stapling();
        log::info!(
            "ocsp stapling: 按证书分派（real={} cover={}）",
            ocsp.real.is_some(),
            ocsp.cover.is_some()
        );
        return Ok(());
    }
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
    // QMux（`qmux = true`）走 h1-over-QMux，所以必须 h1 开着（配置校验已拦）。
    let offer_qmux = lc.qmux && offer_h1;
    builder.set_alpn_select_callback(move |_ssl, client_protos: &[u8]| {
        // wire 格式：u8 len + name，逐段扫描；记录 h2 / http/1.1 / qmux 的命中区间。
        let mut h2_span: Option<&[u8]> = None;
        let mut h1_span: Option<&[u8]> = None;
        let mut qmux_span: Option<&[u8]> = None;
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
                n if offer_qmux && n == crate::server::qmux::conn::QMUX_ALPN => {
                    qmux_span = Some(name)
                }
                _ => {}
            }
            i = end;
        }
        // 服务端偏好 h2 > http/1.1 > QMux：**开启 qmux 不改变老客户端的行为**，
        // 想要 QMux 的客户端在 ALPN 里只给 `h1-02qx` 即可。
        h2_span
            .or(h1_span)
            .or(qmux_span)
            .ok_or(boring::ssl::AlpnError::NOACK)
    });
    Ok(())
}

// P2-4：按（listener + SslConfig 全字段指纹）缓存 SslAcceptor——旧实现每连接重新
// load PEM/解析双证/装 ECH keys，session ticket 复用全部失效。缓存上限 64，超限清空。
// 注意：PSK 若经环境变量注入，env 变化不会反映到指纹（配置 ssl.psk_key 即可热生效）。
static ACCEPTOR_CACHE: Lazy<Mutex<HashMap<u64, Arc<SslAcceptor>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
/// acceptor 缓存条目上限。
///
/// 必须**大于等于**允许的 listener 数（`admin_config_edit::MAX_LISTENERS = 128`）：
/// 指纹里含 `lc.port`，每个 listener 至少占一项；以前是 64 < 128，一旦配置里的
/// ssl listener 超过 64 个（或 ssl 参数组合多），满上限就**整表清空** ⇒ 命中率跌到 0，
/// 每次握手都重新读 PEM/解析链/装 ECH 密钥（纯性能悬崖，不是正确性问题）。
/// 取 256 = 128 listener × 2（同一 listener 在 h1/h2 两种 ALPN 组合下各一项）+ 余量。
pub const ACCEPTOR_CACHE_CAP: usize = 256;

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
    // **材料指纹（mtime + size）**：证书/密钥路径不变、内容被原地替换（certbot/acme.sh/
    // `dns.acme` 续期、运维手工覆盖）时，只哈希**路径字符串**会让指纹不变 ⇒ 命中旧
    // acceptor ⇒ 对继续出示**旧证书**（甚至已过期的）直到 config.toml 被 reload 或重启。
    // 哈希 mtime+size 让「文件被换掉」这件事本身进指纹：mtime 由内核在写入/替换时更新，
    // 精确到纳秒（OpenBSD: st_mtim），两次续期落在同一纳秒的可能性可以忽略。
    //
    // 热路径不额外 stat：`build_acceptor_cached` 只在**握手路径**上（每连接一次），
    // 这里 stat 的是 4~8 个小文件（内核 denty 缓存），代价远小于一次 TLS 握手。
    for p in [
        &ssl.cert,
        &ssl.key,
        &ssl.cert_ec,
        &ssl.key_ec,
        &ssl.ech_keys,
        &ssl.ech_cover_cert,
        &ssl.ech_cover_key,
        &ssl.ocsp_der_path,
    ] {
        if let Some(path) = p.as_deref() {
            if path.contains("-----BEGIN") {
                // 内联 PEM：内容本身就是配置的一部分，上面已经哈希过字段值。
                continue;
            }
            match std::fs::metadata(path) {
                Ok(m) => {
                    m.len().hash(&mut h);
                    if let Ok(t) = m.modified() {
                        if let Ok(d) = t.duration_since(std::time::UNIX_EPOCH) {
                            d.as_nanos().hash(&mut h);
                        }
                    }
                }
                // 打不开的文件：把「打不开」也编进指纹，避免「文件先消失后出现」
                // 一直命中旧 acceptor（真正读不到时 build_acceptor 会自己报错）。
                Err(_) => 0u8.hash(&mut h),
            }
        }
    }
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
    if alpn.as_deref() == Some(crate::server::qmux::conn::QMUX_ALPN) && lc.qmux {
        // QMux v1：在其逻辑流上跑 HTTP/1.1（每条流一个 h1 会话）
        crate::server::qmux::serve_h1(tls, live, lc, peer).await
    } else if alpn.as_deref() == Some(b"h2") && lc.allows_h2() {
        h2::serve_tls(tls, live, lc, peer).await
    } else {
        h1::serve_tls(tls, live, lc, peer).await
    }
}

#[cfg(test)]
mod fingerprint_tests {
    use super::*;

    /// 证书文件被**原地替换**（路径不变）时，指纹必须变化。
    ///
    /// 旧实现只哈希**路径字符串**：certbot/acme.sh/`dns.acme` 续期、运维手工覆盖
    /// `ssl.cert` 之后指纹不变 ⇒ 命中旧 acceptor ⇒ 端口继续出示旧（甚至已过期的）
    /// 证书，直到 config.toml 被 reload 或进程重启。
    #[test]
    fn fingerprint_follows_material_changes() {
        let dir = std::env::temp_dir().join(format!("crucible-fp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");
        std::fs::write(&cert, b"first").expect("write");
        std::fs::write(&key, b"key").expect("write");
        let ssl = crate::config::SslConfig {
            cert: Some(cert.display().to_string()),
            key: Some(key.display().to_string()),
            ..Default::default()
        };
        let lc = crate::config::ListenerConfig::default();

        let fp1 = acceptor_fingerprint(&ssl, &lc);
        assert_eq!(
            fp1,
            acceptor_fingerprint(&ssl, &lc),
            "同样的材料必须得到同样的指纹（否则缓存永不命中）"
        );

        // ① 长度不同的替换
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(&cert, b"second-cert-content").expect("rewrite");
        let fp2 = acceptor_fingerprint(&ssl, &lc);
        assert_ne!(fp1, fp2, "证书被替换后指纹必须变化（否则继续用旧证书）");

        // ② **同样长度**、不同内容（只把 size 编进指纹的实现会在这条上漏掉）
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(&cert, b"THIRD-cert-content!").expect("rewrite2");
        let fp3 = acceptor_fingerprint(&ssl, &lc);
        assert_ne!(fp2, fp3, "等长替换也必须改变指纹（要靠 mtime）");

        // ③ 与内容无关的字段变化同样要影响指纹
        let mut ssl2 = ssl.clone();
        ssl2.prefer_tls13 = true;
        assert_ne!(fp3, acceptor_fingerprint(&ssl2, &lc), "配置字段变化必须影响指纹");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
