//! BoringSSL 可配置套件目录（**运行时探测**，不手抄名字）。
//!
//! 为什么探测而不是写死：
//! * 手抄的名单会漂 —— 本项目就踩过：`PSK_SUITE_TAIL` 里 6 个名字有 5 个是 OpenSSL
//!   的名字、BoringSSL 根本没有，而解析失败是**静默忽略**的，于是"管理员显式配了套件
//!   列表"时 psk 一个都没生效。
//! * 探测的对象就是**链接进来的那个 BoringSSL**，所以结果与在用版本严格一致
//!   （`SSL_CTX_set_cipher_list` 对未知名字必报错，`SSL_R_NO_CIPHER_MATCH`）。
//!
//! 用途：
//! 1. 配置校验：`ssl.ciphers` 里写了不支持的套件名 → 加载期就报错（指名道姓），
//!    而不是运行期静默忽略（用户要求"拒绝异常配置"）。
//! 2. 面板可选列表：把全集给用户挑（"尽可能多的选择"）。
//! 3. PSK 族：从目录里按名字筛 `PSK`，替代手工常量。
//!
//! TLS1.3 的 5 个套件名单独列：BoringSSL 没有 `set_ciphersuites`，它们**不能**经
//! `set_cipher_list` 配置（只会被忽略，甚至让整条列表报错），限制 TLS1.3 只能用
//! `ssl.versions`。这里仍把它们列出来供面板展示/校验（合法但不可配）。

use once_cell::sync::OnceCell;

/// 候选名：IANA/OpenSSL 风格的常见写法（**超集**，真伪由探测决定）。
const CANDIDATES: &[&str] = &[
    // ECDHE + AES-GCM / CHACHA20 / CBC
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-CHACHA20-POLY1305",
    "ECDHE-ECDSA-AES128-SHA",
    "ECDHE-RSA-AES128-SHA",
    "ECDHE-ECDSA-AES256-SHA",
    "ECDHE-RSA-AES256-SHA",
    "ECDHE-ECDSA-AES128-SHA256",
    "ECDHE-RSA-AES128-SHA256",
    "ECDHE-ECDSA-AES256-SHA384",
    "ECDHE-RSA-AES256-SHA384",
    "ECDHE-RSA-DES-CBC3-SHA",
    "ECDHE-ECDSA-DES-CBC3-SHA",
    // DHE
    "DHE-RSA-AES128-GCM-SHA256",
    "DHE-RSA-AES256-GCM-SHA384",
    "DHE-RSA-CHACHA20-POLY1305",
    "DHE-RSA-AES128-SHA",
    "DHE-RSA-AES256-SHA",
    "DHE-RSA-AES128-SHA256",
    "DHE-RSA-AES256-SHA256",
    // 静态 RSA（无前向保密，保留给老客户端）
    "AES128-GCM-SHA256",
    "AES256-GCM-SHA384",
    "AES128-SHA",
    "AES256-SHA",
    "AES128-SHA256",
    "AES256-SHA256",
    "DES-CBC3-SHA",
    // PSK 族
    "PSK-AES128-CBC-SHA",
    "PSK-AES256-CBC-SHA",
    "PSK-AES128-CBC-SHA256",
    "PSK-AES256-CBC-SHA384",
    "PSK-CHACHA20-POLY1305",
    "DHE-PSK-AES128-CBC-SHA",
    "DHE-PSK-AES256-CBC-SHA",
    "ECDHE-PSK-AES128-CBC-SHA",
    "ECDHE-PSK-AES256-CBC-SHA",
    "ECDHE-PSK-CHACHA20-POLY1305",
    "RSA-PSK-AES128-CBC-SHA",
    "RSA-PSK-AES256-CBC-SHA",
    // CCM
    "AES128-CCM",
    "AES256-CCM",
    "AES128-CCM8",
    "AES256-CCM8",
    "ECDHE-ECDSA-AES128-CCM",
    "ECDHE-ECDSA-AES256-CCM",
    "ECDHE-ECDSA-AES128-CCM8",
    "ECDHE-ECDSA-AES256-CCM8",
];

/// TLS1.3 套件（库内固定，不可经 set_cipher_list 配置；仅用于展示与校验合法性）。
pub const TLS13_SUITES: &[&str] = &[
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_CCM_SHA256",
    "TLS_AES_128_CCM_8_SHA256",
];

static SUPPORTED: OnceCell<Vec<String>> = OnceCell::new();

fn probe() -> Vec<String> {
    let mut ok = Vec::new();
    let Ok(mut ctx) = boring::ssl::SslContextBuilder::new(boring::ssl::SslMethod::tls()) else {
        // 连 TLS 上下文都建不起来（极早期/无 TLS 特性）→ 返回空表：
        // 调用方（配置校验）在空表时**不做套件名校验**，避免把能跑的配置判死。
        return ok;
    };
    for &name in CANDIDATES {
        if ctx.set_cipher_list(name).is_ok() {
            ok.push(name.to_string());
        }
    }
    ok
}

/// BoringSSL 实际接受的套件名（首次调用时探测，之后缓存）。
pub fn supported() -> &'static [String] {
    SUPPORTED.get_or_init(probe)
}

/// 名字是否可用：BoringSSL 真接受的，或 TLS1.3 的固定套件（合法但不可配）。
pub fn is_acceptable(name: &str) -> bool {
    let n = name.trim();
    if n.is_empty() {
        return false;
    }
    if TLS13_SUITES.iter().any(|s| s.eq_ignore_ascii_case(n)) {
        return true;
    }
    let table = supported();
    if table.is_empty() {
        // 探测不可用（无 TLS/上下文建不起来）→ 不武断拒绝。
        return true;
    }
    table.iter().any(|s| s.eq_ignore_ascii_case(n))
}

/// PSK 族的可用套件（替代手工维护的 PSK_SUITE_TAIL）。
pub fn psk_suites() -> Vec<String> {
    supported()
        .iter()
        .filter(|s| s.to_ascii_uppercase().contains("PSK"))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 探测必须能拿到非空集合（否则说明探测方式失效，配置校验会退化成"不校验"）。
    #[test]
    fn probe_finds_real_suites() {
        let s = supported();
        assert!(!s.is_empty(), "探测不到任何套件：探测方式失效");
        // 这几个是 BoringSSL 必备的现代套件，缺任何一个都说明探测/链接不对。
        for must in ["ECDHE-RSA-AES128-GCM-SHA256", "ECDHE-ECDSA-AES128-GCM-SHA256"] {
            assert!(s.iter().any(|x| x == must), "缺少 {must}: {s:?}");
        }
    }

    /// 反面：OpenSSL 有、BoringSSL 没有的名字必须被识别为不可用
    /// （这正是之前 psk 静默失效的原因）。
    #[test]
    fn openssl_only_names_are_rejected() {
        assert!(!is_acceptable("PSK-AES128-GCM-SHA256"));
        assert!(!is_acceptable("不存在的套件名"));
        assert!(is_acceptable("TLS_AES_128_GCM_SHA256"), "TLS1.3 套件名应视为合法");
    }

    /// PSK 族从目录里筛出来，且非空（psk=true 才有意义）。
    #[test]
    fn psk_family_is_nonempty() {
        let p = psk_suites();
        assert!(!p.is_empty(), "PSK 目录为空（BoringSSL 至少有 PSK-AES128-CBC-SHA）");
    }
}
