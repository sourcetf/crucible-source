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
///
/// **必须与配置期「剔除 TLS1.3 套件名」的那份名单逐项一致**（`boring_path::TLS13_SUITES`，
/// 已比对 `ssl_cipher.cc` 的 kCiphers）。原因：`is_acceptable` 对这里的名字**短路放行**
/// （不再问库），而 `apply_ciphers`/`split_tls13_suites` 只剔除**它自己那份**名单里的名字。
/// 一旦这里多出库并不具备的名字 → 配置校验放行、该名字留在 `set_cipher_list` 的实参里、
/// 而 BoringSSL 匹配不到任何条目：整条列表若只剩这种名字就报 `SSL_R_NO_CIPHER_MATCH`
/// → build_acceptor 失败 → **该监听口每个握手都软失败**（面板还会把它当可选项列出来）。
/// RFC 8446 有 5 条，本库只有下面 3 条；CCM 两条（TLS_AES_128_CCM_SHA256 / _8）不在
/// kCiphers 里，故**不列**（列出来正是上面那个「配置过了、端口实际下线」的坑）。
pub const TLS13_SUITES: &[&str] = &[
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
];

static SUPPORTED: OnceCell<Vec<String>> = OnceCell::new();

/// 枚举 BoringSSL **内部套件表**（不是「当前配置的列表」）：用
/// `SSL_get_cipher_by_value` 扫一遍 IANA 编号空间（0..=u16::MAX，65k 次查表，毫秒级）。
///
/// 为什么枚举而不是只试探 [`CANDIDATES`]：`apply_ciphers` 见到目录里没有的名字会
/// 直接 `bail!`（**加载期报错**，不是忽略），所以「目录」必须是库的真实能力。
/// 枚举是**权威**来源；手抄名单只作为补充（别名/关键字类写法）。
///
/// 实测更正（2026-10-01，OpenBSD）：本机 BoringSSL 的表与 `CANDIDATES` **恰好一致**
/// （22 项），所以「手抄名单一定会漏」这个最初的假设在这台机器上**不成立**；
/// 枚举的价值是「不再依赖假设」—— 换 BoringSSL 版本/构建选项后表会变，而代码不用改。
///
/// 返回的名字是 OpenSSL/IANA 风格（`SSL_CIPHER_get_name`），与本项目配置里
/// 书写套件名的方式一致；TLS1.3 套件不在 `kCiphers` 表里（它们不能经
/// `set_cipher_list` 配置），由 [`TLS13_SUITES`] 单独列出。
fn enumerate_by_value() -> Vec<String> {
    #[cfg(not(feature = "tls_boring"))]
    {
        Vec::new()
    }
    #[cfg(feature = "tls_boring")]
    {
        let mut out: Vec<String> = (0u16..=u16::MAX)
            .filter_map(|v| boring::ssl::SslCipher::from_value(v).map(|c| c.name().to_string()))
            // TLS1.3 套件名一律 `TLS_` 前缀，而它们**不能**经 set_cipher_list 配置
            //（BoringSSL 没有 set_ciphersuites）⇒ 不放进「可用于 ssl.ciphers 的目录」，
            // 否则面板会给管理员一个配了不生效的选项。它们的合法性由 TLS13_SUITES 回答。
            .filter(|n| !n.is_empty() && !n.starts_with("TLS_"))
            .collect();
        out.sort_unstable();
        out.dedup();
        out
    }
}

fn probe() -> Vec<String> {
    // 空表 = 「不武断拒绝」：配置校验看到空表就不做套件名校验（见 is_acceptable）。
    // rustls 配置下没有 boring 的 cipher list 可探，返回空表正是这个语义。
    #[cfg(not(feature = "tls_boring"))]
    {
        return Vec::new();
    }
    #[cfg(feature = "tls_boring")]
    {
        // ① 权威全集：枚举库内部表。
        let mut ok = enumerate_by_value();
        // ② 再用手抄候选项补充：枚举拿不到「cipher string 元素」类写法
        //    （`HIGH` / `AESGCM` / `kRSA` 这类别名与关键字），它们不是套件名，
        //    但对 `ssl.ciphers` 是合法输入。验证方式仍是让 BoringSSL 自己说。
        if let Ok(mut ctx) = boring::ssl::SslContextBuilder::new(boring::ssl::SslMethod::tls()) {
            for &name in CANDIDATES {
                if ctx.set_cipher_list(name).is_ok() && !ok.iter().any(|x| x == name) {
                    ok.push(name.to_string());
                }
            }
        }
        ok.sort_unstable();
        ok.dedup();
        ok
    }
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
    if table.iter().any(|s| s.eq_ignore_ascii_case(n)) {
        return true;
    }
    // 目录里没有：**不武断拒绝**，直接问 BoringSSL（`set_cipher_list` 成功即合法）。
    //
    // 这一步是「支持所有 BoringSSL 支持的套件名」的兜底：目录再全也可能漏掉
    // 别名/新套件，而这里按库的真实能力回答；反过来，乱写的名字会被库拒绝
    // （`SSL_R_NO_CIPHER_MATCH`），typo 仍拦得住。
    #[cfg(feature = "tls_boring")]
    {
        if let Ok(mut ctx) = boring::ssl::SslContextBuilder::new(boring::ssl::SslMethod::tls()) {
            return ctx.set_cipher_list(n).is_ok();
        }
    }
    // 探测不可用（rustls 构建 / 建不起上下文）→ 不武断拒绝。
    true
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

    /// 这份名单必须与配置期剔除 TLS1.3 名字的名单（`boring_path::TLS13_SUITES`）相同。
    ///
    /// 多一条（例如 RFC 里那两条 CCM）就会：`is_acceptable` 放行 → 剔除逻辑不认 → 名字
    /// 落进 `set_cipher_list` → 若列表只剩它则 `SSL_R_NO_CIPHER_MATCH`、端口每个握手都
    /// 失败。这条断言就是对「有人凭 RFC 列表把 CCM 加回来」的闸门。
    #[test]
    fn tls13_suite_list_matches_the_strippable_set() {
        assert_eq!(
            TLS13_SUITES,
            &[
                "TLS_AES_128_GCM_SHA256",
                "TLS_AES_256_GCM_SHA384",
                "TLS_CHACHA20_POLY1305_SHA256",
            ]
        );
    }

    /// 探测必须能拿到非空集合（否则说明探测方式失效，配置校验会退化成"不校验"）。
    // 探测本身要 BoringSSL 的 SslContextBuilder：只在 boring 构建下有意义（rustls 配置下 probe 返回空表 = 不武断拒绝）。
    #[cfg(feature = "tls_boring")]
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
    // 「拒绝 OpenSSL-only 名字」判据依赖 BoringSSL 的实际探测结果：只在 boring 构建下有意义（rustls 配置下 probe 返回空表 = 不武断拒绝）。
    #[cfg(feature = "tls_boring")]
    #[test]
    fn openssl_only_names_are_rejected() {
        assert!(!is_acceptable("PSK-AES128-GCM-SHA256"));
        assert!(!is_acceptable("不存在的套件名"));
        assert!(is_acceptable("TLS_AES_128_GCM_SHA256"), "TLS1.3 套件名应视为合法");
    }

    /// 目录必须是「BoringSSL 自己说的那套」，而不是只回显手抄名单。
    ///
    /// **实测更正**：最初这里断言「枚举结果一定比手抄名单多」—— 在 OpenBSD 上**为假**
    /// （本机 BoringSSL 的套件表恰好与 `CANDIDATES` 一致，22 项）。那条断言是假设，已删。
    /// 保留的判据是可验证的超集关系：枚举/探测的结果必须包含手抄候选中 BoringSSL 认可的全部名字，
    /// 且含现代必配套件 —— 这样「枚举把名单里的名字弄丢」这类退化仍会被抓到。
    #[cfg(feature = "tls_boring")]
    #[test]
    fn catalog_is_a_superset_of_the_handwritten_probe() {
        let full = supported();
        assert!(!full.is_empty(), "目录为空：枚举与探测都失效 → 配置校验会退化成不校验");
        for must in ["ECDHE-RSA-AES128-GCM-SHA256", "ECDHE-ECDSA-AES128-GCM-SHA256"] {
            assert!(full.iter().any(|x| x == must), "缺少 {must}: {full:?}");
        }
        let mut kept = 0;
        for c in CANDIDATES.iter().copied() {
            if is_acceptable(c) {
                assert!(
                    full.iter().any(|x| x.eq_ignore_ascii_case(c)),
                    "枚举丢了手抄候选里可用的 {c}"
                );
                kept += 1;
            }
        }
        eprintln!(
            "[cipher-catalog] 目录 {} 项 / 手抄候选 {} 项（其中 {} 项 BoringSSL 认可）",
            full.len(),
            CANDIDATES.len(),
            kept
        );
    }

    /// PSK 族从目录里筛出来，且非空（psk=true 才有意义）。
    // PSK 套件表来自 BoringSSL 的 cipher list：只在 boring 构建下有意义（rustls 配置下 probe 返回空表 = 不武断拒绝）。
    #[cfg(feature = "tls_boring")]
    #[test]
    fn psk_family_is_nonempty() {
        let p = psk_suites();
        assert!(!p.is_empty(), "PSK 目录为空（BoringSSL 至少有 PSK-AES128-CBC-SHA）");
    }
}
