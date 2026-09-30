//! TLS facade: BoringSSL primary + optional NSS / TomCrypt legacy stacks.
//!
//! - **BoringSSL**: TLS 1.2/1.3, ECH, PQC hybrid groups, ALPN → H1/H2
//! - **NSS**: SSLv3, TLS 1.0–1.2, IE6 v2-compatible ClientHello
//! - **TomCrypt**: pure SSLv2 records
//!
//! ClientHello peek routing lives in [`client_hello`]; legacy modules compile only
//! when `tls_nss` / `tls_tomcrypt` features are enabled (configure `--enable-*`).

use crate::config::SslConfig;

pub mod accept;
pub mod boring_path;
pub mod cipher_catalog;
pub mod client_hello;
#[cfg(feature = "tls_boring")]
pub mod ech_pem;
/// ECH 真机握手测试：用本仓库依赖的 `boring` 当 ECH 客户端（见文件头说明）。
#[cfg(all(test, feature = "tls_boring"))]
mod ech_handshake_test;
pub mod legacy_io;
#[cfg(all(feature = "tls_rustls", not(feature = "tls_boring")))]
pub mod rustls_path;

#[cfg(feature = "tls_nss")]
#[path = "tls_nss.rs"]
pub mod nss;

#[cfg(feature = "tls_tomcrypt")]
#[path = "tls_tomcrypt.rs"]
pub mod tomcrypt;

pub use boring_path::{active_stack, legacy_modules};

/// Primary stack for a listener (always BoringSSL when compiled in).
/// Legacy NSS/TomCrypt are selected per-connection via [`client_hello::resolve`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsStack {
    Boring,
    Nss,
    Tomcrypt,
}

/// Declared primary TLS implementation for admin/catalog (not per-hello routing).
pub fn select_stack(_ssl: &SslConfig) -> TlsStack {
    TlsStack::Boring
}

/// 把握手失败的错误链压成**一行短原因**，供日志使用。
///
/// 为什么需要它：`boring` 的握手失败是 `Failure(MidHandshakeSslStream { stream: … prefix:
/// Cursor { inner: [22, 3, 1, 1, 158, …整个 ClientHello 的每个字节…] } })`，`{e:#}` 会把这
/// 串**攻击者可控**的字节原样写进日志（实测单条 ≈2KB，占 /var/log/crucible-restart.log 的
/// 67%）。公网 TLS 端口上「明文请求 / 扫描器 / 老客户端」是**预期流量**：任何一个匿名客户端
/// 只要发一次明文 GET 就能让磁盘多写 2KB —— 放大上万倍的日志洪泛，而这台机器磁盘长期紧张
/// （曾因写满让 GeoIP merge 死在半路）。
///
/// 处理方式：把「长数字数组」（就是那些缓冲字节）折叠成 `[…]`，再给整行加长度上限；
/// 完整的原始错误仍然会以 debug 级别写出（`RUST_LOG=debug` 可查），信息没有被删。
pub(crate) fn handshake_failure_reason(e: &anyhow::Error) -> String {
    /// 连续数字个数超过它就认为是「字节数组」而不是正常诊断文本。
    const ARRAY_DIGITS: usize = 24;
    /// 折行上限（正常错误原因远短于此）。
    const MAX_CHARS: usize = 375;
    /// 超限时保留的**头部**字数（对端地址、栈名、状态在这里）。
    const HEAD_CHARS: usize = 180;
    /// 超限时保留的**尾部**字数 —— 必须留：boring 的判定结论（`reason: "HTTP_REQUEST"`
    /// 这类）在 Debug 输出的**最末尾**，只截头部会得到一条「很长但看不出原因」的日志。
    const TAIL_CHARS: usize = 180;

    let full = format!("{e:#}");
    let chars: Vec<char> = full.chars().collect();
    let mut out = String::with_capacity(full.len().min(MAX_CHARS * 4));
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '[' {
            let mut j = i + 1;
            let mut digits = 0usize;
            while j < chars.len()
                && (chars[j].is_ascii_digit() || chars[j] == ',' || chars[j] == ' ')
            {
                if chars[j].is_ascii_digit() {
                    digits += 1;
                }
                j += 1;
            }
            if digits > ARRAY_DIGITS && j < chars.len() && chars[j] == ']' {
                out.push_str("[…字节已折叠…]");
                i = j + 1;
                continue;
            }
        }
        out.push(chars[i]);
        i += 1;
    }

    let folded: Vec<char> = out.chars().collect();
    if folded.len() <= MAX_CHARS {
        return out;
    }
    let head: String = folded[..HEAD_CHARS].iter().collect();
    let tail: String = folded[folded.len() - TAIL_CHARS..].iter().collect();
    format!("{head}…[中略 {n} 字]…{tail}", n = folded.len() - HEAD_CHARS - TAIL_CHARS)
}

#[cfg(test)]
mod reason_tests {
    use super::*;

    /// 与 boring 实际形状一致的错误：中间塞满「ClientHello 字节数组」，判定结论在**末尾**。
    /// 断言：字节被折叠、结论留住、单行有上限。
    #[test]
    fn folds_byte_arrays_and_keeps_the_reason() {
        let mut dump = String::from("[22, 3, 1, 1, 158, 1, 0, 1, 154, 3, 3,");
        for i in 0..400 {
            dump.push_str(&format!(" {i},"));
        }
        dump.push_str(" 0]");
        // 结构刻意与真实报文一致：**字节数组在前**（所以要落在头部的 180 字里），
        // 中间塞长文本把总长顶过 375（触发中略），判定结论在**末尾**。
        let filler = "stream ".repeat(80);
        let e = anyhow::anyhow!(
            "tls handshake failure: prefix={dump} {filler}\
             error: Error {{ code: SSL (1), cause: Some(Ssl(ErrorStack([Error {{ reason: \"HTTP_REQUEST\" }}]))) }}"
        );
        let s = handshake_failure_reason(&e);
        assert!(s.contains("HTTP_REQUEST"), "必须保留可诊断的原因：{s}");
        assert!(s.contains("字节已折叠"), "长字节数组必须被折叠：{s}");
        assert!(s.contains("中略"), "超长要中略（头+尾），实际：{s}");
        assert!(
            s.chars().count() <= 400,
            "单行必须有上限，实际 {}",
            s.chars().count()
        );
        // 折叠后不该再出现大段裸数组
        assert!(!s.contains("158, 1, 0, 1, 154"), "{s}");
    }

    /// 关键回归：只截头部会把 boring 写在**末尾**的判定结论丢掉 —— 那样日志又长又没结论。
    #[test]
    fn keeps_the_tail_where_boring_puts_the_verdict() {
        let e = anyhow::anyhow!(
            "{}reason: \"WRONG_VERSION_NUMBER\"",
            "Failure(MidHandshakeSslStream { ... }) ".repeat(30)
        );
        let s = handshake_failure_reason(&e);
        assert!(s.contains("中略"), "这一例必须触发中略：{s}");
        assert!(
            s.contains("WRONG_VERSION_NUMBER"),
            "尾部结论必须保留：{s}"
        );
    }

    /// 正常短错误原样保留（别把有用的诊断信息也吃掉）。
    #[test]
    fn keeps_short_errors_intact() {
        let e = anyhow::anyhow!("connection reset by peer");
        assert_eq!(handshake_failure_reason(&e), "connection reset by peer");
        // 短数组（如 [1, 2, 3]）不算字节转储
        let e2 = anyhow::anyhow!("bad alpn [1, 2, 3] in hello");
        assert_eq!(handshake_failure_reason(&e2), "bad alpn [1, 2, 3] in hello");
    }

    /// 超长但不是数组的错误也要被截断（不能让一条日志无界增长）。
    #[test]
    fn truncates_overlong_plain_text() {
        let e = anyhow::anyhow!("{}", "x".repeat(5000));
        let s = handshake_failure_reason(&e);
        assert!(s.chars().count() <= 400, "实际 {}", s.chars().count());
        assert!(s.contains("中略"), "{s}");
    }
}
