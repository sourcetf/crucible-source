//! IP parsing and normalization utilities.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Parse an IP string; returns None on invalid input.
pub fn parse_ip(s: &str) -> Option<IpAddr> {
    s.trim().parse().ok()
}

/// IPv4 → u32 host order for numeric range compares (TEXT lex order is wrong).
pub fn ipv4_to_u32(s: &str) -> Option<u32> {
    s.trim().parse::<Ipv4Addr>().ok().map(u32::from)
}

/// Format u32 as dotted IPv4.
pub fn u32_to_ipv4(n: u32) -> String {
    Ipv4Addr::from(n).to_string()
}


/// IPv6 → u128 host order for numeric range compares.
pub fn ipv6_to_u128(s: &str) -> Option<u128> {
    s.trim().parse::<Ipv6Addr>().ok().map(u128::from)
}

/// `ipv4`/`ipv6` 两张 range 表 `start_i`/`end_i` 列的数值键。
///
/// IPv4：地址的 u32 值（i64 装得下，无需偏移）。
/// IPv6：128 位放不进 SQLite 的 i64，取**高 64 位**并按 `hi ^ 2^63` 映射 ——
/// 该映射保序，因此 `start_i <= key <= end_i` 是「落在区间内」的**必要**条件，
/// 可走 `idx_*_numeric` 索引把候选行压到极少数；精确的 128 位包含判定仍由
/// `ipv6_in_range` 在 Rust 侧完成（必要条件放行多余行，但绝不漏行）。
///
/// Python 侧 `geoip_common.range_numeric_key` 必须与此逐位一致，否则新导入的行查不到。
pub fn range_numeric_key(s: &str) -> Option<i64> {
    match parse_ip(s)? {
        IpAddr::V4(v4) => Some(i64::from(u32::from(v4))),
        IpAddr::V6(v6) => {
            let hi = (u128::from(v6) >> 64) as u64;
            Some((hi ^ (1u64 << 63)) as i64)
        }
    }
}

/// True when `ip` is inside inclusive IPv6 `[start, end]` (numeric, form-normalized).
pub fn ipv6_in_range(ip: &str, start: &str, end: &str) -> bool {
    match (ipv6_to_u128(ip), ipv6_to_u128(start), ipv6_to_u128(end)) {
        (Some(i), Some(a), Some(b)) => i >= a && i <= b,
        _ => false,
    }
}

/// True when `ip` is inside inclusive dotted-quad `[start, end]` (numeric).
pub fn ipv4_in_range(ip: &str, start: &str, end: &str) -> bool {
    match (ipv4_to_u32(ip), ipv4_to_u32(start), ipv4_to_u32(end)) {
        (Some(i), Some(a), Some(b)) => i >= a && i <= b,
        _ => false,
    }
}

/// Normalize IPv6 to canonical compressed form; IPv4 unchanged.
pub fn normalize_ip(addr: IpAddr) -> String {
    match addr {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => canonical_ipv6(v6).to_string(),
    }
}

fn canonical_ipv6(v6: Ipv6Addr) -> Ipv6Addr {
    let segments = v6.segments();
    let mut best_start = 0usize;
    let mut best_len = 0usize;
    let mut cur_start = 0usize;
    let mut cur_len = 0usize;
    for (i, &seg) in segments.iter().enumerate() {
        if seg == 0 {
            if cur_len == 0 {
                cur_start = i;
            }
            cur_len += 1;
            if cur_len > best_len {
                best_len = cur_len;
                best_start = cur_start;
            }
        } else {
            cur_len = 0;
        }
    }
    if best_len < 2 {
        return v6;
    }
    let mut out = String::new();
    for (i, &seg) in segments.iter().enumerate() {
        if i == best_start {
            out.push_str("::");
            continue;
        }
        if i > best_start && i < best_start + best_len {
            continue;
        }
        if !out.is_empty() && !out.ends_with("::") {
            out.push(':');
        }
        out.push_str(&format!("{seg:x}"));
    }
    out.parse().unwrap_or(v6)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_numeric_order() {
        assert!(ipv4_to_u32("1.2.4.8").unwrap() > ipv4_to_u32("1.2.4.0").unwrap());
        assert!(ipv4_to_u32("1.2.4.8").unwrap() < ipv4_to_u32("1.2.4.255").unwrap());
        // Lexicographic trap: "9.0.0.0" > "10.0.0.0" as text, but numeric is smaller.
        assert!(ipv4_to_u32("9.0.0.0").unwrap() < ipv4_to_u32("10.0.0.0").unwrap());
        assert!(ipv4_in_range("1.2.4.8", "1.2.4.0", "1.2.4.255"));
        assert!(!ipv4_in_range("1.2.5.0", "1.2.4.0", "1.2.4.255"));
    }

    #[test]
    fn ipv6_numeric_order() {
        assert!(ipv6_in_range("2001:db8::2", "2001:db8::1", "2001:db8::ff"));
        assert!(!ipv6_in_range("2001:db8::1000", "2001:db8::1", "2001:db8::ff"));
        // Compressed vs expanded must agree.
        assert!(ipv6_in_range(
            "2001:0db8:0000:0000:0000:0000:0000:0002",
            "2001:db8::1",
            "2001:db8::ff",
        ));
    }

    #[test]
    fn range_key_ipv4_is_direct() {
        assert_eq!(range_numeric_key("10.0.0.0"), Some(167_772_160));
        assert_eq!(range_numeric_key("0.0.0.0"), Some(0));
        assert_eq!(
            range_numeric_key("255.255.255.255"),
            Some(i64::from(u32::MAX))
        );
        assert_eq!(range_numeric_key("not-an-ip"), None);
    }

    #[test]
    fn range_key_ipv6_preserves_order() {
        // 高 64 位相同者同键；键随地址单调不减（跨 8000::/1 边界也要成立）。
        let k = |s: &str| range_numeric_key(s).unwrap();
        assert_eq!(k("2001:db8::1"), k("2001:db8::ff"));
        assert!(k("::") < k("2001:db8::"));
        assert!(k("2001:db8::") < k("8000::"));
        assert!(k("7fff:ffff:ffff:ffff::") < k("8000::"));
        assert!(k("8000::") < k("ffff:ffff:ffff:ffff::"));
        // 必要条件：区间内的点，其键必落在 [start_i, end_i] 内。
        let (s, e, q) = ("2001:db8::", "2001:db8:ffff::", "2001:db8:8000::1");
        assert!(k(s) <= k(q) && k(q) <= k(e));
    }

    /// 跨语言互锁：这些字面量由 Python `geoip_common.range_numeric_key` 算出
    /// （scripts 侧 `_verify_range.py` 输出）。两侧必须逐位一致，否则导入脚本写的
    /// 行在查询侧会因数值过滤而查不到 —— 改动任一侧都必须同步改另一侧。
    #[test]
    fn range_key_matches_python_literals() {
        let cases: &[(&str, i64)] = &[
            ("10.0.0.0", 167_772_160),
            ("255.255.255.255", 4_294_967_295),
            ("::", -9_223_372_036_854_775_808),
            ("8000::", 0),
            ("2001:db8::", -6_917_232_468_739_227_648),
            ("2001:db8::ffff", -6_917_232_468_739_227_648),
            ("7fff:ffff:ffff:ffff::", -1),
            ("ffff:ffff:ffff:ffff::", 9_223_372_036_854_775_807),
        ];
        for (ip, want) in cases {
            assert_eq!(range_numeric_key(ip), Some(*want), "range key mismatch for {ip}");
        }
    }
}
