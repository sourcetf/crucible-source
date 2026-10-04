//! IP parsing and normalization utilities.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Parse an IP string; returns None on invalid input.
pub fn parse_ip(s: &str) -> Option<IpAddr> {
    s.trim().parse().ok()
}

/// 把 v4-mapped 的 IPv6（`::ffff:a.b.c.d`）折回 IPv4；其余原样返回。
///
/// 为什么必须做：`IpAddr::from_str("::ffff:1.2.3.4")` 得到的是 **V6**，其字符串形
/// 也是 `::ffff:1.2.3.4`。covering 侧按地址族分流（v4 走 geoip/ipv4 表、v6 走 ipv6
/// 表），于是同一个地址带上 `::ffff:` 前缀后查不到任何 v4 数据 —— 面板表现为
/// 「库里有这个 IP，却查不出结果」。本项目其它入口（`rate_limit`/`access`/
/// `basic_auth`）早就把 v4-mapped 归一成 v4，这里与它们保持一致。
pub fn unmap_v4_mapped(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
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

/// 把 IPv4 前缀 `base/bits` 归一成**网络地址**（长度以下的位清零）。
///
/// 为什么必须清位：`10.0.0.1/8` 的语义是 `10.0.0.0/8`。若把 base 原样存下（面板追加
/// anycast 段就是这么做的），只要下游按「网络地址 ↔ 区间」用它（例如写成 start/end 行、
/// 或与别的 /8 做字符串比较），主机位就会让 `10.0.0.1..10.0.0.1` 这种「隐式 /32」
/// 生效，覆盖查询静默漏行。`bits > 32` 或 base 非法（含 `::ffff:..`、`fe80::1%eth0`
/// 这类非纯 v4 写法）一律返回 None，由调用方决定报错。
pub fn normalize_v4_prefix(base: &str, bits: u32) -> Option<String> {
    if bits > 32 {
        return None;
    }
    let v4: Ipv4Addr = base.trim().parse().ok()?;
    let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
    Some(Ipv4Addr::from(u32::from(v4) & mask).to_string())
}

/// 解析 `a.b.c.d/N` 或 `x::y/N`：base 必须是 IP 字面量、N 在该族位宽内。
/// 返回归一化后的 (地址, 前缀长)；v4-mapped 基址折回 v4。非法返回 None。
pub fn parse_cidr(s: &str) -> Option<(IpAddr, u8)> {
    let t = s.trim();
    // 裸 IP（没有 `/nn`）按**单点**处理（/32、/128）。
    // 为什么必须容忍：面板的手工覆盖里历史上存过裸 IP（旧 LIKE 语义时代），
    // 而 `normalize_cidr_prefix` 只对新写入生效 —— 库里存的旧行仍是裸形式。
    // 判成「非法 ⇒ 不匹配」会让那些覆盖静默失效（正是本轮要修的那类故障）。
    let (base, bits) = match t.split_once('/') {
        Some((b, p)) => (b.trim(), Some(p.trim().parse::<u8>().ok()?)),
        None => (t, None),
    };
    let addr = unmap_v4_mapped(base.parse::<IpAddr>().ok()?);
    let max = match addr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    let bits = bits.unwrap_or(max);
    if bits > max {
        return None;
    }
    Some((addr, bits))
}

/// 真·CIDR 包含判断（`ip` 是否落在 `cidr` 内）。
///
/// 为什么不能用字符串 LIKE：`10.0.0.0/8` 的编辑必须命中 `10.1.2.0/24` 的查询
/// （段级 errata），而 `1.2.3.4` 绝不能命中 `1.2.3.40/32` —— 原来
/// `?1 LIKE prefix || '%'` 两头都错（漏段、误命中更长的邻居）。
/// 基址的主机位不要求为零（先掩码再比较）；v4-mapped 两侧都折回 v4。
pub fn ip_in_cidr(cidr: &str, ip: IpAddr) -> bool {
    let Some((base, bits)) = parse_cidr(cidr) else {
        return false;
    };
    let ip = unmap_v4_mapped(ip);
    match (base, ip) {
        (IpAddr::V4(b), IpAddr::V4(i)) => {
            let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
            (u32::from(b) & mask) == (u32::from(i) & mask)
        }
        (IpAddr::V6(b), IpAddr::V6(i)) => {
            let mask = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
            (u128::from(b) & mask) == (u128::from(i) & mask)
        }
        _ => false,
    }
}

/// 把面板手工覆盖的 `prefix` 归一成 CIDR 字符串：单个 IP 补全长度（/32、/128），
/// 主机位清零，v4-mapped 折回 v4，大小写/压缩形式统一。
/// 非法（不是 IP、长度越界、带 `/` 但 base 不是纯 IP）返回 None —— 调用方必须拒绝落库。
pub fn normalize_cidr_prefix(s: &str) -> Option<String> {
    let t = s.trim();
    let (base, bits) = match t.split_once('/') {
        Some((b, p)) => (b.trim(), Some(p.trim().parse::<u8>().ok()?)),
        None => (t, None),
    };
    let addr = unmap_v4_mapped(base.parse::<IpAddr>().ok()?);
    match addr {
        IpAddr::V4(v4) => {
            let bits = bits.unwrap_or(32);
            if bits > 32 {
                return None;
            }
            let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
            Some(format!("{}/{}", Ipv4Addr::from(u32::from(v4) & mask), bits))
        }
        IpAddr::V6(v6) => {
            let bits = bits.unwrap_or(128);
            if bits > 128 {
                return None;
            }
            let mask = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
            Some(format!("{}/{}", Ipv6Addr::from(u128::from(v6) & mask), bits))
        }
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
    use std::net::{IpAddr, Ipv4Addr};

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

    /// v4-mapped 归一：带 `::ffff:` 的地址必须折回 v4，否则面板按地址族分流会漏掉 v4 数据。
    #[test]
    fn v4_mapped_unmaps_to_v4() {
        let m = |s: &str| unmap_v4_mapped(parse_ip(s).unwrap());
        assert_eq!(m("::ffff:1.2.3.4"), IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        // 纯 v4 / 纯 v6 不受影响。
        assert_eq!(m("1.2.3.4"), IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(m("2001:db8::1"), "2001:db8::1".parse::<IpAddr>().unwrap());
        // 只是「看起来像」但不属于 v4-mapped 段的 v6 不能被折叠。
        assert_eq!(m("::1"), "::1".parse::<IpAddr>().unwrap());
        assert_eq!(m("::fffe:1.2.3.4"), "::fffe:1.2.3.4".parse::<IpAddr>().unwrap());
    }

    /// 前缀归一：长度以下的位必须清零；/0、/32 边界；/33、非法、非纯 v4 一律 None。
    #[test]
    fn v4_prefix_normalization() {
        assert_eq!(normalize_v4_prefix("10.0.0.1", 8).as_deref(), Some("10.0.0.0"));
        assert_eq!(normalize_v4_prefix("10.0.0.255", 24).as_deref(), Some("10.0.0.0"));
        assert_eq!(normalize_v4_prefix("192.168.1.130", 25).as_deref(), Some("192.168.1.128"));
        assert_eq!(normalize_v4_prefix("10.0.0.1", 0).as_deref(), Some("0.0.0.0"));
        assert_eq!(normalize_v4_prefix("255.255.255.255", 32).as_deref(), Some("255.255.255.255"));
        // 非网络地址在 /32 下保持不变（唯一合法主机位就是它本身）。
        assert_eq!(normalize_v4_prefix("10.0.0.1", 32).as_deref(), Some("10.0.0.1"));
        // 越界 / 非法 / 空 / 带空白 / v4-mapped / zone index ⇒ None
        assert_eq!(normalize_v4_prefix("10.0.0.0", 33), None);
        assert_eq!(normalize_v4_prefix("10.0.0.0/8", 8), None);
        assert_eq!(normalize_v4_prefix("", 8), None);
        assert_eq!(normalize_v4_prefix("not-an-ip", 8), None);
        assert_eq!(normalize_v4_prefix("::ffff:1.2.3.4", 24), None);
        assert_eq!(normalize_v4_prefix("fe80::1%eth0", 64), None);
    }

    /// 面板覆盖用的 CIDR 包含：段级命中、邻居不误命中、v4-mapped 归一、v6 一样工作。
    #[test]
    fn cidr_containment_is_true_network_math() {
        // 段级 errata：/8 的编辑必须命中 /24 里的查询点。
        assert!(ip_in_cidr("10.0.0.0/8", "10.1.2.3".parse().unwrap()));
        // 旧 LIKE 语义的两种错法都要被钉死：
        // 1) 存更宽的 /8 时 `merged.prefix LIKE '10.0.0.0/8%'` 恒假（漏命中）；
        assert!(!ip_in_cidr("1.2.3.4/32", "1.2.3.40".parse().unwrap()));
        // 2) 存 1.2.3.4 时旧 LIKE 会误命中 1.2.3.40。
        assert!(ip_in_cidr("1.2.3.4", "1.2.3.4".parse().unwrap()));
        // 基址主机位非零也按网段语义处理。
        assert!(ip_in_cidr("10.1.2.3/24", "10.1.2.200".parse().unwrap()));
        // /0 全匹配；越界长度/垃圾输入不匹配。
        assert!(ip_in_cidr("0.0.0.0/0", "203.0.113.9".parse().unwrap()));
        assert!(!ip_in_cidr("10.0.0.0/33", "10.0.0.1".parse().unwrap()));
        assert!(!ip_in_cidr("not-a-cidr", "10.0.0.1".parse().unwrap()));
        // v4-mapped 客户端按 v4 口径命中 v4 段。
        assert!(ip_in_cidr("10.0.0.0/8", "::ffff:10.1.2.3".parse().unwrap()));
        // v6：/48 段命中、邻居不命中。
        assert!(ip_in_cidr("2001:db8:1::/48", "2001:db8:1::5".parse().unwrap()));
        assert!(!ip_in_cidr("2001:db8:1::/48", "2001:db8:2::5".parse().unwrap()));
        // 不跨族匹配。
        assert!(!ip_in_cidr("2001:db8::/32", "10.0.0.1".parse().unwrap()));
    }

    /// 面板 prefix 归一：单点补长度、主机位清零、v6 压缩、非法拒绝。
    #[test]
    fn panel_prefix_normalization() {
        assert_eq!(normalize_cidr_prefix("10.0.0.1/8").as_deref(), Some("10.0.0.0/8"));
        assert_eq!(normalize_cidr_prefix("1.2.3.4").as_deref(), Some("1.2.3.4/32"));
        assert_eq!(normalize_cidr_prefix(" ::ffff:1.2.3.4 ").as_deref(), Some("1.2.3.4/32"));
        assert_eq!(
            normalize_cidr_prefix("2001:0db8::1/48").as_deref(),
            Some("2001:db8::/48")
        );
        assert_eq!(normalize_cidr_prefix("0.0.0.0/0").as_deref(), Some("0.0.0.0/0"));
        assert_eq!(normalize_cidr_prefix("10.0.0.0/33"), None);
        assert_eq!(normalize_cidr_prefix("2001:db8::/129"), None);
        assert_eq!(normalize_cidr_prefix("10.0.0.0/"), None);
        assert_eq!(normalize_cidr_prefix("%"), None);
        assert_eq!(normalize_cidr_prefix("10.0.0"), None);
        assert_eq!(normalize_cidr_prefix(""), None);
    }
}
