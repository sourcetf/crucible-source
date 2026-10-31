//! Anycast CIDR detection and geo field suppression (§23.5.6).

use once_cell::sync::Lazy;
use parking_lot::Mutex;
use rusqlite::Connection;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// §2.6：anycast 表（bgptools / RIPE anycast 提取写入）优先；无表/无命中回落内置种子。
///
/// 表里两类行都要判：v4 行按 u32 比较，v6 行按 u128 比较。旧实现只解析 v4，
/// 表里的 IPv6 anycast 段**永远不会命中**（v6 客户端直接回落只含 4 条 v4 的内置种子）。
pub fn is_anycast_conn(conn: &Connection, ip: IpAddr) -> bool {
    // 与 rate_limit/access/basic_auth 同口径：v4-mapped 客户端先折回 v4，否则会被
    // 当成纯 v6 去扫 v6 行，内置的 8.8.8.0/24 等永远不命中。
    let ip = crate::server::geoip_panel::iputil::unmap_v4_mapped(ip);
    match anycast_table_hit(conn, ip) {
        Ok(hit) => hit || is_anycast(ip),
        Err(_) => is_anycast(ip),
    }
}

/// 扫 anycast 表判断 ip 是否落在任一区间（v4 行与 v6 行分别按地址族解析）。
///
/// 性能：Python `init_schema` 现在写入 `start_i`/`end_i` 数值列 + `idx_anycast_numeric`；
/// 有该列时用「数值键 → 必要区间」把候选行压到极少数（v6 用高 64 位保序映射，
/// 精确 128 位判定仍在下面做）。老库没有这两列时 prepare 失败，自动回落全表扫描，
/// 行为不变。此前每次 lookup 都全表扫描 + 逐行 `parse`，5000 个不同客户端 IP 会把
/// anycast 表扫 5000 遍（U-17 压测里的主要冷查询成本之一）。
fn anycast_table_hit(conn: &Connection, ip: IpAddr) -> rusqlite::Result<bool> {
    let ip_s = ip.to_string();
    let key = crate::server::geoip_panel::iputil::range_numeric_key(&ip_s).unwrap_or(0);
    if let Ok(mut stmt) = conn.prepare(
        "SELECT start, end FROM anycast
         WHERE start_i IS NULL OR (start_i <= ?1 AND end_i >= ?1)",
    ) {
        let rows = stmt.query_map([key], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        for row in rows {
            let (s, e) = row?;
            if range_hit(ip, &s, &e) {
                return Ok(true);
            }
        }
        return Ok(false);
    }
    // 兼容老库（没有 start_i/end_i 列）。
    let mut stmt = conn.prepare("SELECT start, end FROM anycast")?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    for row in rows {
        let (s, e) = row?;
        if range_hit(ip, &s, &e) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// 精确区间判定（文本起止 → 对应地址族数值比较）。
fn range_hit(ip: IpAddr, start: &str, end: &str) -> bool {
    match ip {
        IpAddr::V4(v4) => match (start.parse::<Ipv4Addr>(), end.parse::<Ipv4Addr>()) {
            (Ok(a), Ok(b)) => u32::from(v4) >= u32::from(a) && u32::from(v4) <= u32::from(b),
            _ => false,
        },
        IpAddr::V6(v6) => match (start.parse::<Ipv6Addr>(), end.parse::<Ipv6Addr>()) {
            (Ok(a), Ok(b)) => u128::from(v6) >= u128::from(a) && u128::from(v6) <= u128::from(b),
            _ => false,
        },
    }
}

/// Well-known anycast / CDN prefixes (RIR 提取集的内置种子).
const ANYCAST_V4: &[(&str, u32)] = &[
    ("1.1.1.0", 24),
    ("8.8.8.0", 24),
    ("9.9.9.0", 24),
    ("208.67.222.0", 24),
];

/// P2-16（§23.5.6）：anycast 集可由面板追加（旧实现硬编码 4 条、无法扩展）。
static EXTRA_ANYCAST: Lazy<Mutex<Vec<(String, u32)>>> = Lazy::new(|| Mutex::new(Vec::new()));

/// 面板追加 anycast 前缀（base=网络地址, bits=前缀长；v4）。
///
/// base 必须先归一到**网络地址**再存：`is_anycast` 现在两边都套掩码，匹配不受影响，
/// 但存下的字符串会经 `anycast_prefixes()` 外泄给下游（面板展示 / 写回 anycast 表 /
/// 生成视图）；原样存 `10.0.0.1/8` 一旦被当成区间起点就退化成「隐式 /32」，
/// 覆盖查询静默漏行。归一化与校验都走 iputil，保证与查询侧同一套口径。
// G-19：这两个函数目前**没有 HTTP/面板调用点**（§2.6 的「面板追加 anycast」
// 功能尚未接线，anycast 表由离线脚本写入）。保留为进程内 API 并用 allow 标注，
// 而不是删除：`is_anycast` 已经消费 EXTRA_ANYCAST，接线时只需要一个 handler。
#[allow(dead_code)]
pub fn add_anycast_prefix(base: &str, bits: u32) -> anyhow::Result<()> {
    let net = crate::server::geoip_panel::iputil::normalize_v4_prefix(base, bits)
        .ok_or_else(|| anyhow::anyhow!("invalid anycast prefix {base:?}/{bits}"))?;
    EXTRA_ANYCAST.lock().push((net, bits));
    Ok(())
}

/// 当前生效的 anycast 前缀表（内置种子 + 面板追加）。
#[allow(dead_code)] // 见 add_anycast_prefix 的说明（面板端点未接线）。
pub fn anycast_prefixes() -> Vec<(String, u32)> {
    let mut out: Vec<(String, u32)> = ANYCAST_V4
        .iter()
        .map(|(b, n)| ((*b).to_string(), *n))
        .collect();
    out.extend(EXTRA_ANYCAST.lock().iter().cloned());
    out
}

/// IPv4 前缀掩码：`/0` → 0（匹配全部），`>= /32` → u32::MAX，其余左移 `(32 - bits)`。
/// 注意：对 `u32::MAX` 直接左移 32 位会触发移位溢出 panic（debug）/错误结果，
/// 因此 bits==0 必须单独处理。
fn v4_mask(bits: u32) -> u32 {
    if bits == 0 {
        0
    } else if bits >= 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - bits)
    }
}

pub fn is_anycast(ip: IpAddr) -> bool {
    let IpAddr::V4(v4) = ip else {
        return false;
    };
    let n = u32::from(v4);
    for (base, bits) in ANYCAST_V4 {
        if let Ok(b) = base.parse::<std::net::Ipv4Addr>() {
            let mask = v4_mask(*bits);
            if (n & mask) == (u32::from(b) & mask) {
                return true;
            }
        }
    }
    // P2-16：面板追加段一并参与判定。
    for (base, bits) in EXTRA_ANYCAST.lock().iter() {
        if let Ok(b) = base.parse::<std::net::Ipv4Addr>() {
            let mask = v4_mask(*bits);
            if (n & mask) == (u32::from(b) & mask) {
                return true;
            }
        }
    }
    false
}

/// When anycast or country conflict, suppress city-level fields.
pub fn suppress_locality(country_conflict: bool, anycast: bool) -> bool {
    country_conflict || anycast
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    /// 掩码边界：/0 匹配全部、/32 精确、中间左移；`>= 32` 不能触发移位溢出。
    #[test]
    fn v4_mask_boundaries() {
        assert_eq!(v4_mask(0), 0);
        assert_eq!(v4_mask(8), 0xff00_0000);
        assert_eq!(v4_mask(24), 0xffff_ff00);
        assert_eq!(v4_mask(32), u32::MAX);
        assert_eq!(v4_mask(64), u32::MAX); // 越界不得 panic
    }

    #[test]
    fn seed_prefixes_match() {
        // 种子表内的地址命中，表外不命中。
        assert!(is_anycast(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        assert!(is_anycast(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!is_anycast(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        // 目前不处理 v6（保持既有行为，不误报）。
        assert!(!is_anycast("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn suppress_rule() {
        assert!(!suppress_locality(false, false));
        assert!(suppress_locality(true, false));
        assert!(suppress_locality(false, true));
    }

    /// 表里的 v6 行必须参与判定（旧实现 v6 直接回落内置 v4 种子 = 永不命中）；
    /// v4-mapped 客户端折回 v4，既能命中表里的 v4 行、也能回落内置种子。
    #[test]
    fn anycast_table_v6_rows_match() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE anycast(start TEXT, end TEXT);
             INSERT INTO anycast VALUES('2606:4700::','2606:4700:ffff:ffff:ffff:ffff:ffff:ffff');
             INSERT INTO anycast VALUES('198.51.100.0','198.51.100.255');",
        )
        .unwrap();
        assert!(is_anycast_conn(&conn, "2606:4700::1111".parse().unwrap()));
        assert!(!is_anycast_conn(&conn, "2606:4701::1".parse().unwrap()));
        assert!(is_anycast_conn(&conn, "198.51.100.7".parse().unwrap()));
        assert!(is_anycast_conn(&conn, "::ffff:198.51.100.7".parse().unwrap()));
        assert!(is_anycast_conn(&conn, "::ffff:8.8.8.8".parse().unwrap()));
    }

    /// 新 schema（start_i/end_i + 索引）走数值预过滤，命中/不命中与全表扫描一致；
    /// v6 的数值键必须与 Python `range_numeric_key` 同口径，否则 v6 anycast 行
    /// 会被 `start_i <= key <= end_i` 预过滤直接排掉（合法数据静默丢失）。
    #[test]
    fn anycast_table_numeric_columns_match() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE anycast(
                 start TEXT, end TEXT, bits INTEGER, prefix TEXT, source TEXT,
                 commit_unix INTEGER, start_i INTEGER, end_i INTEGER);
             CREATE INDEX idx_anycast_numeric ON anycast(start_i, end_i);",
        )
        .unwrap();
        let cases = [
            (
                "2606:4700::",
                "2606:4700:ffff:ffff:ffff:ffff:ffff:ffff",
            ),
            ("198.51.100.0", "198.51.100.255"),
            ("2001:db8::", "2001:db8::ffff"),
        ];
        for (s, e) in cases {
            let si = crate::server::geoip_panel::iputil::range_numeric_key(s).unwrap();
            let ei = crate::server::geoip_panel::iputil::range_numeric_key(e).unwrap();
            conn.execute(
                "INSERT INTO anycast(start,end,start_i,end_i) VALUES(?1,?2,?3,?4)",
                rusqlite::params![s, e, si, ei],
            )
            .unwrap();
        }
        assert!(is_anycast_conn(&conn, "2606:4700::1111".parse().unwrap()));
        assert!(is_anycast_conn(&conn, "2001:db8::42".parse().unwrap()));
        assert!(is_anycast_conn(&conn, "198.51.100.7".parse().unwrap()));
        assert!(is_anycast_conn(&conn, "::ffff:198.51.100.7".parse().unwrap()));
        assert!(!is_anycast_conn(&conn, "2606:4701::1".parse().unwrap()));
        assert!(!is_anycast_conn(&conn, "203.0.113.1".parse().unwrap()));
    }
}
