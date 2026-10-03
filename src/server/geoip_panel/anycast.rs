//! Anycast CIDR detection and geo field suppression (§23.5.6).

use once_cell::sync::Lazy;
use parking_lot::Mutex;
use rusqlite::Connection;
use std::net::IpAddr;

/// §2.6：anycast 表（bgptools / RIPE anycast 提取写入）优先；无表/无命中回落内置种子。
pub fn is_anycast_conn(conn: &Connection, ip: IpAddr) -> bool {
    let IpAddr::V4(v4) = ip else {
        return is_anycast(ip);
    };
    let n = u32::from(v4);
    let q = || -> rusqlite::Result<bool> {
        let mut stmt = conn.prepare("SELECT start, end FROM anycast")?;
        let rows = stmt.query_map([], |row| {
            let s: String = row.get(0)?;
            let e: String = row.get(1)?;
            Ok((s, e))
        })?;
        for row in rows {
            let (s, e) = row?;
            let Ok(s) = s.parse::<std::net::Ipv4Addr>() else {
                continue;
            };
            let Ok(e) = e.parse::<std::net::Ipv4Addr>() else {
                continue;
            };
            if n >= u32::from(s) && n <= u32::from(e) {
                return Ok(true);
            }
        }
        Ok(false)
    };
    match q() {
        Ok(hit) => hit || is_anycast(ip),
        Err(_) => is_anycast(ip),
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
pub fn add_anycast_prefix(base: &str, bits: u32) -> anyhow::Result<()> {
    let net = crate::server::geoip_panel::iputil::normalize_v4_prefix(base, bits)
        .ok_or_else(|| anyhow::anyhow!("invalid anycast prefix {base:?}/{bits}"))?;
    EXTRA_ANYCAST.lock().push((net, bits));
    Ok(())
}

/// 当前生效的 anycast 前缀表（内置种子 + 面板追加）。
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
}
