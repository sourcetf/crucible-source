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
pub fn add_anycast_prefix(base: &str, bits: u32) -> anyhow::Result<()> {
    let b: std::net::Ipv4Addr = base
        .trim()
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid anycast base {base:?}: {e}"))?;
    if bits > 32 {
        anyhow::bail!("v4 prefix length must be <= 32");
    }
    EXTRA_ANYCAST.lock().push((b.to_string(), bits));
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

pub fn is_anycast(ip: IpAddr) -> bool {
    let IpAddr::V4(v4) = ip else {
        return false;
    };
    let n = u32::from(v4);
    for (base, bits) in ANYCAST_V4 {
        if let Ok(b) = base.parse::<std::net::Ipv4Addr>() {
            let mask = if *bits >= 32 {
                u32::MAX
            } else {
                u32::MAX << (32 - bits)
            };
            if (n & mask) == (u32::from(b) & mask) {
                return true;
            }
        }
    }
    // P2-16：面板追加段一并参与判定。
    for (base, bits) in EXTRA_ANYCAST.lock().iter() {
        if let Ok(b) = base.parse::<std::net::Ipv4Addr>() {
            let mask = if *bits >= 32 {
                u32::MAX
            } else {
                u32::MAX << (32 - bits)
            };
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
