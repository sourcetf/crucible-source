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
}
