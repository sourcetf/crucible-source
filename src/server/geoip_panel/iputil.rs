//! GeoIP IP 工具函数（CIDR 匹配、规范化）。
use std::net::IpAddr;

pub fn ip_to_u128(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(v4) => u128::from(u32::from(v4)),
        IpAddr::V6(v6) => u128::from(u128::from(v6)),
    }
}

pub fn parse_cidr(cidr: &str) -> Option<(u128, u32)> {
    let (ip_s, bits_s) = cidr.split_once('/')?;
    let ip: IpAddr = ip_s.parse().ok()?;
    let bits: u32 = bits_s.parse().ok()?;
    if bits > 128 { return None; }
    Some((ip_to_u128(ip), bits))
}

pub fn cidr_contains(cidr: &str, ip: IpAddr) -> bool {
    parse_cidr(cidr)
        .map(|(base, bits)| {
            let mask = if bits == 0 { 0u128 } else { (u128::MAX << (128 - bits)) >> (128 - bits) };
            (ip_to_u128(ip) >> (128 - bits)) == (base >> (128 - bits)) && mask != 0
        })
        .unwrap_or(false)
}