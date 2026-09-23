//! IP allow/deny access control.

use crate::config::IpAccessConfig;
use std::net::{IpAddr, SocketAddr};

/// Returns true if the peer is allowed.
/// 规则：若 allow 非空则必须命中 allow；deny 命中则拒绝（deny 优先于 allow 之外的默认放行）。
pub fn is_allowed(cfg: &IpAccessConfig, peer: SocketAddr) -> bool {
    // ::ffff:x.y.z.w 归一化为 IPv4，避免 deny 10.0.0.0/8 被 v4-mapped v6 绕过。
    let ip = match peer.ip() {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v => v,
    };
    if cfg.deny.iter().any(|p| cidr_or_exact(p, ip)) {
        return false;
    }
    if cfg.allow.is_empty() {
        return true;
    }
    cfg.allow.iter().any(|p| cidr_or_exact(p, ip))
}

pub fn deny_response() -> (http::StatusCode, &'static str) {
    (http::StatusCode::FORBIDDEN, "forbidden by ip_access")
}

/// 浏览器跨站请求判定（`Sec-Fetch-Site: cross-site`）——admin 路径的 CSRF 补强。
///
/// 为什么放在 h1/h2/h3 而不是只靠 admin.rs：`admin.rs` 的 CSRF 检查形如
/// 「若存在 `Origin` 头则比对 Host」，**缺 `Origin` 时整段跳过**，而且它只覆盖
/// POST/PUT/DELETE/PATCH —— GET 从不带 `Origin`，所以跨站 GET（`<img>`/`<script>`
/// 触发，浏览器会给带缓存 Basic 凭据的同源请求自动附上凭据）完全没有防线。
/// `Sec-Fetch-Site` 由浏览器自己写入、脚本改不了，且对**所有**方法都发；
/// 管理面 UI 恒为 `same-origin`（用户在地址栏直接打开是 `none`），
/// 而非浏览器客户端（curl/运维脚本）根本不带这个头 —— 保持 admin.rs 注释里
/// 「非浏览器请求由 Basic 凭据本身鉴权」的既有策略，不会把自动化挡在门外。
pub fn cross_site_blocked(headers: &http::HeaderMap) -> bool {
    headers
        .get("sec-fetch-site")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("cross-site"))
}

/// 跨站请求被拒时的状态码/文案（三协议共用，保持响应一致）。
pub fn cross_site_response() -> (http::StatusCode, &'static str) {
    (http::StatusCode::FORBIDDEN, "cross-site request blocked")
}

fn cidr_or_exact(pattern: &str, ip: IpAddr) -> bool {
    let pattern = pattern.trim();
    if pattern.is_empty() || pattern == "*" {
        return true;
    }
    if let Some((net, bits)) = pattern.split_once('/') {
        let Ok(base) = net.parse::<IpAddr>() else {
            return false;
        };
        let Ok(prefix) = bits.parse::<u8>() else {
            return false;
        };
        return ip_in_cidr(ip, base, prefix);
    }
    match pattern.parse::<IpAddr>() {
        Ok(p) => p == ip,
        Err(_) => false,
    }
}

fn ip_in_cidr(ip: IpAddr, base: IpAddr, prefix: u8) -> bool {
    match (ip, base) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            if prefix > 32 {
                return false;
            }
            let mask = if prefix == 0 {
                0u32
            } else {
                u32::MAX << (32 - prefix)
            };
            (u32::from(a) & mask) == (u32::from(b) & mask)
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            if prefix > 128 {
                return false;
            }
            let a = u128::from(a);
            let b = u128::from(b);
            let mask = if prefix == 0 {
                0u128
            } else {
                u128::MAX << (128 - prefix)
            };
            (a & mask) == (b & mask)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[test]
    fn allow_exact() {
        let cfg = IpAccessConfig {
            allow: vec!["127.0.0.1".into()],
            deny: vec![],
        };
        let peer: SocketAddr = "127.0.0.1:1".parse().unwrap();
        assert!(is_allowed(&cfg, peer));
        let peer2: SocketAddr = "10.0.0.1:1".parse().unwrap();
        assert!(!is_allowed(&cfg, peer2));
    }

    #[test]
    fn deny_cidr() {
        let cfg = IpAccessConfig {
            allow: vec![],
            deny: vec!["10.0.0.0/8".into()],
        };
        assert!(!is_allowed(&cfg, "10.1.2.3:9".parse().unwrap()));
        assert!(is_allowed(&cfg, "192.168.0.1:9".parse().unwrap()));
    }

    /// 只拦 cross-site：同源/无该头（非浏览器客户端）一律放行。
    #[test]
    fn cross_site_only_blocks_cross_site() {
        use http::HeaderValue;
        let mut h = http::HeaderMap::new();
        assert!(!cross_site_blocked(&h), "no header must not block (curl/脚本)");
        h.insert("sec-fetch-site", HeaderValue::from_static("same-origin"));
        assert!(!cross_site_blocked(&h));
        h.insert("sec-fetch-site", HeaderValue::from_static("none"));
        assert!(!cross_site_blocked(&h));
        h.insert("sec-fetch-site", HeaderValue::from_static("same-site"));
        assert!(!cross_site_blocked(&h));
        h.insert("sec-fetch-site", HeaderValue::from_static("Cross-Site"));
        assert!(cross_site_blocked(&h));
    }
}
