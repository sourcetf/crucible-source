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

/// 请求路径是否属于管理面：**必须带段边界**。
///
/// `admin.path` 默认 `/__admin`（校准时会去掉尾斜杠），于是裸 `starts_with` 会让
/// `/__adminX/api/files` 也进管理分发 —— 而 `admin.rs` 内部的判定是
/// `path.ends_with("/api/files")` 这类**后缀**匹配，于是文件管理器 API 在配置的
/// 管理前缀之外也能被调（安全边界仍靠 Basic + CSRF，但运维常在前置代理上用
/// `location /__admin/` 把管理面挡在公网之外 —— 绕过点正是这里）。
pub fn is_admin_path(admin_path: &str, path: &str) -> bool {
    if path == admin_path {
        return true;
    }
    let with_slash = format!("{}/", admin_path.trim_end_matches('/'));
    path.starts_with(&with_slash)
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
    // 只有显式 `*` 才等于「匹配所有地址」。空串/纯空白**绝不能**走这条分支：
    // `allow = [""]` 会因此变成「放行所有地址」（白名单被静默解除），
    // 而配置期那道拦截一旦被绕过（例如以后新增一条直接构造 IpAccessConfig 的路径），
    // 运行期就必须自己 fail-closed。与 config.rs 对「非法条目永不匹配」的说明保持一致。
    if pattern == "*" {
        return true;
    }
    if pattern.is_empty() {
        return false;
    }
    if let Some((net, bits)) = pattern.split_once('/') {
        // 两侧都必须 trim：配置期校验（`config::ip_access_entry_is_valid`）对
        // `"10.0.0.0/ 8"`、`"10.0.0.0 /8"` 是**接受**的（它分别 trim 了两侧），
        // 而这里原先只 trim 整个 pattern，于是 `"10.0.0.0 "` / `" 8"` 都 parse 失败
        // ⇒ 该条目运行期**恒不匹配**。实测：`deny = ["203.0.113.0/ 24"]` 对
        // 203.0.113.9 直接放行（封禁静默失效，还不在加载期报错）。
        let Ok(base) = net.trim().parse::<IpAddr>() else {
            return false;
        };
        let Ok(prefix) = bits.trim().parse::<u8>() else {
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

    /// 空/纯空白条目必须「永不匹配」而不是「匹配所有地址」：否则 `allow = [""]`
    /// 等于白名单被静默解除（fail-open），`deny = [""]` 则等于自封全站。
    #[test]
    fn empty_entry_never_matches() {
        assert!(!cidr_or_exact("", "10.0.0.1".parse().unwrap()));
        assert!(!cidr_or_exact("   ", "10.0.0.1".parse().unwrap()));
        assert!(cidr_or_exact("*", "10.0.0.1".parse().unwrap()));
        let cfg = IpAccessConfig {
            allow: vec!["".into()],
            deny: vec![],
        };
        // allow 非空却没有任何条目匹配 ⇒ 拒绝（fail-closed），而不是放行所有人。
        assert!(!is_allowed(&cfg, "10.0.0.1:9".parse().unwrap()));
    }

    /// CIDR 条目两侧的空白必须被容忍 —— 配置期校验（`config::ip_access_entry_is_valid`）
    /// 对 `"10.0.0.0/ 8"` / `"10.0.0.0 /8"` 是接受的，运行期若 parse 失败就是
    /// 「配置通过、规则恒不匹配」：`deny` 静默失效（安全），`allow` 静默全员拒绝（可用性）。
    #[test]
    fn cidr_tolerates_inner_whitespace_like_config_validation() {
        let peer: SocketAddr = "10.1.2.3:9".parse().unwrap();
        for rule in ["10.0.0.0/8", "10.0.0.0/ 8", "10.0.0.0 /8", "10.0.0.0 / 8"] {
            assert!(
                !is_allowed(
                    &IpAccessConfig { allow: vec![], deny: vec![rule.into()] },
                    peer
                ),
                "deny {rule:?} 必须生效（此前带内部空白时静默放行）"
            );
        }
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

#[cfg(test)]
mod admin_path_tests {
    use super::is_admin_path;

    #[test]
    fn admin_path_needs_a_segment_boundary() {
        assert!(is_admin_path("/__admin", "/__admin"));
        assert!(is_admin_path("/__admin", "/__admin/"));
        assert!(is_admin_path("/__admin", "/__admin/api/files"));
        // 关键：同前缀的**别站**路径不算管理面
        assert!(!is_admin_path("/__admin", "/__adminX/api/files"));
        assert!(!is_admin_path("/__admin", "/__administrator"));
        // 前缀本身带尾斜杠也要正常
        assert!(is_admin_path("/__admin/", "/__admin/api"));
        assert!(!is_admin_path("/__admin/", "/__adminX"));
    }
}
