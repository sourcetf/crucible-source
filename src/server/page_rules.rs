//! Page rules (CDN-style). UI copy must not mention third-party brand names.
//!
//! 支持的 action(均为每 listener `[[listeners.page_rules]]` 或全局规则):
//! - `redirect`: 302 → target,可带 "301:" / "307:" / "308:" 前缀指定状态码
//! - `block`:    403
//! - `rewrite`:  路径前缀改写,target 为新前缀(match_url 前缀被替换)
//! - `pass`:     反向代理到 target(完整上游 URL;http:// → 不校验上游 TLS)
//! - `cache`:    响应加 Cache-Control(target 为指令值,缺省 public, max-age=3600)
//! - `header`:   响应加自定义响应头,target 为 "Name: value"

use crate::config::ListenerConfig;
use crate::server::h1::{full, BoxBody};
use http::{header, Request, Response, StatusCode};
use hyper::body::Incoming;

/// 立即响应类动作(redirect/block)的同步判定;rewrite/pass/cache/header 见其余入口。
pub fn apply(lc: &ListenerConfig, req: &Request<Incoming>) -> Option<Response<BoxBody>> {
    let path = req.uri().path();
    for rule in &lc.page_rules {
        if path_matches(&rule.match_url, path) {
            match rule.action.as_str() {
                "redirect" => {
                    return Some(redirect_response(
                        rule.target.clone().unwrap_or_else(|| "/".into()),
                    ));
                }
                "block" => {
                    return Some(
                        Response::builder()
                            .status(StatusCode::FORBIDDEN)
                            .body(full("blocked by page rule"))
                            .unwrap(),
                    );
                }
                "rewrite" | "pass" | "cache" | "header" => {
                    log::debug!("page_rule {} on {}", rule.action, path);
                }
                _ => {}
            }
        }
    }
    None
}

/// h2/h3 使用的简化版本:返回 (status, location, _) 三元组,由调用方组装响应。
pub fn apply_simple(lc: &ListenerConfig, path: &str) -> Option<(StatusCode, String)> {
    for rule in &lc.page_rules {
        if path_matches(&rule.match_url, path) {
            match rule.action.as_str() {
                "block" => return Some((StatusCode::FORBIDDEN, String::new())),
                "redirect" => {
                    let target = rule.target.clone().unwrap_or_else(|| "/".into());
                    let (status, loc) = match target.split_once(':') {
                        Some(("301", u)) => (StatusCode::MOVED_PERMANENTLY, u.to_string()),
                        Some(("307", u)) => (StatusCode::TEMPORARY_REDIRECT, u.to_string()),
                        Some(("308", u)) => (StatusCode::PERMANENT_REDIRECT, u.to_string()),
                        _ => (StatusCode::FOUND, target),
                    };
                    // 这个 API 只能返回 `(StatusCode, String)`，而 h2/h3 的调用方是
                    // `Response::builder().header(LOCATION, loc).body(..).unwrap()` 组装的
                    // —— `loc` 含控制字符时 `HeaderValue` 构造失败、`.body()` 直接 panic，
                    // **每个命中该规则的请求**都把连接打死（h1 那条路径早已降级为
                    // 「不带 Location 的 302」，这里漏了）。降级成「跳过这条规则」是这套签名
                    // 下唯一能表达「别写这个头」的方式，站点不会因为一个坏 target 全挂。
                    if http::header::HeaderValue::from_str(&loc).is_err() {
                        log::warn!(
                            "page_rules redirect: target 不能作为 Location 响应头，跳过该规则: {loc:?}"
                        );
                        continue;
                    }
                    return Some((status, loc));
                }
                _ => {}
            }
        }
    }
    None
}

fn redirect_response(target: String) -> Response<BoxBody> {
    // "301:URL" / "307:URL" / "308:URL" 形式可指定状态码,其余 302。
    let (status, loc) = match target.split_once(':') {
        Some(("301", u)) => (StatusCode::MOVED_PERMANENTLY, u.to_string()),
        Some(("307", u)) => (StatusCode::TEMPORARY_REDIRECT, u.to_string()),
        Some(("308", u)) => (StatusCode::PERMANENT_REDIRECT, u.to_string()),
        _ => (StatusCode::FOUND, target),
    };
    // **不 unwrap**：`HeaderValue` 拒绝控制字符与非 ASCII，而 `target` 来自配置/面板。
    // 手写配置里一个带换行或非 ASCII 的 target，会让**每一个命中该规则的请求**在 hyper 的
    // service future 里 panic（连接被直接丢弃，日志只有一行 panic）。非法值降级为
    // 「不带 Location 的 302」并把原因写日志 —— 站点不因此整条规则全挂。
    match Response::builder()
        .status(status)
        .header(header::LOCATION, loc.as_str())
        .body(full(""))
    {
        Ok(r) => r,
        Err(e) => {
            log::warn!(
                "page_rules redirect: target 不能作为 Location 响应头（{e}），降级为无 Location 的 302"
            );
            Response::builder()
                .status(StatusCode::FOUND)
                .body(full(""))
                .unwrap()
        }
    }
}

/// `rewrite` 动作:把 match_url 匹配的前缀替换为 target,返回新路径。
pub fn rewrite_path(lc: &ListenerConfig, path: &str) -> Option<String> {
    for rule in &lc.page_rules {
        if rule.action != "rewrite" {
            continue;
        }
        let Some(target) = rule.target.as_deref() else {
            continue;
        };
        if let Some(prefix) = rule.match_url.strip_suffix('*') {
            if let Some(suffix) = path.strip_prefix(prefix) {
                let base = target.trim_end_matches('/');
                if suffix.is_empty() {
                    return Some(base.to_string());
                }
                if suffix.starts_with('/') {
                    return Some(format!("{base}{suffix}"));
                }
                return Some(format!("{base}/{suffix}"));
            }
        } else if path == rule.match_url {
            return Some(target.to_string());
        }
    }
    None
}

/// `pass` 动作:返回 (match_url, upstream 基础 URL)。
/// path 合并交由 `proxy::proxy_page_rule` 按反代规则处理。
pub fn pass_upstream(lc: &ListenerConfig, path: &str) -> Option<(String, String)> {
    for rule in &lc.page_rules {
        if rule.action != "pass" {
            continue;
        }
        let Some(target) = rule.target.as_deref() else {
            continue;
        };
        if path_matches(&rule.match_url, path) {
            return Some((
                rule.match_url.clone(),
                target.trim_end_matches('/').to_string(),
            ));
        }
    }
    None
}

/// `cache`/`header` 动作产生的响应头(注入到最终响应)。
pub fn response_headers(lc: &ListenerConfig, path: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for rule in &lc.page_rules {
        if !path_matches(&rule.match_url, path) {
            continue;
        }
        match rule.action.as_str() {
            "cache" => {
                let v = rule
                    .target
                    .clone()
                    .unwrap_or_else(|| "public, max-age=3600".into());
                if v.bytes().any(|b| b < 0x20) {
                    continue;
                }
                out.push(("Cache-Control".into(), v));
            }
            "header" => {
                let Some(t) = rule.target.as_deref() else {
                    continue;
                };
                if let Some((name, value)) = t.split_once(':') {
                    let name = name.trim();
                    let value = value.trim();
                    // Reject CRLF / control chars — response header injection.
                    if name.is_empty()
                        || name.bytes().any(|b| b < 0x20 || b == b':')
                        || value.bytes().any(|b| b < 0x20)
                    {
                        continue;
                    }
                    out.push((name.to_string(), value.to_string()));
                }
            }
            _ => {}
        }
    }
    out
}

pub fn path_matches(pattern: &str, path: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        path.starts_with(prefix)
    } else {
        path == pattern
    }
}

/// Scrub forbidden brand strings from UI/API copy.
/// P2-9：任意大小写混合形态（CloudFlare/cloudFlare/CLOUDFLARE…）一并清洗；
/// 替换词按原词形态选择（含大写字母→CDN，纯小写→cdn）。按 UTF-8 字符边界推进。
pub fn scrub_brand(s: &str) -> String {
    const BRAND: &[u8] = b"cloudflare";
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if i + BRAND.len() <= bytes.len()
            && bytes[i..i + BRAND.len()]
                .iter()
                .zip(BRAND.iter())
                .all(|(a, b)| a.to_ascii_lowercase() == *b)
        {
            let word = &s[i..i + BRAND.len()];
            out.push_str(if word.bytes().any(|b| b.is_ascii_uppercase()) {
                "CDN"
            } else {
                "cdn"
            });
            i += BRAND.len();
        } else {
            let ch_len = s[i..].chars().next().map(|c| c.len_utf8()).unwrap_or(1);
            out.push_str(&s[i..i + ch_len]);
            i += ch_len;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lc_with(rules: Vec<crate::config::PageRuleConfig>) -> ListenerConfig {
        let mut lc = ListenerConfig::default();
        lc.page_rules = rules;
        lc
    }

    fn rule(m: &str, a: &str, t: Option<&str>) -> crate::config::PageRuleConfig {
        crate::config::PageRuleConfig {
            match_url: m.into(),
            action: a.into(),
            target: t.map(|s| s.into()),
        }
    }

    #[test]
    fn rewrite_prefix() {
        let lc = lc_with(vec![rule("/old/*", "rewrite", Some("/new"))]);
        assert_eq!(rewrite_path(&lc, "/old/a/b").as_deref(), Some("/new/a/b"));
        assert_eq!(rewrite_path(&lc, "/other/"), None);
    }

    #[test]
    fn pass_upstream_and_suffix() {
        let lc = lc_with(vec![rule("/api/*", "pass", Some("http://127.0.0.1:8080"))]);
        let (murl, up) = pass_upstream(&lc, "/api/v1/x").unwrap();
        assert_eq!(murl, "/api/*");
        assert_eq!(up, "http://127.0.0.1:8080");
    }

    #[test]
    fn cache_and_header_injection() {
        let lc = lc_with(vec![
            rule("/static/*", "cache", Some("max-age=60")),
            rule("/static/*", "header", Some("X-Frame-Options: DENY")),
        ]);
        let hs = response_headers(&lc, "/static/a.js");
        assert!(hs.contains(&("Cache-Control".into(), "max-age=60".into())));
        assert!(hs.contains(&("X-Frame-Options".into(), "DENY".into())));
    }

    #[test]
    fn redirect_status_prefix() {
        let r = redirect_response("301:https://x/y".into());
        assert_eq!(r.status(), StatusCode::MOVED_PERMANENTLY);
    }

    /// h2/h3 用 `apply_simple` 的返回值直接构造 `Location`（`.unwrap()`）——
    /// 含控制字符的 target 会让每个命中请求 panic，因此必须在这里被跳过。
    #[test]
    fn apply_simple_skips_unusable_location() {
        let lc = lc_with(vec![rule("/bad", "redirect", Some("/a\r\nX-Evil: 1"))]);
        assert_eq!(apply_simple(&lc, "/bad"), None, "非法 Location 必须跳过规则");
        let ok = lc_with(vec![rule("/ok", "redirect", Some("301:https://x/y"))]);
        assert_eq!(
            apply_simple(&ok, "/ok"),
            Some((StatusCode::MOVED_PERMANENTLY, "https://x/y".to_string()))
        );
    }

    // P2-9：混合大小写品牌词也要清洗；非品牌内容原样保留。
    #[test]
    fn scrub_brand_covers_mixed_case() {
        assert_eq!(scrub_brand("via CloudFlare"), "via CDN");
        assert_eq!(scrub_brand("cloudflare"), "cdn");
        assert_eq!(scrub_brand("CLOUDFLARE"), "CDN");
        assert_eq!(scrub_brand("xCloudflareY"), "xCDNY");
        assert_eq!(scrub_brand("保持中文不动"), "保持中文不动");
    }
}
