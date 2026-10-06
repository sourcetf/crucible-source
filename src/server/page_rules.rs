//! Page rules (CDN-style). UI copy must not mention third-party brand names.
//!
//! 支持的 action(均为每 listener `[[listeners.page_rules]]` 或全局规则):
//! - `redirect`: 302 → target,可带 "301:" / "307:" / "308:" 前缀指定状态码
//! - `block`:    403
//! - `rewrite`:  路径前缀改写,target 为新前缀(match_url 前缀被替换)
//! - `pass`:     反向代理到 target(完整上游 URL;http:// → 不校验上游 TLS)
//! - `cache`:    响应加 Cache-Control(target 为指令值,缺省 public, max-age=3600)
//! - `header`:   响应加自定义响应头,target 为 "Name: value"
//!
//! **评估顺序三协议统一**（唯一入口 [`plan`]）：rewrite → redirect/block → pass →
//! 响应头（`response_headers` 按改写后的路径求值）。rewrite 命中后的路径必须重新
//! 经过 block/redirect，否则改写可以绕过安全规则（h2/h3 旧实现即如此）。

use crate::config::{ListenerConfig, PageRuleConfig};
use crate::server::h1::{full, BoxBody};
use http::{header, Request, Response, StatusCode};
use hyper::body::Incoming;

/// 按 §16.11 的 `priority` 排序：**数值大者先评估**；等值保持**配置顺序**
/// （`sort_by` 是稳定排序，且全默认 0 时直接沿用原切片顺序，零排序开销）。
///
/// 所有评估入口（apply / scan_immediate / rewrite_path / pass_upstream /
/// response_headers）都经此遍历，保证「首个命中者胜」在协议间与优先级间一致。
fn ordered<'a>(rules: &'a [PageRuleConfig]) -> Vec<&'a PageRuleConfig> {
    let mut v: Vec<&PageRuleConfig> = rules.iter().collect();
    if v.iter().any(|r| r.priority != 0) {
        v.sort_by(|a, b| b.priority.cmp(&a.priority));
    }
    v
}

/// 立即响应类动作(redirect/block)的同步判定;rewrite/pass/cache/header 见其余入口。
pub fn apply(lc: &ListenerConfig, req: &Request<Incoming>) -> Option<Response<BoxBody>> {
    let path = req.uri().path();
    for rule in ordered(&lc.page_rules) {
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

/// 页面规则的**统一评估结果**（`plan` 的返回值）。
///
/// 顺序固定为 h1 的语义：**rewrite（先改写路径）→ redirect/block（在新路径上判定）
/// → pass（也在新路径上判定）**。h2/h3 此前是「先 redirect/block 再 rewrite 且改写后
/// 不再判定」，导致 `rewrite /secret/* → /admin` 的流量绕过 `block /admin*`（浏览器默认
/// 走 h2/h3，安全规则整体失效）。
#[derive(Debug, Default)]
pub struct RulePlan {
    /// 命中的 rewrite 之后的**新请求路径**（调用方需要用它更新 `req.uri()`，并用它
    /// 调用 `response_headers`）。
    pub rewritten: Option<String>,
    /// 命中 redirect(状态码, Location) / block(403, None)：调用方立即返回响应。
    /// Location 已通过 `HeaderValue` 校验（非法 target 跳过该规则，见 `scan_immediate`）。
    pub immediate: Option<(StatusCode, Option<String>)>,
    /// 命中 pass：返回 (match_url, upstream)。
    pub pass: Option<(String, String)>,
}

/// 页面规则的**唯一评估入口**：一次给出 rewrite/immediate/pass 三项决策，
/// 三者顺序与 h1 一致（见 [`RulePlan`]）。h2/h3 应改用它（其调用点不在本文件）。
///
/// 副作用为零：不改请求、不发响应、`pass`/`immediate` 只做判定。
pub fn plan(lc: &ListenerConfig, path: &str) -> RulePlan {
    // 1) rewrite 先行：后续所有判定都必须基于改写后的路径（与 h1 一致）。
    let rewritten = rewrite_path(lc, path);
    let effective = rewritten.as_deref().unwrap_or(path);
    // 2) redirect/block 在**新路径**上判定。
    let immediate = scan_immediate(lc, effective);
    // 3) pass 同样基于新路径；命中 immediate 时 pass 不再有意义（调用方先返回 immediate）。
    let pass = if immediate.is_some() {
        None
    } else {
        pass_upstream(lc, effective)
    };
    RulePlan {
        rewritten,
        immediate,
        pass,
    }
}

/// 立即响应类动作（redirect/block）的扫描（不含 rewrite；调用方必须已把路径改写好）。
fn scan_immediate(
    lc: &ListenerConfig,
    path: &str,
) -> Option<(StatusCode, Option<String>)> {
    for rule in ordered(&lc.page_rules) {
        if path_matches(&rule.match_url, path) {
            match rule.action.as_str() {
                "block" => return Some((StatusCode::FORBIDDEN, None)),
                "redirect" => {
                    let target = rule.target.clone().unwrap_or_else(|| "/".into());
                    let (status, loc) = match target.split_once(':') {
                        Some(("301", u)) => (StatusCode::MOVED_PERMANENTLY, u.to_string()),
                        Some(("307", u)) => (StatusCode::TEMPORARY_REDIRECT, u.to_string()),
                        Some(("308", u)) => (StatusCode::PERMANENT_REDIRECT, u.to_string()),
                        _ => (StatusCode::FOUND, target),
                    };
                    // 这个 API 只能返回可选的 Location，而 h2/h3 的调用方是
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
                    return Some((status, Some(loc)));
                }
                _ => {}
            }
        }
    }
    None
}

/// h2/h3 使用的简化版本:返回 (status, location) 二元组,由调用方组装响应。
///
/// **rewrite 在判定之前**（走 `plan`）：h2/h3 的调用点保持「先调本函数、命中就返回；
/// 否则再调 `rewrite_path` 更新请求」的形状即可，改写后的路径会先被 block/redirect
/// 判定，不再绕过。
pub fn apply_simple(lc: &ListenerConfig, path: &str) -> Option<(StatusCode, String)> {
    let decision = plan(lc, path);
    decision
        .immediate
        .map(|(status, loc)| (status, loc.unwrap_or_default()))
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
    for rule in ordered(&lc.page_rules) {
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
    for rule in ordered(&lc.page_rules) {
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
    for rule in ordered(&lc.page_rules) {
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
                    // 统一黑名单（headers_mod::response_header_injectable）：Content-Length /
                    // Transfer-Encoding / Connection / Host 等定界与逐跳头一律拒绝。
                    // 过滤放在**源头**（这里）意味着所有调用方——包括 h2/h3 直接对
                    // response_headers 结果做 `.insert()` 的内联循环——都自动受保护。
                    if !crate::server::headers_mod::response_header_injectable(name) {
                        log::warn!(
                            "page_rules header: 拒绝注入定界/逐跳响应头 {name:?}（CL/TE/Connection/Host 等）"
                        );
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
            priority: 0,
        }
    }

    fn rule_p(m: &str, a: &str, t: Option<&str>, priority: i64) -> crate::config::PageRuleConfig {
        crate::config::PageRuleConfig {
            match_url: m.into(),
            action: a.into(),
            target: t.map(|s| s.into()),
            priority,
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

    /// P2 回归：h2/h3 的 `apply_simple` 必须先 rewrite 再判 block/redirect，
    /// 否则 rewrite 到被 block 的路径会绕过 block（h1 一直是按新路径判定）。
    #[test]
    fn apply_simple_evaluates_after_rewrite_like_h1() {
        let lc = lc_with(vec![
            rule("/secret/*", "rewrite", Some("/admin")),
            rule("/admin*", "block", None),
        ]);
        assert_eq!(
            apply_simple(&lc, "/secret/x"),
            Some((StatusCode::FORBIDDEN, String::new())),
            "rewrite 之后的路径必须再经 block 判定"
        );
        assert_eq!(apply_simple(&lc, "/public/x"), None);

        let lc2 = lc_with(vec![
            rule("/old/*", "rewrite", Some("/new")),
            rule("/new*", "redirect", Some("301:/moved")),
        ]);
        assert_eq!(
            apply_simple(&lc2, "/old/a"),
            Some((StatusCode::MOVED_PERMANENTLY, "/moved".to_string()))
        );
    }

    /// `plan` 是单一入口：rewrite/immediate/pass 三项一次算出且顺序固定。
    #[test]
    fn plan_covers_rewrite_immediate_and_pass() {
        let lc = lc_with(vec![
            rule("/go/*", "rewrite", Some("/api")),
            rule("/api/*", "pass", Some("http://127.0.0.1:8080")),
        ]);
        let p = plan(&lc, "/go/v1");
        assert_eq!(p.rewritten.as_deref(), Some("/api/v1"));
        assert!(p.immediate.is_none());
        let (murl, up) = p.pass.unwrap();
        assert_eq!(murl, "/api/*");
        assert_eq!(up, "http://127.0.0.1:8080");

        // immediate 命中时 pass 不再给出（调用方先返回 immediate）
        let lc2 = lc_with(vec![
            rule("/x/*", "rewrite", Some("/y")),
            rule("/y*", "block", None),
            rule("/y*", "pass", Some("http://127.0.0.1:1")),
        ]);
        let p2 = plan(&lc2, "/x/a");
        assert_eq!(p2.immediate.as_ref().unwrap().0, StatusCode::FORBIDDEN);
        assert!(p2.pass.is_none());
    }

    /// P2 回归：`header` 动作不得注入 Content-Length/Transfer-Encoding/Connection/Host
    /// （h1 会原样写出错的 CL ⇒ 响应走私；h2/h3 走同一 `response_headers`，自动受保护）。
    #[test]
    fn response_headers_reject_framing_and_hop_headers() {
        let lc = lc_with(vec![
            rule("/a", "header", Some("Content-Length: 5")),
            rule("/a", "header", Some("Transfer-Encoding: chunked")),
            rule("/a", "header", Some("Connection: keep-alive")),
            rule("/a", "header", Some("Host: evil.tld")),
            rule("/a", "header", Some("X-Frame-Options: DENY")),
        ]);
        let hs = response_headers(&lc, "/a");
        assert_eq!(
            hs,
            vec![("X-Frame-Options".to_string(), "DENY".to_string())],
            "只有正常头能通过：{hs:?}"
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

    /// §16.11 优先级：**数值大者先评估**，与书写顺序无关。
    /// 两条同前缀 redirect，后者 priority 更高 ⇒ 后者胜（旧实现是「先写者胜」）。
    #[test]
    fn priority_overrides_config_order() {
        let lc = lc_with(vec![
            rule_p("/a", "redirect", Some("302:/first"), 1),
            rule_p("/a", "redirect", Some("301:/second"), 5),
        ]);
        assert_eq!(
            apply_simple(&lc, "/a"),
            Some((StatusCode::MOVED_PERMANENTLY, "/second".to_string()))
        );
        // block 同理：高优先级的 block 压过低优先级的 redirect。
        let lc2 = lc_with(vec![
            rule_p("/x", "redirect", Some("301:/ok"), 1),
            rule_p("/x", "block", None, 9),
        ]);
        assert_eq!(apply_simple(&lc2, "/x"), Some((StatusCode::FORBIDDEN, String::new())));
    }

    /// 等优先级必须**稳定**保持配置顺序（旧配置无 priority 字段 ⇒ 行为不变）。
    #[test]
    fn equal_priority_keeps_config_order() {
        let lc = lc_with(vec![
            rule("/p", "redirect", Some("301:/first")),
            rule("/p", "redirect", Some("308:/second")),
        ]);
        assert_eq!(
            apply_simple(&lc, "/p"),
            Some((StatusCode::MOVED_PERMANENTLY, "/first".to_string())),
            "等优先级首条胜"
        );
        // rewrite 入口同样按优先级：高优先级的 rewrite 先改路径。
        let lc2 = lc_with(vec![
            rule_p("/r/*", "rewrite", Some("/low"), 0),
            rule_p("/r/*", "rewrite", Some("/high"), 3),
        ]);
        assert_eq!(rewrite_path(&lc2, "/r/a").as_deref(), Some("/high/a"));
        // response_headers 的注入顺序也按优先级（高者在前）。
        let lc3 = lc_with(vec![
            rule_p("/h", "header", Some("X-Order: low"), 0),
            rule_p("/h", "header", Some("X-Order: high"), 7),
        ]);
        let hs = response_headers(&lc3, "/h");
        assert_eq!(hs, vec![("X-Order".to_string(), "high".to_string()), ("X-Order".to_string(), "low".to_string())]);
    }
}
