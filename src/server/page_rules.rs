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
use http::{header, HeaderMap, Request, Response, StatusCode};
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

/// 页面规则匹配的**请求上下文**（§16.11 的 host / 方法 / header 维度）。
///
/// 为什么需要它：评估入口此前只收 `&str path`，host/方法/header 无从判定。更关键的是
/// **跨协议一致** —— h1 的 [`apply`] 拿得到 `Request`，而 h2/h3 走
/// [`apply_simple`]/[`rewrite_path`]/… 只传路径；若只在 `apply` 里接维度，就会出现
/// 「`{method: POST, action: block}` 在 h1 拦、h2/h3 放行」的协议分叉。因此把请求上下文
/// 抽成 `MatchCtx`，**所有入口 × 所有协议**都传同一份判据。
///
/// `None` 的维度 = 该维度**不可用**：若规则声明了该维度则判**不匹配**（而非静默忽略），
/// 避免「取不到 host 就把带 host 约束的规则放宽成 path-only」这种误命中。
#[derive(Clone, Copy, Default)]
pub struct MatchCtx<'a> {
    pub method: Option<&'a str>,
    pub host: Option<&'a str>,
    pub headers: Option<&'a HeaderMap>,
}

impl<'a> MatchCtx<'a> {
    /// 从任意协议的请求构造：method/host/headers 是所有协议共有的
    /// （h2/h3 的 `:method`/`:authority` 经 hyper/h3 已落到 `Method`/URI authority
    /// 或 Host 头）。h1/h2/h3 的调用点都用它，保证三协议判定一致。
    pub fn from_request<B>(req: &'a Request<B>) -> Self {
        Self {
            method: Some(req.method().as_str()),
            host: host_of(req),
            headers: Some(req.headers()),
        }
    }

    /// 只有路径、无请求上下文（纯路径调用点/单测）：所有维度都缺失，
    /// 于是只按 URL 判定（规则未声明其它维度时行为与旧实现一致）。
    pub const fn path_only() -> Self {
        Self {
            method: None,
            host: None,
            headers: None,
        }
    }

    /// 从请求重建上下文，但 host 用调用方在改写 URI **之前**取好的快照。
    ///
    /// 为什么需要：h2/h3 的 host 只存在于 `:authority`（= URI authority）里，客户端
    /// 可以合法地不发 `Host` 头；而 rewrite 会把 `req.uri_mut()` 换成相对形态
    /// （`path?query`）——authority 随之消失，之后重建的 `MatchCtx` 拿不到 host。
    /// 于是带 host 约束的后续规则（`block` / `pass` / `header`）在 rewrite 之后
    /// **静默不命中**：安全规则被绕过，且只在 h2/h3 上发生（h1 的 Host 头始终在）。
    /// 调用方在改写前用 [`host_snapshot`] 存一份，改写后经本函数传入即可与 h1 一致。
    pub fn from_request_with_host<B>(req: &'a Request<B>, host: Option<&'a str>) -> Self {
        Self {
            method: Some(req.method().as_str()),
            host: host.or_else(|| host_of(req)),
            headers: Some(req.headers()),
        }
    }
}

/// 请求 host 的 owned 快照（调用方在改写 `req.uri_mut()` **之前**取）：
/// 优先 URI authority（h2/h3 的 `:authority`、绝对形式 h1 请求），退回 `Host` 头。
pub fn host_snapshot<B>(req: &Request<B>) -> Option<String> {
    host_of(req).map(str::to_string)
}

/// 取请求的 host：优先 URI authority（h2/h3 的 `:authority`、绝对形式 h1 请求），
/// 退回 `Host` 头（h1 origin-form）。两者都缺 → `None`（带 host 约束的规则不命中）。
fn host_of<B>(req: &Request<B>) -> Option<&str> {
    if let Some(h) = req.uri().host() {
        return Some(h);
    }
    req.headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
}

/// 一条规则是否命中：**URL + host + 方法 + header 四个维度全部满足**才命中。
///
/// - 规则**未声明**的维度不构成约束（`None`）；
/// - 规则**声明了**但 ctx 里该维度不可用 ⇒ 判不匹配（见 [`MatchCtx`] 说明）；
/// - 任何畸形输入（非法 header 名、超长 host、控制字符）都只导致「不匹配」，
///   绝不 panic（`HeaderName`/`HeaderValue` 构造失败即返回 false）。
pub fn rule_matches(rule: &PageRuleConfig, path: &str, ctx: &MatchCtx) -> bool {
    if !path_matches(&rule.match_url, path) {
        return false;
    }
    if let Some(m) = rule.method.as_deref() {
        let Some(actual) = ctx.method else {
            return false;
        };
        if !method_matches(m, actual) {
            return false;
        }
    }
    if let Some(h) = rule.host.as_deref() {
        let Some(actual) = ctx.host else {
            return false;
        };
        if !host_matches(h, actual) {
            return false;
        }
    }
    if let Some(spec) = rule.header.as_deref() {
        let Some(map) = ctx.headers else {
            return false;
        };
        if !header_matches(spec, map) {
            return false;
        }
    }
    true
}

/// 方法维度：逗号分隔多值、大小写不敏感（`"GET, HEAD"`）。空 token 忽略。
fn method_matches(pattern: &str, actual: &str) -> bool {
    pattern
        .split(',')
        .map(str::trim)
        .filter(|m| !m.is_empty())
        .any(|m| m.eq_ignore_ascii_case(actual))
}

/// host 维度：精确（大小写不敏感、忽略端口）/ `*.suffix` 通配子域（含 apex）/ `*` 全匹配。
///
/// 只做 ASCII 大小写折叠与字节比较，**不做正则**（避免 ReDoS 与热路径编译开销）；
/// 非 ASCII 的 host 不可能来自 URI/Host 头（`to_str()` 会拒绝），故字节切片安全。
/// 模式侧同样剥端口（`example.com:8080` 与 `example.com` 等价），避免写带端口的
/// 规则「面板显示已保存、实际永不命中」。
fn host_matches(pattern: &str, host: &str) -> bool {
    let host = host_without_port(host).trim_end_matches('.');
    // 模式单独走一遍分支判定：**先**看 `*` 前缀形态，再做尾点折叠 —— 否则 `"*."`
    // 会被 `trim_end_matches('.')` 折叠成 `"*"`，从「非法模式」变成「全匹配」。
    let p_full = host_without_port(pattern.trim());
    if p_full.is_empty() || host.is_empty() {
        return false;
    }
    if p_full == "*" {
        return true;
    }
    if let Some(suffix) = p_full.strip_prefix("*.") {
        let suffix = suffix.trim_end_matches('.');
        if suffix.is_empty() {
            // 只有 `"*."` 不是有意义的模式（`"*"` 才是全匹配；面板保存也拒绝 `"*."`）。
            // 手写 toml 里出现它时**不匹配**，绝不放大成「匹配所有 host」。
            return false;
        }
        let host_l = host.to_ascii_lowercase();
        let suf_l = suffix.to_ascii_lowercase();
        // apex 或任意层级子域（`a.example.com`、`a.b.example.com`）。
        return host_l == suf_l
            || (host_l.len() > suf_l.len()
                && host_l.as_bytes()[host_l.len() - suf_l.len() - 1] == b'.'
                && host_l.ends_with(&suf_l));
    }
    let p = p_full.trim_end_matches('.');
    !p.is_empty() && host.eq_ignore_ascii_case(p)
}

/// 去掉 host 的端口部分：`example.com:8080` → `example.com`；
/// IPv6 字面量 `[::1]:80` → `[::1]`。仅当冒号后是纯数字端口、且冒号**前**没有
/// 其它冒号（排除无括号 IPv6 字面量 `::1`）时才剥离 —— 避免把 `::1` 误切成 `::`。
fn host_without_port(host: &str) -> &str {
    if let Some(rest) = host.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            return &host[..end + 2];
        }
        return host;
    }
    match host.rsplit_once(':') {
        Some((h, port))
            if !h.contains(':') && !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) =>
        {
            h
        }
        _ => host,
    }
}

/// header 维度：`Name`（存在即命中）或 `Name: value`（值**精确**、大小写敏感）。
/// header 名大小写不敏感（`HeaderName` 归一化）。非法名 ⇒ 不匹配。
fn header_matches(spec: &str, headers: &HeaderMap) -> bool {
    let (name, want) = match spec.split_once(':') {
        Some((n, v)) => (n.trim(), Some(v.trim())),
        None => (spec.trim(), None),
    };
    if name.is_empty() {
        return false;
    }
    let Ok(hname) = http::header::HeaderName::from_bytes(name.as_bytes()) else {
        return false;
    };
    match want {
        None => headers.contains_key(&hname),
        Some(v) => headers
            .get_all(&hname)
            .iter()
            .any(|hv| hv.to_str().map(|s| s == v).unwrap_or(false)),
    }
}

/// 立即响应类动作(redirect/block)的同步判定;rewrite/pass/cache/header 见其余入口。
pub fn apply(lc: &ListenerConfig, req: &Request<Incoming>) -> Option<Response<BoxBody>> {
    let path = req.uri().path();
    let ctx = MatchCtx::from_request(req);
    for rule in ordered(&lc.page_rules) {
        if rule_matches(rule, path, &ctx) {
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
/// `ctx` 提供 host/方法/header 维度（见 [`MatchCtx`]）——三协议必须传同一份上下文。
pub fn plan(lc: &ListenerConfig, path: &str, ctx: &MatchCtx) -> RulePlan {
    // 1) rewrite 先行：后续所有判定都必须基于改写后的路径（与 h1 一致）。
    let rewritten = rewrite_path(lc, path, ctx);
    let effective = rewritten.as_deref().unwrap_or(path);
    // 2) redirect/block 在**新路径**上判定。
    let immediate = scan_immediate(lc, effective, ctx);
    // 3) pass 同样基于新路径；命中 immediate 时 pass 不再有意义（调用方先返回 immediate）。
    let pass = if immediate.is_some() {
        None
    } else {
        pass_upstream(lc, effective, ctx)
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
    ctx: &MatchCtx,
) -> Option<(StatusCode, Option<String>)> {
    for rule in ordered(&lc.page_rules) {
        if rule_matches(rule, path, ctx) {
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
pub fn apply_simple(lc: &ListenerConfig, path: &str, ctx: &MatchCtx) -> Option<(StatusCode, String)> {
    let decision = plan(lc, path, ctx);
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
pub fn rewrite_path(lc: &ListenerConfig, path: &str, ctx: &MatchCtx) -> Option<String> {
    for rule in ordered(&lc.page_rules) {
        if rule.action != "rewrite" {
            continue;
        }
        if !rule_matches(rule, path, ctx) {
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
pub fn pass_upstream(lc: &ListenerConfig, path: &str, ctx: &MatchCtx) -> Option<(String, String)> {
    for rule in ordered(&lc.page_rules) {
        if rule.action != "pass" {
            continue;
        }
        let Some(target) = rule.target.as_deref() else {
            continue;
        };
        if rule_matches(rule, path, ctx) {
            return Some((
                rule.match_url.clone(),
                target.trim_end_matches('/').to_string(),
            ));
        }
    }
    None
}

/// `cache`/`header` 动作产生的响应头(注入到最终响应)。
pub fn response_headers(lc: &ListenerConfig, path: &str, ctx: &MatchCtx) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for rule in ordered(&lc.page_rules) {
        if !rule_matches(rule, path, ctx) {
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
            method: None,
            host: None,
            header: None,
            match_url: m.into(),
            action: a.into(),
            target: t.map(|s| s.into()),
            priority: 0,
        }
    }

    fn rule_p(m: &str, a: &str, t: Option<&str>, priority: i64) -> crate::config::PageRuleConfig {
        crate::config::PageRuleConfig {
            method: None,
            host: None,
            header: None,
            match_url: m.into(),
            action: a.into(),
            target: t.map(|s| s.into()),
            priority,
        }
    }

    #[test]
    fn rewrite_prefix() {
        let lc = lc_with(vec![rule("/old/*", "rewrite", Some("/new"))]);
        assert_eq!(rewrite_path(&lc, "/old/a/b", &MatchCtx::path_only()).as_deref(), Some("/new/a/b"));
        assert_eq!(rewrite_path(&lc, "/other/", &MatchCtx::path_only()), None);
    }

    #[test]
    fn pass_upstream_and_suffix() {
        let lc = lc_with(vec![rule("/api/*", "pass", Some("http://127.0.0.1:8080"))]);
        let (murl, up) = pass_upstream(&lc, "/api/v1/x", &MatchCtx::path_only()).unwrap();
        assert_eq!(murl, "/api/*");
        assert_eq!(up, "http://127.0.0.1:8080");
    }

    #[test]
    fn cache_and_header_injection() {
        let lc = lc_with(vec![
            rule("/static/*", "cache", Some("max-age=60")),
            rule("/static/*", "header", Some("X-Frame-Options: DENY")),
        ]);
        let hs = response_headers(&lc, "/static/a.js", &MatchCtx::path_only());
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
        assert_eq!(apply_simple(&lc, "/bad", &MatchCtx::path_only()), None, "非法 Location 必须跳过规则");
        let ok = lc_with(vec![rule("/ok", "redirect", Some("301:https://x/y"))]);
        assert_eq!(
            apply_simple(&ok, "/ok", &MatchCtx::path_only()),
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
            apply_simple(&lc, "/secret/x", &MatchCtx::path_only()),
            Some((StatusCode::FORBIDDEN, String::new())),
            "rewrite 之后的路径必须再经 block 判定"
        );
        assert_eq!(apply_simple(&lc, "/public/x", &MatchCtx::path_only()), None);

        let lc2 = lc_with(vec![
            rule("/old/*", "rewrite", Some("/new")),
            rule("/new*", "redirect", Some("301:/moved")),
        ]);
        assert_eq!(
            apply_simple(&lc2, "/old/a", &MatchCtx::path_only()),
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
        let p = plan(&lc, "/go/v1", &MatchCtx::path_only());
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
        let p2 = plan(&lc2, "/x/a", &MatchCtx::path_only());
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
        let hs = response_headers(&lc, "/a", &MatchCtx::path_only());
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
            apply_simple(&lc, "/a", &MatchCtx::path_only()),
            Some((StatusCode::MOVED_PERMANENTLY, "/second".to_string()))
        );
        // block 同理：高优先级的 block 压过低优先级的 redirect。
        let lc2 = lc_with(vec![
            rule_p("/x", "redirect", Some("301:/ok"), 1),
            rule_p("/x", "block", None, 9),
        ]);
        assert_eq!(apply_simple(&lc2, "/x", &MatchCtx::path_only()), Some((StatusCode::FORBIDDEN, String::new())));
    }

    /// 等优先级必须**稳定**保持配置顺序（旧配置无 priority 字段 ⇒ 行为不变）。
    #[test]
    fn equal_priority_keeps_config_order() {
        let lc = lc_with(vec![
            rule("/p", "redirect", Some("301:/first")),
            rule("/p", "redirect", Some("308:/second")),
        ]);
        assert_eq!(
            apply_simple(&lc, "/p", &MatchCtx::path_only()),
            Some((StatusCode::MOVED_PERMANENTLY, "/first".to_string())),
            "等优先级首条胜"
        );
        // rewrite 入口同样按优先级：高优先级的 rewrite 先改路径。
        let lc2 = lc_with(vec![
            rule_p("/r/*", "rewrite", Some("/low"), 0),
            rule_p("/r/*", "rewrite", Some("/high"), 3),
        ]);
        assert_eq!(rewrite_path(&lc2, "/r/a", &MatchCtx::path_only()).as_deref(), Some("/high/a"));
        // response_headers 的注入顺序也按优先级（高者在前）。
        let lc3 = lc_with(vec![
            rule_p("/h", "header", Some("X-Order: low"), 0),
            rule_p("/h", "header", Some("X-Order: high"), 7),
        ]);
        let hs = response_headers(&lc3, "/h", &MatchCtx::path_only());
        assert_eq!(hs, vec![("X-Order".to_string(), "high".to_string()), ("X-Order".to_string(), "low".to_string())]);
    }

    /// 带维度的规则构造器（host/method/header）。
    fn rule_dims(
        m: &str,
        action: &str,
        target: Option<&str>,
        host: Option<&str>,
        method: Option<&str>,
        header: Option<&str>,
    ) -> crate::config::PageRuleConfig {
        crate::config::PageRuleConfig {
            method: method.map(Into::into),
            host: host.map(Into::into),
            header: header.map(Into::into),
            match_url: m.into(),
            action: action.into(),
            target: target.map(Into::into),
            priority: 0,
        }
    }

    /// §16.11 方法维度：逗号多值 + 大小写不敏感。
    #[test]
    fn method_dimension_case_insensitive_and_multi_value() {
        let lc = lc_with(vec![rule_dims("/x", "block", None, None, Some("get, HEAD"), None)]);
        let hm = HeaderMap::new();
        let mk = |m: &'static str| MatchCtx { method: Some(m), host: None, headers: Some(&hm) };
        assert_eq!(apply_simple(&lc, "/x", &mk("GET")), Some((StatusCode::FORBIDDEN, String::new())));
        assert_eq!(apply_simple(&lc, "/x", &mk("HEAD")), Some((StatusCode::FORBIDDEN, String::new())));
        assert_eq!(apply_simple(&lc, "/x", &mk("POST")), None, "未列出的方法不得命中");
    }

    /// §16.11 host 维度：精确/通配/全匹配；大小写与端口被忽略。
    #[test]
    fn host_dimension_exact_wildcard_and_port() {
        assert!(host_matches("a.example", "A.Example:8080"));
        assert!(host_matches("*.example.com", "a.example.com"));
        assert!(host_matches("*.example.com", "a.b.example.com"), "多级子域");
        assert!(host_matches("*.example.com", "example.com"), "apex 也算（文档语义）");
        assert!(!host_matches("*.example.com", "badexample.com"), "后缀必须落在 '.' 边界");
        assert!(!host_matches("example.com", "example.com.evil"));
        assert!(host_matches("*", "anything"));
        assert!(!host_matches("*.", "a.example"), "\"*.\" 不是合法模式，不得变成全匹配");
        assert!(host_matches("*.example.com.", "a.example.com"), "模式尾点被容忍");
        assert!(host_matches("example.com.", "example.com"), "模式尾点被容忍");
        assert!(host_matches("[::1]:80", "[::1]"), "IPv6 字面量剥端口");
        assert!(host_matches("example.com:8080", "example.com"), "模式侧端口同样忽略");
        assert!(host_matches("::1", "::1"), "无括号 IPv6 不被误切");
        assert!(!host_matches("", "example.com"));
        assert!(!host_matches("example.com", ""));
    }

    /// header 维度：`Name`（存在）或 `Name: value`（精确）；多值头任一值命中；
    /// 畸形输入只返回 false，不 panic。
    #[test]
    fn header_dimension_presence_value_and_malformed() {
        let mut hm = HeaderMap::new();
        hm.insert("X-Foo", http::HeaderValue::from_static("bar"));
        hm.insert("X-Multi", http::HeaderValue::from_static("a"));
        hm.append("X-Multi", http::HeaderValue::from_static("b"));
        assert!(header_matches("X-Foo", &hm));
        assert!(header_matches("x-foo: bar", &hm), "头名大小写不敏感");
        assert!(header_matches("X-Foo: bar ", &hm), "值两侧空白 trim");
        assert!(!header_matches("X-Foo: baz", &hm), "值必须精确");
        assert!(header_matches("X-Multi: b", &hm), "多值头任一值匹配即可");
        assert!(!header_matches("X-Absent", &hm));
        // 畸形：非法头名 / 空名 / 值含控制字符 —— 一律 false。
        assert!(!header_matches("Bad Name", &hm));
        assert!(!header_matches("", &hm));
        assert!(!header_matches("X-Foo: ba\tr", &hm));
    }

    /// **匹配不到上下文就不匹配**（而非放宽成 path-only）：维度缺失时规则不得命中。
    #[test]
    fn declared_but_unavailable_dimension_never_matches() {
        let lc = lc_with(vec![
            rule_dims("/h", "block", None, Some("a.example"), None, None),
            rule_dims("/m", "block", None, None, Some("POST"), None),
            rule_dims("/k", "block", None, None, None, Some("X-Foo: bar")),
        ]);
        // path_only：method/host/headers 全缺 ⇒ 三条带约束的规则都不命中。
        assert_eq!(apply_simple(&lc, "/h", &MatchCtx::path_only()), None);
        assert_eq!(apply_simple(&lc, "/m", &MatchCtx::path_only()), None);
        assert_eq!(apply_simple(&lc, "/k", &MatchCtx::path_only()), None);

        let empty = HeaderMap::new();
        let ctx = MatchCtx { method: Some("POST"), host: Some("a.example"), headers: Some(&empty) };
        assert_eq!(apply_simple(&lc, "/h", &ctx), Some((StatusCode::FORBIDDEN, String::new())));
        assert_eq!(apply_simple(&lc, "/m", &ctx), Some((StatusCode::FORBIDDEN, String::new())));
        assert_eq!(apply_simple(&lc, "/k", &ctx), None, "头不存在 ⇒ 不命中");

        let mut hm = HeaderMap::new();
        hm.insert("X-Foo", http::HeaderValue::from_static("bar"));
        let ctx2 = MatchCtx { method: Some("GET"), host: None, headers: Some(&hm) };
        assert_eq!(apply_simple(&lc, "/k", &ctx2), Some((StatusCode::FORBIDDEN, String::new())));
    }

    /// §16.11 跨协议 host 保留回归：h2/h3 的 host 只在 URI authority 里；rewrite 把
    /// URI 换成相对形态后 authority 消失，必须用**改写前的快照**重建 ctx——否则带 host
    /// 约束的后续规则（block/pass/header）静默不命中（h1 的 Host 头始终在，无此问题）。
    #[test]
    fn host_survives_uri_rewrite_with_snapshot() {
        let mut req = Request::builder()
            .method("GET")
            .uri("https://a.example/old/x")
            .body(())
            .unwrap();
        let snap = host_snapshot(&req);
        assert_eq!(snap.as_deref(), Some("a.example"));
        // 模拟 h2/h3 的 rewrite：替换成相对形态（authority 与 scheme 一并消失）。
        *req.uri_mut() = "/new/x".parse().unwrap();
        assert_eq!(
            MatchCtx::from_request(&req).host,
            None,
            "改写后裸 from_request 拿不到 host —— 这正是修复前的漏洞面"
        );
        let ctx = MatchCtx::from_request_with_host(&req, snap.as_deref());
        assert_eq!(ctx.host, Some("a.example"));
        // 带 host 约束的 block 规则在改写后的路径上仍然命中。
        let lc = lc_with(vec![rule_dims("/new/x", "block", None, Some("a.example"), None, None)]);
        assert_eq!(
            apply_simple(&lc, "/new/x", &ctx),
            Some((StatusCode::FORBIDDEN, String::new()))
        );
        // 请求本来就没有 host（HTTP/1.0 风格）⇒ 快照 None，host 规则不命中（不放宽）。
        let req2 = Request::builder().method("GET").uri("/only/path").body(()).unwrap();
        let snap2 = host_snapshot(&req2);
        assert_eq!(snap2, None);
        let ctx2 = MatchCtx::from_request_with_host(&req2, snap2.as_deref());
        assert_eq!(ctx2.host, None);
        assert_eq!(apply_simple(&lc, "/new/x", &ctx2), None);
    }
}
