//! Embedded Admin UI and API.
//!
//! 路由总览（全部挂在 `[admin].path` 前缀下，默认 `/__admin`）：
//! - 页面/资源：`/`（admin_ui.html）、`/hls.light.min.js`
//! - 只读：`/api/overview`、`/api/catalog`、`/api/config`（TOML）、`/api/config/json`
//! - 保存（POST，写 config.toml → 校验 → 原子替换 → 热重载）：
//!   `/api/config/toml`、`/api/listener/save|delete`、`/api/apps/save`、`/api/ssl/save`、
//!   `/api/file_open/save`、`/api/autoindex/save`、`/api/page_rules/save`、
//!   `/api/proxy_rules/save`、`/api/access_log/save`、`/api/ip_access/save`、`/api/geoip/save`
//! - 文件管理：`/api/files`（GET list/read、PUT/POST write）、`/api/files/mkdir`、`/api/files/delete`
//! - GeoIP 面板：`/api/geoip/{lookup,status,filter,sources,conflicts,edit,audit,cron,update}`
//! - 账号：`/api/password`（明文进、argon2id/yescrypt 盐哈希落盘）

use crate::config::{Config, ListenerConfig};
use crate::server::admin_config_edit as cfg_edit;
use crate::server::admin_files;
use crate::server::admin_geoip;
use crate::server::h1::{full, BoxBody};
use crate::server::live_config::LiveConfig;
use crate::server::password;
use bytes::Bytes;
use http::{header, HeaderMap, Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use serde_json::Value as Json;
use std::sync::Arc;

pub const UI_HTML: &str = include_str!("admin_ui.html");
/// 视频预览（HLS/mp4）辅助脚本，经 include_str! 编进二进制；改后需重链。
pub const HLS_JS: &str = include_str!("admin_hls.light.min.js");

/// 从 `Origin`/`Referer` 这类 URL 里取出 `host[:port]`（无尾斜杠、去尾点）。
///
/// 取不到就返回 None（`null`、相对路径、畸形）—— 上层按「不同源」处理，宁可拒绝。
fn url_host(u: &str) -> Option<&str> {
    let after_scheme = u.split("://").nth(1)?;
    let host = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .trim()
        .trim_end_matches('.');
    // 沙箱 iframe / file:// 会把 Origin 写成字面量 `null`，它不是主机名。
    (!host.is_empty() && !host.eq_ignore_ascii_case("null")).then_some(host)
}

/// 本请求的 `host[:port]`：优先 `Host` 头，h2 只有 `:authority` 时用 URI authority
/// （hyper 的 h2 服务端把 `:authority` 放进 URI，不保证补 `Host` 头）。
fn request_host<T>(req: &Request<T>) -> Option<&str> {
    req.headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|h| !h.is_empty())
        .or_else(|| req.uri().authority().map(|a| a.as_str()))
}

/// `Content-Type` 是否为 JSON（允许 `; charset=` 之类的参数）。
fn has_json_content_type(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.split(';')
                .next()
                .unwrap_or("")
                .trim()
                .eq_ignore_ascii_case("application/json")
        })
}

/// 状态变更请求（POST/PUT/PATCH/DELETE）的跨站判定（P0-2 补强）。
///
/// 为什么不能只看 `Origin`：此前实现是「有 `Origin` 才比，没有就整段跳过」——
/// 于是所有**不带 Origin** 的写请求（部分旧浏览器/表单场景、以及想绕检查的非浏览器
/// 客户端）等于完全没有这道防线。而 `<form method=POST>` 恰恰是攻击者最容易构造的
/// 跨站写请求。
///
/// 现在的判定分两层：
/// 1. 带 `Origin` 或 `Referer`：其 `host[:port]` 必须与本请求的 `Host`（或 h2 的
///    `:authority`）相同，否则 403。scheme 不参与比较（反代/回源常改 scheme）。
/// 2. 两者都没有：要求请求具备「非简单请求」特征之一 ——
///    `Content-Type: application/json`（含 `; charset=` 变体）、自定义头
///    `X-Crucible-Admin: 1`、或浏览器自写的 `Sec-Fetch-Site: same-origin|none`。
///    为什么这样就够：浏览器跨源发 JSON content-type 或自定义头**必然先发 CORS 预检**，
///    而本服务不放行任何跨源请求（预检拿不到 Access-Control-Allow-* 就会失败），
///    所以这两者跨源时根本发不出去；`<form>` 只能产出简单请求（简单 Content-Type +
///    不能带自定义头），表单型 CSRF 因此被挡住。
///
/// GET/HEAD 不走这个门槛：它们是只读语义，浏览器也不会给它们带 `Origin`，套上反而
/// 会误伤状态查询。跨站 GET 由三协议入口的 `access::cross_site_blocked` 负责。
fn state_change_allowed<T>(req: &Request<T>) -> bool {
    let headers = req.headers();
    let origin = headers
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or_else(|| {
            headers
                .get(header::REFERER)
                .and_then(|v| v.to_str().ok())
                .map(str::trim)
                .filter(|s| !s.is_empty())
        });
    if let Some(src) = origin {
        return match (url_host(src), request_host(req)) {
            (Some(a), Some(b)) => a.eq_ignore_ascii_case(b.trim_end_matches('/')),
            // 有来源信息但比不出同源（畸形 URL、无边界的 `null`、无 Host/authority）
            // → 一律拒绝，不做「拿不准就放行」。
            _ => false,
        };
    }
    if has_json_content_type(headers) {
        return true;
    }
    if headers
        .get("x-crucible-admin")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.trim() == "1")
    {
        return true;
    }
    headers
        .get("sec-fetch-site")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            let v = v.trim();
            v.eq_ignore_ascii_case("same-origin") || v.eq_ignore_ascii_case("none")
        })
}

/// P1-4：统一请求体类型为 Request<Full<Bytes>>——h1 在入口收齐（32MiB 上限），
/// h2/h3 把已收集的 body 用 Full 重建后复用同一处理函数（admin API 不再只走 h1）。
pub async fn handle(req: Request<Full<Bytes>>, live: Arc<LiveConfig>) -> Response<BoxBody> {
    let cfg = live.snapshot();
    let admin_path = cfg.admin.path.trim_end_matches('/').to_string();
    let path = req.uri().path().to_string();
    let method = req.method().clone();

    // Basic gate: any configured user list requires Authorization (empty hashes never pass).
    let needs_auth = crate::server::basic_auth::admin_requires_auth(&cfg.admin);
    if needs_auth {
        if !crate::server::basic_auth::check_admin(&req, &cfg.admin) {
            return Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header(
                    header::WWW_AUTHENTICATE,
                    format!("Basic realm=\"{}\"", cfg.admin.realm),
                )
                .body(full("unauthorized"))
                .unwrap();
        }
    }

    // CSRF 防护（P0-2）：状态变更请求必须同源或具备非简单请求特征，缺 `Origin` 不再
    // 直接放行（判定细节见 `state_change_allowed`）。GET/HEAD 只读，不加这道门槛。
    if matches!(method, Method::POST | Method::PUT | Method::DELETE | Method::PATCH)
        && !state_change_allowed(&req)
    {
        return Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(full("cross-origin request blocked"))
            .unwrap();
    }

    if path == admin_path || path == format!("{admin_path}/") || path.ends_with("/index.html") {
        return Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
            .body(full(UI_HTML))
            .unwrap();
    }

    // 静态资源：HLS/媒体预览辅助脚本（§8 视频 mp4/m3u8、音频、PDF 预览）。
    if path.ends_with("/hls.light.min.js") {
        return Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/javascript; charset=utf-8")
            .body(full(HLS_JS))
            .unwrap();
    }

    // hls.js 静态资产(文件管理媒体预览)
    if path == format!("{admin_path}/hls.js") {
        return Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/javascript; charset=utf-8")
            .body(full(HLS_JS))
            .unwrap();
    }

    // DNS 管理面板 API（bind9 控制面，含 JSP 编译按钮）——鉴权/CSRF 已在上方完成。
    // Routes are under [admin].path (default /__admin); bare starts_with("/api/dns/") never matches.
    let dns_rel = path.strip_prefix(&admin_path).unwrap_or(path.as_str());
    // 分区导出必须走 text/plain + Content-Disposition 附件，而不是 admin_api 的
    // JSON 通道 —— 否则浏览器只会显示一段 JSON，用户拿不到 .zone 文件。
    if dns_rel.ends_with("/api/dns/zones/export") && method == Method::GET {
        return crate::server::dns::admin_api::handle_zone_export(&req).await;
    }
    if dns_rel.starts_with("/api/dns/")
        || dns_rel == "/api/apps/jsp/compile"
        || path.ends_with("/api/apps/jsp/compile")
    {
        return crate::server::dns::admin_api::handle(req, &live).await;
    }

    // 访问日志实时 tail(内存环形缓冲)
    if path.ends_with("/api/logs") && method == Method::GET {
        let q = req.uri().query().unwrap_or("");
        let limit = query_str(q, "limit")
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(200)
            .min(500);
        let lines = crate::server::access_log::recent_lines(limit);
        let mut s = String::from("{\"lines\":[");
        for (i, l) in lines.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str(&json_str(l));
        }
        s.push_str("]}");
        return json_ok(s);
    }

    // 页面规则 / 反代规则:GET 读取,POST 增删(写 config.toml + 热重载)
    if path.ends_with("/api/pagerules") && (method == Method::GET || method == Method::POST) {
        return handle_rules_api(req, &live, RulesKind::Page).await;
    }
    if path.ends_with("/api/proxyrules") && (method == Method::GET || method == Method::POST) {
        return handle_rules_api(req, &live, RulesKind::Proxy).await;
    }

    // /api/overview
    if path.ends_with("/api/overview") && method == Method::GET {
        let listeners: Vec<String> = cfg
            .listeners
            .iter()
            .map(|l| {
                format!(
                    "{}:{} root={} ssl={} apps={}",
                    l.address,
                    l.port,
                    l.root.display(),
                    l.ssl.is_some(),
                    l.apps.len()
                )
            })
            .collect();
        let body = format!(
            "{{\n  \"listeners\": {},\n  \"access_log\": {},\n  \"geoip\": {},\n  \"ip_access\": {{\n    \"allow\": {},\n    \"deny\": {}\n  }},\n  \"tls_stack\": {},\n  \"tls_legacy\": {}\n}}",
            serde_json_array(&listeners),
            cfg.access_log.enable,
            cfg.geoip.enabled,
            serde_json_array(&cfg.ip_access.allow),
            serde_json_array(&cfg.ip_access.deny),
            json_str(crate::server::tls::active_stack()),
            json_str(crate::server::tls::legacy_modules())
        );
        return json_ok(body);
    }

    if path.ends_with("/api/catalog") && method == Method::GET {
        return json_ok(crate::server::options_catalog::catalog_json());
    }

    // ---------- GeoIP 面板 API ----------
    if path.ends_with("/api/geoip/lookup") && method == Method::GET {
        return admin_geoip::handle_lookup_with_live(&req, &live).await;
    }
    if path.ends_with("/api/geoip/status") && method == Method::GET {
        return admin_geoip::handle_status_with_live(&req, &live).await;
    }
    // 必须与上面那条**并列**：`/api/geoip/update/status` 并不以 `/api/geoip/status`
    // 结尾，之前把它套在 status 分支内部，等于永远进不去（那条路径会一路落到
    // 末尾的 "admin route not found"）。用 ends_with 做路由时，嵌套顺序就是语义。
    if path.ends_with("/api/geoip/update/status") && method == Method::GET {
        return admin_geoip::handle_update_status(&req).await;
    }
    if path.ends_with("/api/geoip/filter") && method == Method::GET {
        return admin_geoip::handle_filter_with_live(&req, &live).await;
    }
    if path.ends_with("/api/geoip/conflicts/resolve") && method == Method::POST {
        return admin_geoip::handle_conflict_resolve(req).await;
    }
    if path.ends_with("/api/geoip/conflicts/source") && method == Method::GET {
        return admin_geoip::handle_conflict_source(req).await;
    }
    if path.ends_with("/api/geoip/conflicts") && method == Method::GET {
        return admin_geoip::handle_conflicts(&req).await;
    }
    if path.ends_with("/api/geoip/sources") && method == Method::GET {
        return admin_geoip::handle_sources(&req).await;
    }
    if path.ends_with("/api/geoip/edit") && method == Method::POST {
        return admin_geoip::handle_edit(req).await;
    }
    // P0：手工覆盖列表 / 删除——UI 已在调用（loadGeoEdits / delGeoEdit），此前未接线恒 404。
    if path.ends_with("/api/geoip/edits") && method == Method::GET {
        return admin_geoip::handle_edits(&req).await;
    }
    if path.ends_with("/api/geoip/edit/delete") && method == Method::POST {
        return admin_geoip::handle_edit_delete(req).await;
    }
    if path.ends_with("/api/geoip/audit") && method == Method::GET {
        return admin_geoip::handle_audit(&req).await;
    }
    if path.ends_with("/api/geoip/cron") {
        return admin_geoip::handle_cron(req).await;
    }
    if path.ends_with("/api/geoip/sources") && method == Method::POST {
        return admin_geoip::handle_source_set(req).await;
    }
    if path.ends_with("/api/geoip/update") && method == Method::POST {
        return admin_geoip::handle_update_trigger(req).await;
    }

    // TLS 可配置套件目录：**运行时探测**链接进来的 BoringSSL 得到（见 tls/cipher_catalog），
    // 面板据此列出全集供管理员挑选；配置校验也用同一份，避免"面板能选、保存后被拒"。
    if path.ends_with("/api/tls/ciphers") && method == Method::GET {
        use crate::server::tls::cipher_catalog as cc;
        return json_ok(
            serde_json::json!({
                "suites": cc::supported(),
                "tls13": cc::TLS13_SUITES,
                "psk": cc::psk_suites(),
            })
            .to_string(),
        );
    }

    // ---------- 配置读取 ----------
    if path.ends_with("/api/config/json") && method == Method::GET {
        return match serde_json::to_string_pretty(&*cfg) {
            Ok(s) => json_ok(s),
            Err(e) => text_err(StatusCode::INTERNAL_SERVER_ERROR, format!("serialize: {e}")),
        };
    }

    if path.ends_with("/api/config") && method == Method::GET {
        let body = cfg.to_toml_string().unwrap_or_default();
        return Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(full(body))
            .unwrap();
    }

    // ---------- 配置保存（写盘管线：校验 → 原子替换 → 热重载） ----------
    if path.ends_with("/api/config/toml") && method == Method::POST {
        let bytes = match collect_body(req).await {
            Ok(b) => b,
            Err(e) => return text_err(StatusCode::BAD_REQUEST, e),
        };
        let text = String::from_utf8_lossy(&bytes);
        return match cfg_edit::write_toml_text(&live, text.trim()) {
            Ok(()) => text_ok("config saved + reloaded"),
            Err(e) => text_err(StatusCode::BAD_REQUEST, format!("{e:#}")),
        };
    }

    if path.ends_with("/api/config/reload") && method == Method::POST {
        return match live.reload() {
            Ok(()) => text_ok("reloaded"),
            Err(e) => text_err(StatusCode::BAD_REQUEST, format!("{e:#}")),
        };
    }

    if path.ends_with("/api/listener/save") && method == Method::POST {
        return with_json(req, |v| save_listener(&live, &v)).await;
    }
    if path.ends_with("/api/listener/delete") && method == Method::POST {
        return with_json(req, |v| {
            // 端口范围校验：`as u16` 会把 131165 截断成 9095，于是
            // 「删除 131165」实际删掉的是 9095 那个站点。
            let port = match json_port(v, "port") {
                Ok(p) => p,
                Err(resp) => return resp,
            };
            let mut tree = match cfg_edit::load_tree(live.path()) {
                Ok(t) => t,
                Err(e) => return text_err(StatusCode::BAD_REQUEST, format!("{e:#}")),
            };
            match cfg_edit::remove_listener(&mut tree, port) {
                Ok(true) => {}
                Ok(false) => {
                    return text_err(StatusCode::BAD_REQUEST, format!("listener {port} 不存在"))
                }
                Err(e) => return text_err(StatusCode::BAD_REQUEST, format!("{e:#}")),
            }
            finish_write(&live, &tree, "listener deleted")
        })
        .await;
    }
    if path.ends_with("/api/apps/save") && method == Method::POST {
        return with_json(req, |v| save_apps(&live, &v)).await;
    }
    if path.ends_with("/api/ssl/save") && method == Method::POST {
        return with_json(req, |v| save_ssl(&live, &v)).await;
    }
    if path.ends_with("/api/file_open/save") && method == Method::POST {
        return with_json(req, |v| save_file_open(&live, &v)).await;
    }
    if path.ends_with("/api/autoindex/save") && method == Method::POST {
        return with_json(req, |v| save_autoindex(&live, &v)).await;
    }
    if path.ends_with("/api/page_rules/save") && method == Method::POST {
        return with_json(req, |v| save_page_rules(&live, &v)).await;
    }
    if path.ends_with("/api/proxy_rules/save") && method == Method::POST {
        return with_json(req, |v| save_proxy_rules(&live, &v)).await;
    }
    if path.ends_with("/api/access_log/save") && method == Method::POST {
        return with_json(req, |v| {
            let enable = v.get("enable").and_then(|b| b.as_bool()).unwrap_or(true);
            let level = v.get("level").and_then(|s| s.as_str()).unwrap_or("info");
            if !["error", "warn", "info", "debug", "trace"].contains(&level) {
                return text_err(StatusCode::BAD_REQUEST, "invalid level");
            }
            let realtime = v
                .get("realtime")
                .and_then(|b| b.as_bool())
                .unwrap_or(false);
            let mut tree = match cfg_edit::load_tree(live.path()) {
                Ok(t) => t,
                Err(e) => return text_err(StatusCode::BAD_REQUEST, format!("{e:#}")),
            };
            let table = toml_table(&[
                ("enable", toml::Value::Boolean(enable)),
                ("level", toml::Value::String(level.into())),
                ("realtime", toml::Value::Boolean(realtime)),
            ]);
            if let Err(e) = cfg_edit::set_top_level_table(&mut tree, "access_log", table) {
                return text_err(StatusCode::BAD_REQUEST, format!("{e:#}"));
            }
            finish_write(&live, &tree, "access_log saved")
        })
        .await;
    }
    // 规格：syncookie / telemetry / admin 全局项——TOML 可配即可面板配。
    //
    // 这三条路由曾经整段丢失（admin.rs 被替换成一份少了它们的版本，残缺副本
    // 作为 admin.rs.orig / admin.rs.broken 留在仓库里）。UI 的「全局」tab 三个
    // 保存按钮（btnSynSave/btnTmSave/btnAdminSave）一直在 POST 这三个地址，
    // 后端恒 404 —— 与 geoip edits/edit/delete 那次「UI 已在调用、未接线」同类。
    if path.ends_with("/api/syncookie/save") && method == Method::POST {
        return with_json(req, |v| {
            let enabled = v.get("enabled").and_then(|b| b.as_bool()).unwrap_or(false);
            let value_on = v.get("value_on").and_then(|s| s.as_str()).unwrap_or("1");
            let value_off = v.get("value_off").and_then(|s| s.as_str()).unwrap_or("0");
            // 这两个值会被写进 net.ipv4.tcp_syncookies，运行期用
            // `parse().unwrap_or(1/0)` 解析（syncookie.rs）—— 非数字会被**静默替换**成 1/0，
            // 面板上看到的和实际写入内核的不是一回事。
            for (name, val) in [("value_on", value_on), ("value_off", value_off)] {
                if val.trim().is_empty() || val.trim().parse::<u32>().is_err() {
                    return bad_request(format!(
                        "{name} 必须是整数（sysctl 值），当前 {val:?} —— 非数字会被运行期静默替换成默认值"
                    ));
                }
                if val.len() > MAX_SYNCOOKIE_VALUE_LEN {
                    return bad_request(format!(
                        "{name} 过长（{} > {MAX_SYNCOOKIE_VALUE_LEN}）",
                        val.len()
                    ));
                }
            }
            let interval = match v.get("evaluate_interval_ms") {
                None | Some(Json::Null) => 1000u64,
                Some(x) => {
                    let Some(n) = x.as_u64() else {
                        return bad_request("evaluate_interval_ms 必须是整数");
                    };
                    // 运行期有 `.max(500)` 的下限兜底；这里显式拒绝，免得面板上
                    // 写着 1ms、实际按 500ms 跑（也顺手挡掉 0 值）。
                    if !(MIN_SYNCOOKIE_INTERVAL_MS..=MAX_SYNCOOKIE_INTERVAL_MS).contains(&n) {
                        return bad_request(format!(
                            "evaluate_interval_ms 越界（{n}，允许 {MIN_SYNCOOKIE_INTERVAL_MS}..={MAX_SYNCOOKIE_INTERVAL_MS} ms）"
                        ));
                    }
                    n
                }
            };
            let mut tree = match cfg_edit::load_tree(live.path()) {
                Ok(t) => t,
                Err(e) => return text_err(StatusCode::BAD_REQUEST, format!("{e:#}")),
            };
            let table = toml_table(&[
                ("enabled", toml::Value::Boolean(enabled)),
                ("value_on", toml::Value::String(value_on.to_string())),
                ("value_off", toml::Value::String(value_off.to_string())),
                ("evaluate_interval_ms", toml::Value::Integer(interval as i64)),
            ]);
            if let Err(e) = cfg_edit::set_top_level_table(&mut tree, "syncookie", table) {
                return text_err(StatusCode::BAD_REQUEST, format!("{e:#}"));
            }
            finish_write(&live, &tree, "syncookie saved")
        })
        .await;
    }
    if path.ends_with("/api/telemetry/save") && method == Method::POST {
        return with_json(req, |v| {
            let enabled = v.get("enabled").and_then(|b| b.as_bool()).unwrap_or(true);
            let tpath = v.get("path").and_then(|s| s.as_str()).unwrap_or("/metrics");
            // 指标路径是**安全开关**的被匹配项：h1/h2/h3 都按 `req.uri().path() != cfg.path`
            // 判定，写成 "metrics"（缺前导 /）就永远匹配不上 —— 面板显示「已启用指标」，
            // 实际 /metrics 还是 404/静态文件。这里要求绝对路径。
            if tpath.len() > MAX_TELEMETRY_PATH_LEN {
                return bad_request(format!(
                    "telemetry.path 过长（{} > {MAX_TELEMETRY_PATH_LEN} 字节）",
                    tpath.len()
                ));
            }
            if !tpath.starts_with('/') || tpath.bytes().any(|b| b.is_ascii_whitespace() || b < 0x20)
            {
                return bad_request(format!(
                    "telemetry.path 必须以 / 开头且不含空白/控制字符: {tpath:?}（否则指标永远不生效）"
                ));
            }
            if tpath.contains('?') || tpath.contains('#') {
                return bad_request(format!("telemetry.path 不能含 ? 或 #: {tpath:?}"));
            }
            let mut tree = match cfg_edit::load_tree(live.path()) {
                Ok(t) => t,
                Err(e) => return text_err(StatusCode::BAD_REQUEST, format!("{e:#}")),
            };
            let table = toml_table(&[
                ("enabled", toml::Value::Boolean(enabled)),
                ("path", toml::Value::String(tpath.into())),
            ]);
            if let Err(e) = cfg_edit::set_top_level_table(&mut tree, "telemetry", table) {
                return text_err(StatusCode::BAD_REQUEST, format!("{e:#}"));
            }
            finish_write(&live, &tree, "telemetry saved")
        })
        .await;
    }
    if path.ends_with("/api/admin/save") && method == Method::POST {
        return with_json(req, |v| {
            let realm = v
                .get("realm")
                .and_then(|s| s.as_str())
                .unwrap_or("")
                .trim()
                .to_string();
            let apath = v
                .get("path")
                .and_then(|s| s.as_str())
                .unwrap_or("")
                .trim()
                .to_string();
            if !apath.is_empty() {
                // path 是管理面唯一入口：以 / 开头才可能被匹配到，且不能是 "/"
                // （h1 用 `path.starts_with(admin.path)`，"/" 会让面板顶掉整站；
                // 未配用户时等于把管理面板公开到根路径）。
                if !apath.starts_with('/') {
                    return bad_request(format!("admin.path 必须以 / 开头: {apath:?}（否则面板不可达）"));
                }
                if apath.trim_matches('/').is_empty() {
                    return bad_request("admin.path 不能是 /（会让管理面板顶掉整站根路径）");
                }
                if apath.len() > MAX_PATH_STR
                    || apath.bytes().any(|b| b.is_ascii_whitespace() || b < 0x20)
                    || apath.contains('?')
                    || apath.contains('#')
                {
                    return bad_request(format!("admin.path 过长或含空白/控制字符/查询符: {apath:?}"));
                }
            }
            if !realm.is_empty() {
                // realm 会被拼进 `WWW-Authenticate: Basic realm="…"`（admin/h1/h2/h3/
                // telemetry 五处）：含换行等控制字符时 HeaderValue 构造失败 →
                // `.body().unwrap()` panic（每次鉴权失败打崩一个任务）；含引号会往
                // 挑战值里注入额外 auth-param。
                if let Err(e) = check_str("admin.realm", &realm, MAX_SHORT_STR) {
                    return bad_request(e);
                }
                if !realm.bytes().all(|b| (0x20..0x7f).contains(&b)) {
                    return bad_request("admin.realm 只能是可见 ASCII（会被写进 WWW-Authenticate 头）");
                }
                if realm.contains('"') || realm.contains('\\') {
                    return bad_request("admin.realm 不能含引号或反斜杠");
                }
            }
            // 旧实现 `filter_map(|x| x.as_u64().map(|n| n as u16))`：
            // 非数字元素被静默丢掉（白名单少一条，管理员看不出来）、大于 65535 的端口
            // 被截断（131165 → 9095，等于把别的端口加进了白名单）。两者都必须拒绝。
            let allow: Vec<u16> = match v.get("listeners_allow") {
                None | Some(Json::Null) => Vec::new(),
                Some(Json::Array(items)) => {
                    if let Err(e) = check_len("listeners_allow", items.len(), 128) {
                        return bad_request(e);
                    }
                    let mut out = Vec::with_capacity(items.len());
                    for (i, it) in items.iter().enumerate() {
                        let Some(n) = it.as_u64() else {
                            return bad_request(format!("listeners_allow[{i}] 必须是整数端口"));
                        };
                        if n == 0 || n > u16::MAX as u64 {
                            return bad_request(format!(
                                "listeners_allow[{i}] 越界（{n}，必须是 1..=65535）—— \
                                 截断会静默放行另一个端口"
                            ));
                        }
                        out.push(n as u16);
                    }
                    out
                }
                Some(_) => return bad_request("listeners_allow 必须是数组"),
            };
            let mut tree = match cfg_edit::load_tree(live.path()) {
                Ok(t) => t,
                Err(e) => return text_err(StatusCode::BAD_REQUEST, format!("{e:#}")),
            };
            // 只在给了非空值时才覆盖 realm/path，避免把面板上的空输入写成空串
            // （空 path 会让 admin 面板挂到根路径上）。
            //
            // 必须**基于现有 [admin] 表**改，不能从空表重建：set_top_level_table 是
            // insert（整表替换），而 AdminConfig 还有 [[admin.users]]。从空表重建会把
            // 用户数组删掉 —— finish_write → reload 后 check_admin_headers 见
            // users.is_empty() 对一切请求 401，管理面被永久锁死，只能手工改
            // config.toml 再重启才能恢复。
            let mut table = tree
                .get("admin")
                .and_then(|v| v.as_table())
                .cloned()
                .unwrap_or_default();
            if !realm.is_empty() {
                table.insert("realm".into(), toml::Value::String(realm));
            }
            if !apath.is_empty() {
                table.insert("path".into(), toml::Value::String(apath));
            }
            table.insert(
                "listeners_allow".into(),
                toml::Value::Array(
                    allow
                        .into_iter()
                        .map(|p| toml::Value::Integer(p as i64))
                        .collect(),
                ),
            );
            // 任务 3：/__metrics 的公开开关。**只在请求带了该键时才写** ——
            // 这个字段是安全开关，面板/脚本漏发它时不能被一次无关的保存动作悄悄
            // 改回默认值（反之亦然：面板上关掉它必须立即生效）。
            if let Some(mp) = v.get("metrics_public").and_then(|b| b.as_bool()) {
                table.insert("metrics_public".into(), toml::Value::Boolean(mp));
            }
            if let Err(e) =
                cfg_edit::set_top_level_table(&mut tree, "admin", toml::Value::Table(table))
            {
                return text_err(StatusCode::BAD_REQUEST, format!("{e:#}"));
            }
            finish_write(&live, &tree, "admin saved")
        })
        .await;
    }
    if path.ends_with("/api/ip_access/save") && method == Method::POST {
        return with_json(req, |v| {
            let Some(allow) = v.get("allow").and_then(|a| a.as_array()) else {
                return text_err(StatusCode::BAD_REQUEST, "missing allow array");
            };
            let Some(deny) = v.get("deny").and_then(|a| a.as_array()) else {
                return text_err(StatusCode::BAD_REQUEST, "missing deny array");
            };
            let mut tree = match cfg_edit::load_tree(live.path()) {
                Ok(t) => t,
                Err(e) => return text_err(StatusCode::BAD_REQUEST, format!("{e:#}")),
            };
            // 逐条校验允许的形态（`*` / IP / CIDR，与 access::cidr_or_exact 的判定一致）：
            // 非法条目在运行期是「当不匹配处理」——deny 里就等于拒绝规则静默失效
            // （fail-open），allow 里就是白名单少一条。必须在这里点名拒绝。
            let (allow_v, deny_v) = match (
                check_ip_access_list("allow", allow),
                check_ip_access_list("deny", deny),
            ) {
                (Ok(a), Ok(d)) => (toml::Value::Array(a), toml::Value::Array(d)),
                (Err(resp), _) | (_, Err(resp)) => return resp,
            };
            let table = toml_table(&[
                ("allow", allow_v),
                ("deny", deny_v),
            ]);
            if let Err(e) = cfg_edit::set_top_level_table(&mut tree, "ip_access", table) {
                return text_err(StatusCode::BAD_REQUEST, format!("{e:#}"));
            }
            finish_write(&live, &tree, "ip_access saved")
        })
        .await;
    }
    if path.ends_with("/api/geoip/save") && method == Method::POST {
        return with_json(req, |v| {
            let enabled = v.get("enabled").and_then(|b| b.as_bool()).unwrap_or(false);
            let db_path = v.get("db_path").and_then(|s| s.as_str()).map(str::to_string);
            if let Some(p) = db_path.as_deref() {
                if p.trim().is_empty() {
                    return bad_request("db_path 不能为空串（清空请省略该键）");
                }
                // 该路径会被 lookup/filter 拿去 open SQLite：超长/含控制字符的路径
                // 只会在每个请求上失败一次（面板显示「无数据」而非「路径错」）。
                if let Err(e) = check_str("geoip.db_path", p, MAX_DB_PATH_LEN) {
                    return bad_request(e);
                }
            }
            let mut tree = match cfg_edit::load_tree(live.path()) {
                Ok(t) => t,
                Err(e) => return text_err(StatusCode::BAD_REQUEST, format!("{e:#}")),
            };
            let mut table = toml::map::Map::new();
            table.insert("enabled".into(), toml::Value::Boolean(enabled));
            if let Some(p) = db_path {
                table.insert("db_path".into(), toml::Value::String(p));
            }
            if let Err(e) = cfg_edit::set_top_level_table(
                &mut tree,
                "geoip",
                toml::Value::Table(table),
            ) {
                return text_err(StatusCode::BAD_REQUEST, format!("{e:#}"));
            }
            finish_write(&live, &tree, "geoip saved")
        })
        .await;
    }

    // ---------- ECH / HTTPS(type65) DNS 记录（规格 §16 1.a） ----------
    //
    // 面板需要拿到「HTTPS 类型 DNS 记录」以便把 ECH 配置发布出去。
    // 自动配置已经落盘（state/ech/），这里只做读取/发布/删除的轻量视图。
    if path.ends_with("/api/ech/type65") && method == Method::GET {
        let auto_list = crate::server::ech_auto::persisted_config_list_base64();
        let auto_ready = crate::server::ech_auto::has_persisted();
        let mut s = String::from("{\"records\":");
        s.push_str(&crate::server::type65_api::list());
        s.push_str(",\"auto\":{");
        s.push_str(&format!("\"ready\":{auto_ready}"));
        s.push_str(&format!(
            ",\"pem_path\":{}",
            json_str(&crate::server::ech_auto::pem_path().display().to_string())
        ));
        match &auto_list {
            Some(b64) => {
                s.push_str(&format!(",\"config_list_b64\":{}", json_str(b64)));
            }
            None => s.push_str(",\"config_list_b64\":null"),
        }
        s.push_str("}}");
        return json_ok(s);
    }

    if path.ends_with("/api/ech/type65/publish") && method == Method::POST {
        let bytes = match collect_body(req).await {
            Ok(b) => b,
            Err(e) => return text_err(StatusCode::BAD_REQUEST, e),
        };
        let v: serde_json::Value = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(e) => return text_err(StatusCode::BAD_REQUEST, format!("json: {e}")),
        };
        // name 缺省时用自动配置的 public-name：面板只需点一下就能发布。
        let name = match v["name"].as_str().map(|s| s.trim().to_string()) {
            Some(n) if !n.is_empty() => n,
            _ => {
                let snap = live.snapshot();
                snap.listeners
                    .iter()
                    .filter_map(|l| l.ssl.as_ref())
                    .filter_map(|s| s.ech_public_name.clone())
                    .next()
                    .unwrap_or_default()
            }
        };
        if name.is_empty() {
            return text_err(
                StatusCode::BAD_REQUEST,
                "name required (or configure ssl.ech_public_name)",
            );
        }
        // 记录名要由管理员粘进 DNS（面板只做发布/展示）：越界（>253 字节整名、
        // >63 字节标签）或含空白/非 ASCII 的名字在任何解析器里都是无效 HTTPS 记录。
        if let Err(e) = check_dns_name("name", &name) {
            return bad_request(e);
        }
        // ech_config_list 缺省时取自动配置生成的 list。
        let b64 = match v["ech_config_list"].as_str().map(|s| s.trim().to_string()) {
            Some(s) if !s.is_empty() => Some(s),
            _ => crate::server::ech_auto::persisted_config_list_base64(),
        };
        let Some(b64) = b64 else {
            return text_err(
                StatusCode::BAD_REQUEST,
                "no ech_config_list given and none generated (set ssl.ech_public_name)",
            );
        };
        // ECH config list 是 base64（RFC 4648）：超长或含空白/非 base64 字符的值
        // 发出去就是客户端解不开的记录。这里只做形状检查（不校验 base64 语义，
        // 因为标准字母表与 URL 变体都放行）。
        if b64.len() > MAX_ECH_CONFIG_B64 {
            return bad_request(format!(
                "ech_config_list 过长（{} > {MAX_ECH_CONFIG_B64} 字节）",
                b64.len()
            ));
        }
        if !b64
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'-' | b'_'))
        {
            return bad_request("ech_config_list 只能是 base64 字符（不能含空白/换行）");
        }
        // ttl：`as_u64() as u32` 会把 > u32::MAX 的值**截断**成另一个 TTL
        // （4294967296 → 0，等于「不缓存」）。越界必须报错。
        let ttl = match v.get("ttl") {
            None | Some(Json::Null) => None,
            Some(x) => {
                let Some(n) = x.as_u64() else {
                    return bad_request("ttl 必须是非负整数（秒）");
                };
                if n > u32::MAX as u64 {
                    return bad_request(format!("ttl 越界（{n} > {}），会被截断成错误值", u32::MAX));
                }
                Some(n as u32)
            }
        };
        let req65 = crate::server::type65_api::Type65Request {
            name: name.clone(),
            ech_config_list: Some(b64),
            ttl,
        };
        return match crate::server::type65_api::publish(req65) {
            Ok(msg) => text_ok(msg),
            Err(e) => text_err(StatusCode::BAD_REQUEST, e),
        };
    }

    if path.ends_with("/api/ech/type65/delete") && method == Method::POST {
        let bytes = match collect_body(req).await {
            Ok(b) => b,
            Err(e) => return text_err(StatusCode::BAD_REQUEST, e),
        };
        let v: serde_json::Value = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(e) => return text_err(StatusCode::BAD_REQUEST, format!("json: {e}")),
        };
        let name = v["name"].as_str().unwrap_or("").trim().to_string();
        if name.is_empty() {
            return text_err(StatusCode::BAD_REQUEST, "name required");
        }
        // 与 publish 同一名字校验：否则删除一个「语法上不可能发布成功」的名字，
        // 只会得到含糊的 404。
        if let Err(e) = check_dns_name("name", &name) {
            return bad_request(e);
        }
        return match crate::server::type65_api::delete(&name) {
            Ok(()) => text_ok(format!("deleted {name}")),
            Err(e) => text_err(StatusCode::NOT_FOUND, e),
        };
    }

    // ---------- 账号 ----------
    if path.ends_with("/api/password") && method == Method::POST {
        let bytes = match collect_body(req).await {
            Ok(b) => b,
            Err(e) => return text_err(StatusCode::BAD_REQUEST, e),
        };
        let plain = String::from_utf8_lossy(&bytes).trim().to_string();
        // 口令长度上限：哈希成本随输入线性增长，而入口允许 32MiB 体 —— 不设上限
        // 时一个请求就能让服务端把几十 MB 数据送进 yescrypt/argon2。
        // （口令下限属安全策略，不由本处单方面决定，故未加。）
        if plain.len() > MAX_PASSWORD_BYTES {
            return bad_request(format!(
                "口令过长（{} > {MAX_PASSWORD_BYTES} 字节）",
                plain.len()
            ));
        }
        return match password::hash_password(&plain) {
            Ok(h) => {
                let username = cfg
                    .admin
                    .primary_user()
                    .map(|u| u.username.clone())
                    .unwrap_or_else(|| "admin".into());
                // 先持久化到 config.toml；失败则至少保留内存态，不让账号锁死。
                match cfg_edit::persist_admin_password(&live, &username, &h) {
                    Ok(()) => text_ok("ok"),
                    Err(e) => {
                        live.update_admin_hash(h);
                        text_err(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("已写入内存（重启丢失），磁盘持久化失败: {e:#}"),
                        )
                    }
                }
            }
            Err(e) => text_err(StatusCode::BAD_REQUEST, format!("{e:#}")),
        };
    }

    // ---------- 文件管理 ----------
    if path.ends_with("/api/files/mkdir") && method == Method::POST {
        return with_form(req, |port, path_rel| {
            with_listener_root(&cfg, port, |root| match admin_files::mkdir(root, &path_rel) {
                Ok(()) => text_ok("created"),
                Err(e) => text_err(StatusCode::BAD_REQUEST, format!("{e:#}")),
            })
        })
        .await;
    }
    if path.ends_with("/api/files/delete") && method == Method::POST {
        return with_form(req, |port, path_rel| {
            with_listener_root(&cfg, port, |root| {
                match admin_files::delete_path(root, &path_rel) {
                    Ok(()) => text_ok("deleted"),
                    Err(e) => text_err(StatusCode::BAD_REQUEST, format!("{e:#}")),
                }
            })
        })
        .await;
    }

    // P2-14（§16.14）：文件重命名 API。form: port + from + to；限同一 docroot 内。
    if path.ends_with("/api/files/rename") && method == Method::POST {
        let bytes = match collect_body(req).await {
            Ok(b) => b,
            Err(e) => return text_err(StatusCode::BAD_REQUEST, e),
        };
        let body = String::from_utf8_lossy(&bytes);
        let Some(port) = form_field(&body, "port")
            .and_then(|p| p.parse::<u16>().ok())
            .filter(|p| *p != 0)
        else {
            return text_err(StatusCode::BAD_REQUEST, "missing or invalid port");
        };
        let from = form_field(&body, "from").unwrap_or_default();
        let to = form_field(&body, "to").unwrap_or_default();
        if from.trim().is_empty() || to.trim().is_empty() {
            return text_err(StatusCode::BAD_REQUEST, "missing from/to");
        }
        let Some(lc) = cfg.listeners.iter().find(|l| l.port == port) else {
            return text_err(StatusCode::BAD_REQUEST, "unknown listener port");
        };
        // webshell 闸门必须也管 rename：先上传 `php/shell.txt`（扩展名放行），
        // 再 rename 成 `php/shell.php`，就能绕过上传检查拿到执行权。
        // 只查目标名——把可执行文件改名成不可执行的（拆掉执行权）是正常的清理操作。
        if admin_files::would_execute_on_get(lc, &to) {
            return text_err(
                StatusCode::FORBIDDEN,
                "rename blocked: target path would execute via app engine on GET",
            );
        }
        return match admin_files::rename_path(&lc.root, &from, &to) {
            Ok(()) => text_ok("renamed"),
            Err(e) => text_err(StatusCode::BAD_REQUEST, format!("{e:#}")),
        };
    }

    // Files API: /api/files?root_port=9095&path=php
    if path.ends_with("/api/files") {
        let q = req.uri().query().unwrap_or("");
        let port = query_u16(q, "port").unwrap_or(0);
        let rel = query_str(q, "path").unwrap_or_else(|| "".into());
        let Some(lc) = cfg.listeners.iter().find(|l| l.port == port) else {
            return text_err(StatusCode::BAD_REQUEST, "unknown listener port");
        };
        let root = lc.root.clone();
        if method == Method::GET {
            let list = query_str(q, "op").as_deref() != Some("read");
            if list {
                return match admin_files::list_dir(&root, &rel) {
                    Ok(entries) => {
                        let mut s = String::from("[\n");
                        for (i, e) in entries.iter().enumerate() {
                            if i > 0 {
                                s.push_str(",\n");
                            }
                            s.push_str(&format!(
                                "  {{\"name\":{},\"is_dir\":{},\"size\":{}}}",
                                json_str(&e.name),
                                e.is_dir,
                                e.size
                            ));
                        }
                        s.push_str("\n]");
                        json_ok(s)
                    }
                    Err(e) => text_err(StatusCode::BAD_REQUEST, format!("{e:#}")),
                };
            }
            return match admin_files::read_file(&root, &rel, 2 * 1024 * 1024) {
                Ok((data, binary)) => {
                    if binary {
                        text_err(StatusCode::UNSUPPORTED_MEDIA_TYPE, "binary file")
                    } else {
                        Response::builder()
                            .status(StatusCode::OK)
                            .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
                            .body(full(Bytes::from(data)))
                            .unwrap()
                    }
                }
                Err(e) => text_err(StatusCode::BAD_REQUEST, format!("{e:#}")),
            };
        }
        if method == Method::PUT || method == Method::POST {
            let bytes = match collect_body(req).await {
                Ok(b) => b,
                Err(e) => return text_err(StatusCode::BAD_REQUEST, e),
            };
            if admin_files::would_execute_on_get(lc, &rel) {
                return text_err(
                    StatusCode::FORBIDDEN,
                    "upload blocked: path would execute via app engine on GET",
                );
            }
            return match admin_files::write_file(&root, &rel, &bytes) {
                Ok(()) => text_ok("saved"),
                Err(e) => text_err(StatusCode::BAD_REQUEST, format!("{e:#}")),
            };
        }
    }

    // TLS material probe
    //
    // 这个端点只用来校验管理员**粘贴**的 PEM 正文（前端传的是 textarea 内容）。
    // 旧实现把任意字符串当路径 fs::read，并回 `ok bytes={len}`——于是它同时是
    // 「任意文件存在性 + 精确大小」探测口。只接受 PEM 正文，不接受路径。
    if path.ends_with("/api/tls/probe") && method == Method::POST {
        let bytes = match collect_body(req).await {
            Ok(b) => b,
            Err(e) => return text_err(StatusCode::BAD_REQUEST, e),
        };
        let s = String::from_utf8_lossy(&bytes);
        let s = s.trim();
        if !crate::server::ssl_material::is_pem_body(s) {
            return text_err(
                StatusCode::BAD_REQUEST,
                "expected pasted PEM body (-----BEGIN ...); file paths are not accepted here",
            );
        }
        return match crate::server::ssl_material::load_bytes(s) {
            Ok(b) => text_ok(format!("ok bytes={}", b.len())),
            Err(e) => text_err(StatusCode::BAD_REQUEST, format!("{e:#}")),
        };
    }

    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(full("admin route not found"))
        .unwrap()
}

// ---------- 保存端点实现 ----------

/// 新增/整体替换 listener。body: {"orig_port": 旧端口(改名时用), "listener": {...}}
fn save_listener(live: &Arc<LiveConfig>, v: &Json) -> Response<BoxBody> {
    // orig_port 同样要按端口范围校验：`as u16` 会把 131165 截断成 9095，
    // 于是「把站点从 131165 改名」实际改的是 9095 那个 listener。
    let orig_port = match v.get("orig_port") {
        None | Some(Json::Null) => None,
        Some(x) => {
            let Some(n) = x.as_u64() else {
                return bad_request("orig_port 必须是整数端口");
            };
            if n == 0 || n > u16::MAX as u64 {
                return bad_request(format!("orig_port 越界（{n}，必须是 1..=65535）"));
            }
            Some(n as u16)
        }
    };
    let Some(lval) = v.get("listener") else {
        return text_err(StatusCode::BAD_REQUEST, "missing listener");
    };
    // listener 是「整表替换」：一次提交会带上 apps / proxy_rules / page_rules /
    // file_open / autoindex / rate_limit 等全部子表，分表端点的上限在这里也必须生效。
    if let Err(e) = check_listener_json(lval) {
        return bad_request(e);
    }
    // 先做严格类型校验（字段名/类型/默认值），再进 TOML 树。
    let parsed: Result<ListenerConfig, _> = serde_json::from_value(lval.clone());
    if let Err(e) = parsed {
        return text_err(StatusCode::BAD_REQUEST, format!("listener 字段不合法: {e}"));
    }
    let lval = match cfg_edit::json_to_toml(lval) {
        Ok(t) => t,
        Err(e) => return text_err(StatusCode::BAD_REQUEST, format!("{e:#}")),
    };
    let mut tree = match cfg_edit::load_tree(live.path()) {
        Ok(t) => t,
        Err(e) => return text_err(StatusCode::BAD_REQUEST, format!("{e:#}")),
    };
    if let Err(e) = cfg_edit::upsert_listener(&mut tree, orig_port, lval) {
        return text_err(StatusCode::BAD_REQUEST, format!("{e:#}"));
    }
    finish_write(live, &tree, "listener saved")
}

/// body: {"port": 9095, "apps": [AppRouteConfig...]}
fn save_apps(live: &Arc<LiveConfig>, v: &Json) -> Response<BoxBody> {
    let port = match json_port(v, "port") {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let Some(apps) = v.get("apps").and_then(|a| a.as_array()) else {
        return text_err(StatusCode::BAD_REQUEST, "missing apps array");
    };
    // 整表替换前先全量校验（条数 + 每条路由的字段），任何一条不合法都不写盘。
    if let Err(e) = check_len("apps", apps.len(), MAX_APPS_PER_LISTENER) {
        return bad_request(e);
    }
    for (i, a) in apps.iter().enumerate() {
        if let Err(e) = check_app_route(a, i) {
            return bad_request(e);
        }
    }
    for a in apps {
        if let Err(e) = serde_json::from_value::<crate::config::AppRouteConfig>(a.clone()) {
            return text_err(StatusCode::BAD_REQUEST, format!("app 字段不合法: {e}"));
        }
    }
    let mut toml_apps = Vec::with_capacity(apps.len());
    for a in apps {
        match cfg_edit::json_to_toml(a) {
            Ok(t) => toml_apps.push(t),
            Err(e) => return text_err(StatusCode::BAD_REQUEST, format!("{e:#}")),
        }
    }
    let mut tree = match cfg_edit::load_tree(live.path()) {
        Ok(t) => t,
        Err(e) => return text_err(StatusCode::BAD_REQUEST, format!("{e:#}")),
    };
    if let Err(e) = cfg_edit::set_listener_key(
        &mut tree,
        port,
        "apps",
        Some(toml::Value::Array(toml_apps)),
    ) {
        return text_err(StatusCode::BAD_REQUEST, format!("{e:#}"));
    }
    finish_write(live, &tree, "apps saved")
}

/// body: {"port": 9446, "ssl": {...} | null}；null 表示去掉该站点的 TLS。
fn save_ssl(live: &Arc<LiveConfig>, v: &Json) -> Response<BoxBody> {
    let port = match json_port(v, "port") {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let mut tree = match cfg_edit::load_tree(live.path()) {
        Ok(t) => t,
        Err(e) => return text_err(StatusCode::BAD_REQUEST, format!("{e:#}")),
    };
    let ssl_val = match v.get("ssl") {
        None | Some(Json::Null) => None,
        Some(s) => {
            if let Err(e) =
                serde_json::from_value::<crate::config::SslConfig>(s.clone())
            {
                return text_err(StatusCode::BAD_REQUEST, format!("ssl 字段不合法: {e}"));
            }
            // 证书/私钥路径与 ECH public-name：超长/含控制字符的串会原样进 config.toml，
            // 之后每次握手/ECH 自动配置都拿它去开文件（失败只在日志里）。
            for key in ["cert", "key", "cert_ec", "key_ec", "ech_keys"] {
                if let Some(p) = s.get(key).and_then(|x| x.as_str()) {
                    if let Err(e) = check_str(&format!("ssl.{key}"), p, 4096) {
                        return bad_request(e);
                    }
                }
            }
            if let Some(n) = s.get("ech_public_name").and_then(|x| x.as_str()) {
                if !n.is_empty() {
                    if let Err(e) = check_dns_name("ssl.ech_public_name", n) {
                        return bad_request(e);
                    }
                }
            }
            Some(match cfg_edit::json_to_toml(s) {
                Ok(t) => t,
                Err(e) => return text_err(StatusCode::BAD_REQUEST, format!("{e:#}")),
            })
        }
    };
    if let Err(e) = cfg_edit::set_listener_key(&mut tree, port, "ssl", ssl_val) {
        return text_err(StatusCode::BAD_REQUEST, format!("{e:#}"));
    }
    finish_write(live, &tree, "ssl saved")
}

/// body: {"port": 9095, "entries": [{"path": "/x", "mode": "preview|download|execute|auto"}]}
/// 键可为 URL 路径（/a/b）或扩展名（pdf）或 *；file_open 优先级高于应用引擎（§3.2）。
fn save_file_open(live: &Arc<LiveConfig>, v: &Json) -> Response<BoxBody> {
    let port = match json_port(v, "port") {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let Some(entries) = v.get("entries").and_then(|a| a.as_array()) else {
        return text_err(StatusCode::BAD_REQUEST, "missing entries array");
    };
    // 整表替换：先全量校验（条数 + 每条键/mode + 重复键）再写。
    if let Err(e) = check_len("entries", entries.len(), MAX_LIST_ITEMS) {
        return bad_request(e);
    }
    let mut rows = Vec::with_capacity(entries.len());
    // 重复键在 TOML 里是同一张表的两次赋值（后写覆盖先写），面板上却显示两行 ——
    // 静默丢一条规则；这里直接拒绝并指出重复的键。
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for (i, e) in entries.iter().enumerate() {
        let Some(path) = e.get("path").and_then(|p| p.as_str()).map(str::trim) else {
            return text_err(StatusCode::BAD_REQUEST, "entry missing path");
        };
        let Some(mode) = e.get("mode").and_then(|m| m.as_str()) else {
            return text_err(StatusCode::BAD_REQUEST, "entry missing mode");
        };
        if path.is_empty() || path.contains('=') {
            return text_err(
                StatusCode::BAD_REQUEST,
                format!("invalid file_open key: {path}"),
            );
        }
        if let Err(e) = check_str(&format!("entries[{i}].path"), path, MAX_PATH_STR) {
            return bad_request(e);
        }
        let mode_norm = mode.trim().to_ascii_lowercase();
        // 模式归一化后再比对：旧实现在这里**区分大小写**，面板发 "Preview" 就会
        // 400，而 config.rs 的 parse_mode 是小写化后解析的 —— 两边判定必须一致。
        if !FILE_OPEN_MODES.contains(&mode_norm.as_str()) {
            return bad_request(format!(
                "entries[{i}].mode 不合法: {mode:?}（只能是 {}）",
                FILE_OPEN_MODES.join("/")
            ));
        }
        if !seen.insert(path.to_string()) {
            return bad_request(format!("entries 里有重复的键: {path:?}（后一条会静默覆盖前一条）"));
        }
        rows.push(toml::Value::String(format!("{path}={mode_norm}")));
    }
    let mut tree = match cfg_edit::load_tree(live.path()) {
        Ok(t) => t,
        Err(e) => return text_err(StatusCode::BAD_REQUEST, format!("{e:#}")),
    };
    let key = if rows.is_empty() { None } else { Some(toml::Value::Array(rows)) };
    if let Err(e) = cfg_edit::set_listener_key(&mut tree, port, "file_open", key) {
        return text_err(StatusCode::BAD_REQUEST, format!("{e:#}"));
    }
    finish_write(live, &tree, "file_open saved")
}

/// body: {"port": 9081, "enabled": true, "paths": ["/"]}
fn save_autoindex(live: &Arc<LiveConfig>, v: &Json) -> Response<BoxBody> {
    let port = match json_port(v, "port") {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let enabled = v.get("enabled").and_then(|b| b.as_bool()).unwrap_or(false);
    // 旧实现用 `filter_map(as_str)` 收集 paths：非字符串元素被**静默丢掉**
    // （面板发了 [1,"/a"] 只会存下 "/a"，管理员看不出少了一条），
    // 现在逐项校验并指出下标。空数组是合法配置（config.toml 里有 paths = []）。
    let paths: Vec<String> = match v.get("paths") {
        None | Some(Json::Null) => vec!["/".into()],
        Some(Json::Array(items)) => {
            if let Err(e) = check_len("paths", items.len(), MAX_AUTOINDEX_PATHS) {
                return bad_request(e);
            }
            let mut out = Vec::with_capacity(items.len());
            for (i, it) in items.iter().enumerate() {
                let Some(s) = it.as_str() else {
                    return bad_request(format!("paths[{i}] 必须是字符串"));
                };
                if let Err(e) = check_str(&format!("paths[{i}]"), s, MAX_PATH_STR) {
                    return bad_request(e);
                }
                out.push(s.to_string());
            }
            out
        }
        Some(_) => return bad_request("paths 必须是数组"),
    };
    let mut t = toml::map::Map::new();
    t.insert("enabled".into(), toml::Value::Boolean(enabled));
    t.insert(
        "paths".into(),
        toml::Value::Array(
            paths
                .into_iter()
                .map(toml::Value::String)
                .collect(),
        ),
    );
    // 规格 5：autoindex 上传开关与并行线程数（面板可配）。
    // UI（admin_ui.html 的 leAutoindexUpload / leUploadThreads）会发这两个键，
    // 这里不写回就等于「面板上改了、保存后消失」——autoindex 整表是重写的。
    let enable_upload = v
        .get("enable_upload")
        .and_then(|b| b.as_bool())
        .unwrap_or(false);
    // 线程数不再 `.clamp(1,16)` 静默夹紧（面板写 0 会存成 1、写 999 会存成 16，
    // 管理员看到的与实际落盘的不一致）；越界直接报错。
    let upload_threads = match v.get("upload_threads") {
        None | Some(Json::Null) => 4u64,
        Some(x) => {
            let Some(n) = x.as_u64() else {
                return bad_request("upload_threads 必须是整数");
            };
            if !(MIN_UPLOAD_THREADS..=MAX_UPLOAD_THREADS).contains(&n) {
                return bad_request(format!(
                    "upload_threads 越界（{n}，允许 {MIN_UPLOAD_THREADS}..={MAX_UPLOAD_THREADS}）"
                ));
            }
            n
        }
    };
    let upload_threads = upload_threads as u16;
    t.insert(
        "enable_upload".into(),
        toml::Value::Boolean(enable_upload),
    );
    t.insert(
        "upload_threads".into(),
        toml::Value::Integer(upload_threads as i64),
    );
    let mut tree = match cfg_edit::load_tree(live.path()) {
        Ok(x) => x,
        Err(e) => return text_err(StatusCode::BAD_REQUEST, format!("{e:#}")),
    };
    if let Err(e) = cfg_edit::set_listener_key(
        &mut tree,
        port,
        "autoindex",
        Some(toml::Value::Table(t)),
    ) {
        return text_err(StatusCode::BAD_REQUEST, format!("{e:#}"));
    }
    finish_write(live, &tree, "autoindex saved")
}

const PAGE_RULE_ACTIONS: &[&str] = &["redirect", "block", "rewrite", "pass", "cache", "header"];

/// body: {"port": 9081, "rules": [{"match_url": "/old/*", "action": "redirect", "target": "/new"}]}
fn save_page_rules(live: &Arc<LiveConfig>, v: &Json) -> Response<BoxBody> {
    let port = match json_port(v, "port") {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let Some(rules) = v.get("rules").and_then(|a| a.as_array()) else {
        return text_err(StatusCode::BAD_REQUEST, "missing rules array");
    };
    // 整表替换：先把**所有**规则查完（条数 + 每条 match_url/action/target 的语义），
    // 任何一条不合法都不写盘 —— 旧实现逐条边查边 push，查到最后一条出错时
    // 前几条已经在内存树里了（虽然有 write_tree 兜底，但语义上必须「先全量校验再写」）。
    if let Err(e) = check_len("rules", rules.len(), MAX_LIST_ITEMS) {
        return bad_request(e);
    }
    let mut out = Vec::with_capacity(rules.len());
    for (i, r) in rules.iter().enumerate() {
        if let Err(e) = check_page_rule(r, i) {
            return bad_request(e);
        }
        let Some(match_url) = r.get("match_url").and_then(|m| m.as_str()).map(str::trim) else {
            return text_err(StatusCode::BAD_REQUEST, "rule missing match_url");
        };
        // 与 check_page_rule 同一判定（那里已用小写化比较），这里取原值做清洗。
        // action 归一化成小写再落盘：page_rules::apply 用 `match action.as_str()`
        // 精确匹配，写进 "Redirect" 的规则在运行期等于不存在。
        let action = r
            .get("action")
            .and_then(|a| a.as_str())
            .unwrap_or("redirect")
            .trim()
            .to_ascii_lowercase();
        let action = action.as_str();
        if match_url.is_empty() || !PAGE_RULE_ACTIONS.contains(&action) {
            return text_err(
                StatusCode::BAD_REQUEST,
                format!("invalid rule: match_url={match_url} action={action}"),
            );
        }
        let mut t = toml::map::Map::new();
        // P2-9：品牌词在保存入口清洗（此前只在 GET 回显时 scrub，落盘 config 仍带品牌词）。
        t.insert(
            "match_url".into(),
            toml::Value::String(crate::server::page_rules::scrub_brand(match_url)),
        );
        t.insert(
            "action".into(),
            toml::Value::String(crate::server::page_rules::scrub_brand(action)),
        );
        if let Some(target) = r.get("target").and_then(|x| x.as_str()) {
            if !target.trim().is_empty() {
                t.insert(
                    "target".into(),
                    toml::Value::String(crate::server::page_rules::scrub_brand(target.trim())),
                );
            }
        }
        out.push(toml::Value::Table(t));
    }
    let mut tree = match cfg_edit::load_tree(live.path()) {
        Ok(x) => x,
        Err(e) => return text_err(StatusCode::BAD_REQUEST, format!("{e:#}")),
    };
    if let Err(e) = cfg_edit::set_listener_key(
        &mut tree,
        port,
        "page_rules",
        Some(toml::Value::Array(out)),
    ) {
        return text_err(StatusCode::BAD_REQUEST, format!("{e:#}"));
    }
    finish_write(live, &tree, "page_rules saved")
}

/// 回源 TLS 校验模式。**只能有一份**：这里原本还有一份函数内的副本，
/// 两份取值不同（副本多一个 "tor"）——`save_proxy_rules` 用模块级这份校验，
/// 于是面板下拉里能选到的 `tor` 永远存不进去，保存必报 "invalid ssl_mode: tor"，
/// 而 proxy.rs 明明是支持的（ssl_mode=tor 要求 .onion 上游并强制走 Tor）。
const SSL_MODES: &[&str] = &[
    "verify",
    "no_verify",
    "trust_self_signed",
    "off",
    "tor",
];

/// body: {"port": 9081, "rules": [{"path": "/api", "upstream": "http://127.0.0.1:8080",
///   "ssl_mode": "verify", "modify_request_headers": {}, "modify_response_headers": {}}]}
fn save_proxy_rules(live: &Arc<LiveConfig>, v: &Json) -> Response<BoxBody> {
    let port = match json_port(v, "port") {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let Some(rules) = v.get("rules").and_then(|a| a.as_array()) else {
        return text_err(StatusCode::BAD_REQUEST, "missing rules array");
    };
    // 整表替换：先全量校验所有规则（条数 / path / upstream / ssl_mode / 版本枚举 /
    // 注入头），再写盘。
    if let Err(e) = check_len("rules", rules.len(), MAX_LIST_ITEMS) {
        return bad_request(e);
    }
    for (i, r) in rules.iter().enumerate() {
        if let Err(e) = check_proxy_rule(r, i) {
            return bad_request(e);
        }
    }
    let mut out = Vec::with_capacity(rules.len());
    for r in rules {
        let Some(path) = r.get("path").and_then(|p| p.as_str()).map(str::trim) else {
            return text_err(StatusCode::BAD_REQUEST, "rule missing path");
        };
        let Some(upstream) = r.get("upstream").and_then(|u| u.as_str()).map(str::trim) else {
            return text_err(StatusCode::BAD_REQUEST, "rule missing upstream");
        };
        if !path.starts_with('/') || upstream.is_empty() {
            return text_err(
                StatusCode::BAD_REQUEST,
                format!("invalid proxy rule: path={path} upstream={upstream}"),
            );
        }
        let ssl_mode = r
            .get("ssl_mode")
            .and_then(|s| s.as_str())
            .unwrap_or("verify")
            .trim()
            .to_ascii_lowercase();
        if !SSL_MODES.contains(&ssl_mode.as_str()) {
            return text_err(StatusCode::BAD_REQUEST, format!("invalid ssl_mode: {ssl_mode}"));
        }
        let headers = |key: &str| -> Result<toml::Value, Response<BoxBody>> {
            let mut m = toml::map::Map::new();
            if let Some(items) = r.get(key).and_then(|h| h.as_object()) {
                for (k, val) in items {
                    let Some(vs) = val.as_str() else {
                        return Err(text_err(
                            StatusCode::BAD_REQUEST,
                            format!("{key}.{k} 必须是字符串"),
                        ));
                    };
                    m.insert(k.clone(), toml::Value::String(vs.to_string()));
                }
            }
            Ok(toml::Value::Table(m))
        };
        let req_headers = match headers("modify_request_headers") {
            Ok(h) => h,
            Err(resp) => return resp,
        };
        let resp_headers = match headers("modify_response_headers") {
            Ok(h) => h,
            Err(resp) => return resp,
        };
        let mut t = toml::map::Map::new();
        t.insert("path".into(), toml::Value::String(path.into()));
        t.insert("upstream".into(), toml::Value::String(upstream.into()));
        t.insert("ssl_mode".into(), toml::Value::String(ssl_mode));
        t.insert("modify_request_headers".into(), req_headers);
        t.insert("modify_response_headers".into(), resp_headers);
        // 规格 11/3、A.1：回源 TLS/HTTP 版本、连接池、Tor 出口都必须落盘。
        // 这里原本只写 5 个键，而 UI（admin_ui.html 的代理规则表）会发 10 个键 ——
        // 面板每保存一次，就会把 upstream_tls_version / upstream_http_version /
        // connection_pool / via_tor / tor_socks **静默抹掉**（整段 rules 是重写的）。
        // upstream_http_version / connection_pool / tor_socks 也是本轮才真正被
        // proxy.rs 读取，抹掉的后果从「无害」变成「功能消失」。
        if let Some(tv) = r.get("upstream_tls_version").and_then(|x| x.as_str()) {
            if !tv.trim().is_empty() {
                t.insert(
                    "upstream_tls_version".into(),
                    toml::Value::String(tv.trim().into()),
                );
            }
        }
        if let Some(hv) = r.get("upstream_http_version").and_then(|x| x.as_str()) {
            if !hv.trim().is_empty() {
                t.insert(
                    "upstream_http_version".into(),
                    toml::Value::String(hv.trim().into()),
                );
            }
        }
        if let Some(cp) = r.get("connection_pool").and_then(|x| x.as_bool()) {
            t.insert("connection_pool".into(), toml::Value::Boolean(cp));
        }
        if let Some(vt) = r.get("via_tor").and_then(|x| x.as_bool()) {
            t.insert("via_tor".into(), toml::Value::Boolean(vt));
        }
        if let Some(ts) = r.get("tor_socks").and_then(|x| x.as_str()) {
            let ts = ts.trim();
            if !ts.is_empty() {
                t.insert("tor_socks".into(), toml::Value::String(ts.into()));
            }
        }
        out.push(toml::Value::Table(t));
    }
    let mut tree = match cfg_edit::load_tree(live.path()) {
        Ok(x) => x,
        Err(e) => return text_err(StatusCode::BAD_REQUEST, format!("{e:#}")),
    };
    if let Err(e) = cfg_edit::set_listener_key(
        &mut tree,
        port,
        "proxy_rules",
        Some(toml::Value::Array(out)),
    ) {
        return text_err(StatusCode::BAD_REQUEST, format!("{e:#}"));
    }
    finish_write(live, &tree, "proxy_rules saved")
}

/// 统一收尾：校验 + 原子写盘 + 热重载。
fn finish_write(live: &Arc<LiveConfig>, tree: &toml::Value, ok_msg: &str) -> Response<BoxBody> {
    match cfg_edit::write_tree(live, tree) {
        Ok(()) => text_ok(ok_msg.to_string()),
        Err(e) => text_err(StatusCode::BAD_REQUEST, format!("{e:#}")),
    }
}

// ---------- 写接口的取值边界 ----------
//
// 原则（与全局要求一致）：
// 1. 解析后、落盘/落库前校验；越界回 400 + **可读原因**（指出是哪个字段、哪个下标）。
// 2. 不静默忽略/截断/夹紧：旧代码里 `.filter_map(as_u64)`、`.clamp(1,16)`、
//    `parse().ok().unwrap_or(默认值)`、`p as u16` 都属于这一类（面板显示「已保存」，
//    磁盘上却是别的东西）。
// 3. 「整表替换」类接口（listener / apps / proxy_rules / page_rules / file_open）
//    先全量校验再写，不许存一半。
//
// 每条上限都注明**理由与越界后果**，因为它们不是随手挑的数。

/// 单次提交里集合类字段的通用上限（规则/条目/条目对象数）。
const MAX_LIST_ITEMS: usize = 512;
/// 单 listener 的 app 路由上限。本仓库 config.toml 的样例 listener 有 18 条，
/// 64 条留足余量；每条路由都可能拉起引擎进程/FFI 实例，无上限时一次保存就能
/// 让热重载去 spawn 上千个进程。
const MAX_APPS_PER_LISTENER: usize = 64;
/// 单条 app 路由的 paths/extensions 数量上限。
const MAX_APP_PATHS: usize = 32;
/// 引擎名长度上限（引擎名只用来在注册表里查库，超长的一定是错的）。
const MAX_ENGINE_LEN: usize = 32;
/// 引擎并行 worker 上限。php 引擎直接把它写进 php-fpm 的 `pm.max_children`
/// 与 `PHP_FCGI_CHILDREN`（见 apps/php.rs）：每个 worker 常驻几十 MB，
/// 越界（比如 100000）会让 fpm 起不来 → 整个站点 502；0 则被 `.max(1)` 静默改成 1
/// （面板显示 0、实际跑 1）。
const MAX_APP_WORKERS: u64 = 128;
/// 通用短字符串（枚举名/用户名/realm/level/地址等）。
const MAX_SHORT_STR: usize = 128;
/// 路径类字符串（docroot/root/匹配路径/file_open 键）。
const MAX_PATH_STR: usize = 512;
/// URL / 回源地址类字符串（上游、redirect target）。
const MAX_URL_STR: usize = 2048;
/// 注入头的名字/值长度上限（真实头名 <64、值通常 <1KB；超长只是把配置与每个
/// 请求的头部一起撑大）。
const MAX_HEADER_NAME_LEN: usize = 128;
const MAX_HEADER_VALUE_LEN: usize = 4096;
/// 单条代理规则可注入的请求/响应头数量上限。
const MAX_HEADER_ITEMS: usize = 64;
/// ip_access allow/deny 单表条目上限（每个请求都要线性扫描，见 access::is_allowed）。
const MAX_IP_ACCESS_ITEMS: usize = 1024;
/// 管理员口令长度上限。哈希成本随输入线性增长、面板输入框也没有千字符口令的用法；
/// 不设上限时 32MiB 的请求体可以被当成口令送进 yescrypt/argon2。
const MAX_PASSWORD_BYTES: usize = 1024;
/// HTTPS(type65) 记录名（DNS 名）与其标签上限，见 RFC 1035/9460。
const MAX_DNS_NAME_LEN: usize = 253;
const MAX_DNS_LABEL_LEN: usize = 63;
/// ECH config list（base64）长度上限：真实值几百字节，8KB 足够宽松；
/// 越界只是把面板 JSON 与记录表撑大。
const MAX_ECH_CONFIG_B64: usize = 8192;
/// syncookie 评估间隔（ms）。运行期有 `.max(500)` 的下限兜底（syncookie.rs），
/// 这里显式拒绝而不是让面板的 1ms 配置在运行期被悄悄改成 500ms。
const MIN_SYNCOOKIE_INTERVAL_MS: u64 = 500;
const MAX_SYNCOOKIE_INTERVAL_MS: u64 = 60_000;
/// syncookie 写入的 sysctl 值：运行期用 `parse().unwrap_or(1/0)` 解析，
/// 非数字会被静默替换成 1 —— 必须在保存时拒绝。
const MAX_SYNCOOKIE_VALUE_LEN: usize = 32;
/// `/__metrics` 路径上限与形状（必须是绝对路径）。
const MAX_TELEMETRY_PATH_LEN: usize = 256;
/// autoindex 上传并行线程数：UI 只给 1..16。
const MIN_UPLOAD_THREADS: u64 = 1;
const MAX_UPLOAD_THREADS: u64 = 16;
/// autoindex 匹配路径数量上限。
const MAX_AUTOINDEX_PATHS: usize = 64;
/// geoip db_path 长度上限（真实路径远小于此）。
const MAX_DB_PATH_LEN: usize = 1024;
/// 回源 TLS 版本：proxy.rs 把值小写化并去掉 `.`/`_` 后只认 tls12/tls13
/// （`tls1.2`/`TLSv1.3` 等变体都落到这两支）；别的值会被**静默忽略**（回落自动协商）。
const UPSTREAM_TLS_VERSIONS: &[&str] = &["tls12", "tlsv12", "tls13", "tlsv13"];
/// 回源 HTTP 版本：proxy.rs 只对 `h2` 特判（其余一律按 h1 处理），
/// 写 "http2" 这种值会静默变成 h1。
const UPSTREAM_HTTP_VERSIONS: &[&str] = &["h1", "h2"];
/// `http_versions` 允许的协议名（config.rs 的 allows_h1/h2/h3 只认这些，
/// 写错（如 "h4" 或 "HTTP1"）会让该协议静默不服务）。
const HTTP_VERSION_TOKENS: &[&str] = &["h1", "http/1.1", "h2", "http/2", "h3", "http/3"];
/// file_open 的 mode 取值（与 config.rs 的 parse_mode 一致）。
const FILE_OPEN_MODES: &[&str] = &["auto", "preview", "download", "execute"];

/// 400 的简写（校验失败统一走这里，保证响应形状一致）。
fn bad_request(msg: impl Into<Bytes>) -> Response<BoxBody> {
    text_err(StatusCode::BAD_REQUEST, msg)
}

/// 取 JSON 里的端口号。
///
/// 为什么不能 `as_u64() as u16`：那是**静默截断** —— 131165 (=9095+2×65536) 会变成
/// 9095，面板上「保存到 131165 端口」实际改的是 9095 那个站点。端口不是合法 u16
/// 就报错，让面板看到真实原因。
fn json_port(v: &Json, key: &str) -> Result<u16, Response<BoxBody>> {
    let Some(n) = v.get(key).and_then(|p| p.as_u64()) else {
        return Err(bad_request(format!("missing {key}")));
    };
    if n == 0 || n > u16::MAX as u64 {
        return Err(bad_request(format!(
            "{key} 越界（{n}，必须是 1..=65535 的端口）"
        )));
    }
    Ok(n as u16)
}

/// 字符串长度/内容检查（长度按字节）。
fn check_str(what: &str, s: &str, max: usize) -> Result<(), String> {
    if s.len() > max {
        return Err(format!("{what} 过长（{} > {max} 字节）", s.len()));
    }
    if s.chars().any(|c| c.is_control()) {
        return Err(format!("{what} 含控制字符（换行/制表等）"));
    }
    Ok(())
}

/// 集合类字段的数量检查。
fn check_len(what: &str, n: usize, max: usize) -> Result<(), String> {
    if n > max {
        return Err(format!("{what} 过多（{n} > {max}）"));
    }
    Ok(())
}

/// 注入头 name/value 的 HTTP 合法性。
///
/// 为什么用 http crate 自己判而不是手写字符集：proxy.rs 在**发出请求**时用
/// `builder.header(k, v)`（无效值会让 `.body()` 失败 → 该线路每个请求 502），
/// 响应方向则用 `HeaderName::from_bytes`/`HeaderValue::from_bytes` 静默丢弃
/// （管理员配的头永远不生效）。两边都不该靠配置里放非法值来发现。
/// 含 CR/LF 的值更是经典的头部注入/请求走私形态。
fn check_header_pair(what: &str, name: &str, value: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err(format!("{what} 的头名不能为空"));
    }
    if name.len() > MAX_HEADER_NAME_LEN {
        return Err(format!("{what} 的头名过长（{} > {MAX_HEADER_NAME_LEN}）", name.len()));
    }
    if value.len() > MAX_HEADER_VALUE_LEN {
        return Err(format!(
            "{what}.{name} 的值过长（{} > {MAX_HEADER_VALUE_LEN}）",
            value.len()
        ));
    }
    if http::header::HeaderName::from_bytes(name.as_bytes()).is_err() {
        return Err(format!(
            "{what} 的头名非法: {name:?}（必须是 RFC 9110 token，不能含空格/冒号/控制字符）"
        ));
    }
    if http::header::HeaderValue::from_bytes(value.as_bytes()).is_err() {
        return Err(format!(
            "{what}.{name} 的值非法: 不能含 CR/LF 或控制字符（会造成头部注入）"
        ));
    }
    // 非 ASCII 单独判：`HeaderValue` 只拒绝控制字符，0x80+ 会按 obs-text 原样发出
    // （h1 上属遗留形态、h2/h3 与中间缓存处理各不相同）；头值配成中文没有正当场景，
    // 保存时明确拒绝而不是留到线上看乱码。
    if !value.bytes().all(|b| (0x20..0x7f).contains(&b) || b == b'\t') {
        return Err(format!(
            "{what}.{name} 的值含非 ASCII 字节: {value:?}（HTTP 头值只能是可见 ASCII）"
        ));
    }
    Ok(())
}

/// 校验 `modify_request_headers` / `modify_response_headers` 映射。
fn check_header_map(rule: &Json, key: &str, idx: usize) -> Result<(), String> {
    let Some(obj) = rule.get(key) else {
        return Ok(());
    };
    if obj.is_null() {
        return Ok(());
    }
    let Some(map) = obj.as_object() else {
        return Err(format!("rule[{idx}].{key} 必须是对象（头名→头值）"));
    };
    if map.len() > MAX_HEADER_ITEMS {
        return Err(format!(
            "rule[{idx}].{key} 项数过多（{} > {MAX_HEADER_ITEMS}）",
            map.len()
        ));
    }
    for (k, v) in map {
        let Some(vs) = v.as_str() else {
            return Err(format!("rule[{idx}].{key}.{k} 必须是字符串"));
        };
        check_header_pair(&format!("rule[{idx}].{key}"), k, vs)?;
    }
    Ok(())
}

/// DNS 名（HTTPS/type65 记录名、ECH public-name）校验。
///
/// 为什么必须判：这些名字要由管理员粘进 DNS 配置（面板只负责发布/展示），
/// 而 DNS 的硬上限是「整名 ≤ 253 字节、单标签 ≤ 63 字节」—— 越界的名字在任何
/// 解析器里都是无效记录；含空白/控制字符的名字此前会被原样存下并显示在面板上。
fn check_dns_name(what: &str, name: &str) -> Result<(), String> {
    let n = name.trim().trim_end_matches('.');
    if n.is_empty() {
        return Err(format!("{what} 不能为空"));
    }
    if n.len() > MAX_DNS_NAME_LEN {
        return Err(format!(
            "{what} 过长（{} > {MAX_DNS_NAME_LEN} 字节，DNS 名上限）",
            n.len()
        ));
    }
    for label in n.split('.') {
        if label.is_empty() {
            return Err(format!("{what} 有空标签（连续的点/首尾点）: {name:?}"));
        }
        if label.len() > MAX_DNS_LABEL_LEN {
            return Err(format!(
                "{what} 的标签过长（{} > {MAX_DNS_LABEL_LEN} 字节）: {label:?}",
                label.len()
            ));
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(format!(
                "{what} 含非法字符: {label:?}（只允许 ASCII 字母数字与 - _）"
            ));
        }
    }
    Ok(())
}

/// ip_access 条目：`*` / 单个 IP / CIDR。
///
/// 必须与 `access::cidr_or_exact` 的判定逐字对齐：它把解析不了的条目**当不匹配**处理 ——
/// 在 deny 里就等于「这条拒绝规则静默失效」（fail-open），在 allow 里就是悄悄少一条白名单。
fn check_ip_access_entry(list: &str, idx: usize, s: &str) -> Result<(), String> {
    let p = s.trim();
    if p.is_empty() {
        return Err(format!("{list}[{idx}] 为空"));
    }
    if p == "*" {
        // 语义明确（放行/拒绝全部），但很容易是笔误，单独提示。
        return Ok(());
    }
    if let Some((net, bits)) = p.split_once('/') {
        let base: std::net::IpAddr = net
            .parse()
            .map_err(|_| format!("{list}[{idx}] 的网络地址不合法: {p:?}"))?;
        let bits: u32 = bits
            .parse()
            .map_err(|_| format!("{list}[{idx}] 的前缀长度不合法: {p:?}"))?;
        let max = if base.is_ipv4() { 32 } else { 128 };
        if bits > max {
            return Err(format!("{list}[{idx}] 前缀长度越界（{p:?}，最大 /{max}）"));
        }
        return Ok(());
    }
    p.parse::<std::net::IpAddr>()
        .map(|_| ())
        .map_err(|_| format!("{list}[{idx}] 不是合法 IP/CIDR: {p:?}"))
}

/// 整份 ip 列表检查（allow/deny 共用）。
fn check_ip_access_list(list: &str, items: &[Json]) -> Result<Vec<toml::Value>, Response<BoxBody>> {
    check_len(list, items.len(), MAX_IP_ACCESS_ITEMS).map_err(bad_request)?;
    let mut out = Vec::with_capacity(items.len());
    for (i, it) in items.iter().enumerate() {
        let Some(s) = it.as_str() else {
            return Err(bad_request(format!("{list}[{i}] 必须是字符串")));
        };
        if let Err(e) = check_ip_access_entry(list, i, s) {
            return Err(bad_request(e));
        }
        out.push(toml::Value::String(s.trim().to_string()));
    }
    Ok(out)
}

/// 页面规则校验（save_page_rules 与 /api/pagerules 共用；idx 用于指出是第几条）。
fn check_page_rule(rule: &Json, idx: usize) -> Result<(), String> {
    let match_url = rule
        .get("match_url")
        .and_then(|m| m.as_str())
        .map(str::trim)
        .unwrap_or("");
    if match_url.is_empty() {
        return Err(format!("rule[{idx}] 缺少 match_url"));
    }
    if match_url.len() > MAX_PATH_STR {
        return Err(format!("rule[{idx}].match_url 过长（{} > {MAX_PATH_STR}）", match_url.len()));
    }
    // 请求路径恒以 `/` 开头，`path_matches` 是字面前缀/全等比较 ——
    // 不以 `/` 开头的规则永远匹配不上（面板显示已保存、实际从不生效）。
    if !match_url.starts_with('/') {
        return Err(format!(
            "rule[{idx}].match_url 必须以 / 开头（当前 {match_url:?}），否则永远匹配不到请求"
        ));
    }
    let action = rule
        .get("action")
        .and_then(|a| a.as_str())
        .unwrap_or("redirect")
        .trim()
        .to_ascii_lowercase();
    if !PAGE_RULE_ACTIONS.contains(&action.as_str()) {
        return Err(format!(
            "rule[{idx}] action 不合法: {action:?}（只能是 {}）",
            PAGE_RULE_ACTIONS.join("/")
        ));
    }
    let target = rule.get("target").and_then(|t| t.as_str()).map(str::trim);
    if let Some(t) = target {
        if !t.is_empty() {
            if t.len() > MAX_URL_STR {
                return Err(format!("rule[{idx}].target 过长（{} > {MAX_URL_STR}）", t.len()));
            }
            // redirect 的 target 会直接进 `Location:` 头（page_rules::redirect_response
            // 用 `.header(...).unwrap()` 构造响应）：含控制字符（换行等）时 HeaderValue
            // 构造失败 → **每个命中该规则的请求都 panic**。非 ASCII 会被按 obs-text 原样
            // 发出（h2/h3 与中间缓存处理不一），一并拒绝。
            if action == "redirect" {
                check_header_pair(&format!("rule[{idx}].target(Location)"), "location", t)?;
            }
            match action.as_str() {
                // rewrite 的 target 会与请求路径做前缀拼接，非绝对路径拼出来的东西
                // 不再是合法请求路径（后续 404，且日志里看不出原因）。
                "rewrite" => {
                    if !t.starts_with('/') {
                        return Err(format!(
                            "rule[{idx}].target（rewrite）必须以 / 开头: {t:?}"
                        ));
                    }
                }
                // pass 的 target 当上游 URL 用（proxy::upstream_parts 只认 http/https
                // 且有 host），非法值 = 该路径每个请求都失败。
                "pass" => check_upstream(&format!("rule[{idx}].target(pass)"), t)?,
                // header 的 target 形如 "Name: value"，运行期按 ':' 拆开，
                // 名字/值非法时**静默丢弃**（page_rules::response_headers 的 continue）
                // —— 管理员配的头永远不生效。
                "header" => {
                    let (name, value) = t.split_once(':').ok_or_else(|| {
                        format!("rule[{idx}].target（header）必须是 \"Name: value\" 形式: {t:?}")
                    })?;
                    check_header_pair(&format!("rule[{idx}].target(header)"), name.trim(), value.trim())?;
                }
                // cache 的 target 就是 Cache-Control 值：含控制字符时运行期静默丢弃。
                "cache" => {
                    if t.chars().any(|c| c.is_control()) {
                        return Err(format!("rule[{idx}].target（cache）含控制字符"));
                    }
                }
                _ => {}
            }
        }
    }
    // header / rewrite / pass 缺 target 时运行期直接 `continue`（静默忽略整条规则）。
    if target.map(|t| t.is_empty()).unwrap_or(true)
        && matches!(action.as_str(), "header" | "rewrite" | "pass")
    {
        return Err(format!(
            "rule[{idx}] action={action} 必须给 target（缺 target 时运行期会静默跳过这条规则）"
        ));
    }
    Ok(())
}

/// 上游地址校验（proxy.rs 的 `upstream_parts`：必须是 http/https 且带 host）。
fn check_upstream(what: &str, upstream: &str) -> Result<(), String> {
    if upstream.len() > MAX_URL_STR {
        return Err(format!("{what} 过长（{} > {MAX_URL_STR}）", upstream.len()));
    }
    let uri: http::Uri = upstream
        .parse()
        .map_err(|e| format!("{what} 不是合法 URL: {upstream:?} ({e})"))?;
    match uri.scheme_str() {
        Some("http") | Some("https") => {}
        other => {
            return Err(format!(
                "{what} 的 scheme 不支持: {other:?}（上游只支持 http/https）"
            ))
        }
    }
    if uri.host().map(|h| h.is_empty()).unwrap_or(true) {
        return Err(format!("{what} 缺少主机名: {upstream:?}"));
    }
    Ok(())
}

/// 代理规则校验（save_proxy_rules 与 /api/proxyrules 共用）。
fn check_proxy_rule(rule: &Json, idx: usize) -> Result<(), String> {
    let path = rule
        .get("path")
        .and_then(|p| p.as_str())
        .map(str::trim)
        .unwrap_or("");
    if path.is_empty() {
        return Err(format!("rule[{idx}] 缺少 path"));
    }
    if path.len() > MAX_PATH_STR {
        return Err(format!("rule[{idx}].path 过长（{} > {MAX_PATH_STR}）", path.len()));
    }
    if !path.starts_with('/') {
        return Err(format!("rule[{idx}].path 必须以 / 开头: {path:?}"));
    }
    let upstream = rule
        .get("upstream")
        .and_then(|u| u.as_str())
        .map(str::trim)
        .unwrap_or("");
    if upstream.is_empty() {
        return Err(format!("rule[{idx}] 缺少 upstream"));
    }
    check_upstream(&format!("rule[{idx}].upstream"), upstream)?;
    let ssl_mode = rule
        .get("ssl_mode")
        .and_then(|s| s.as_str())
        .unwrap_or("verify")
        .trim()
        .to_ascii_lowercase();
    if !SSL_MODES.contains(&ssl_mode.as_str()) {
        return Err(format!(
            "rule[{idx}] ssl_mode 不合法: {ssl_mode:?}（只能是 {}）",
            SSL_MODES.join("/")
        ));
    }
    if let Some(tv) = rule.get("upstream_tls_version").and_then(|x| x.as_str()) {
        let tv = tv.trim();
        if !tv.is_empty() {
            let norm = tv.to_ascii_lowercase().replace(['.', '_'], "");
            if !UPSTREAM_TLS_VERSIONS.contains(&norm.as_str()) {
                return Err(format!(
                    "rule[{idx}].upstream_tls_version 不合法: {tv:?}（只能是 tls1.2 / tls1.3）—— \
                     其它值会被静默忽略、回落自动协商"
                ));
            }
        }
    }
    if let Some(hv) = rule.get("upstream_http_version").and_then(|x| x.as_str()) {
        let hv = hv.trim().to_ascii_lowercase();
        if !hv.is_empty() && !UPSTREAM_HTTP_VERSIONS.contains(&hv.as_str()) {
            return Err(format!(
                "rule[{idx}].upstream_http_version 不合法: {hv:?}（只能是 h1 / h2）—— \
                     只有 h2 会被识别，别的值等于写 h1"
            ));
        }
    }
    if let Some(ts) = rule.get("tor_socks").and_then(|x| x.as_str()) {
        let ts = ts.trim();
        if !ts.is_empty() {
            if ts.len() > MAX_SHORT_STR {
                return Err(format!("rule[{idx}].tor_socks 过长（{} > {MAX_SHORT_STR}）", ts.len()));
            }
            if ts.chars().any(|c| c.is_control()) {
                return Err(format!("rule[{idx}].tor_socks 含控制字符"));
            }
        }
    }
    check_header_map(rule, "modify_request_headers", idx)?;
    check_header_map(rule, "modify_response_headers", idx)?;
    Ok(())
}

/// app 路由校验（save_apps 与 save_listener 共用）。
fn check_app_route(app: &Json, idx: usize) -> Result<(), String> {
    let engine = app
        .get("engine")
        .and_then(|e| e.as_str())
        .map(str::trim)
        .unwrap_or("");
    if engine.is_empty() {
        return Err(format!("app[{idx}] 缺少 engine"));
    }
    // 引擎名只是注册表键（apps/mod.rs 里按小写名字分派）；这里只挡住
    // 「超长/含控制字符」这种一定错的值，不枚举引擎 —— 未知引擎在请求时会回 501
    // 并在 reconcile 日志里点名，不是静默失败。
    if engine.len() > MAX_ENGINE_LEN
        || !engine
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'+' | b'.'))
    {
        return Err(format!(
            "app[{idx}].engine 不是合法引擎名: {engine:?}（只允许 ASCII 字母数字与 _ - . +，≤{MAX_ENGINE_LEN} 字节）"
        ));
    }
    if let Some(workers) = app.get("workers").and_then(|w| w.as_u64()) {
        if workers == 0 || workers > MAX_APP_WORKERS {
            return Err(format!(
                "app[{idx}].workers 越界（{workers}，允许 1..={MAX_APP_WORKERS}）—— \
                 该值会直接写进 php-fpm 的 pm.max_children / PHP_FCGI_CHILDREN，\
                 0 会被运行期静默改成 1、过大则让 fpm 起不来（站点 502）"
            ));
        }
    }
    for key in ["paths", "extensions", "entry"] {
        let Some(arr) = app.get(key).and_then(|a| a.as_array()) else {
            continue;
        };
        check_len(&format!("app[{idx}].{key}"), arr.len(), MAX_APP_PATHS)?;
        for (i, it) in arr.iter().enumerate() {
            let Some(s) = it.as_str() else {
                return Err(format!("app[{idx}].{key}[{i}] 必须是字符串"));
            };
            if s.len() > MAX_PATH_STR {
                return Err(format!(
                    "app[{idx}].{key}[{i}] 过长（{} > {MAX_PATH_STR}）",
                    s.len()
                ));
            }
            if s.chars().any(|c| c.is_control()) {
                return Err(format!("app[{idx}].{key}[{i}] 含控制字符"));
            }
            // 路由前缀必须绝对：`would_handle` 拿请求路径做前缀比较，
            // 相对前缀永远匹配不上（面板显示已保存、路由却不生效）。
            if key == "paths" && !s.trim().is_empty() && !s.starts_with('/') {
                return Err(format!(
                    "app[{idx}].paths[{i}] 必须以 / 开头: {s:?}"
                ));
            }
        }
    }
    for key in ["socket", "index", "php_bin", "libc"] {
        if let Some(s) = app.get(key).and_then(|x| x.as_str()) {
            if s.len() > MAX_PATH_STR {
                return Err(format!("app[{idx}].{key} 过长（{} > {MAX_PATH_STR}）", s.len()));
            }
            if s.chars().any(|c| c.is_control()) {
                return Err(format!("app[{idx}].{key} 含控制字符"));
            }
        }
    }
    // 各类路径字段：真实路径（Windows 长路径也够）+ 无控制字符。
    const APP_PATH_KEYS: &[&str] = &["docroot", "source_dir", "out_dir", "deps_dir", "lib"];
    for key in APP_PATH_KEYS {
        if let Some(p) = app.get(key).and_then(|x| x.as_str()) {
            // 4096 与 admin_files::MAX_REL_PATH_LEN 对齐（同一类「路径」语义）。
            if p.len() > 4096 {
                return Err(format!("app[{idx}].{key} 过长（{} > 4096 字节）", p.len()));
            }
            if p.contains('\0') || p.chars().any(|c| c.is_control()) {
                return Err(format!("app[{idx}].{key} 含控制字符"));
            }
        }
    }
    if let Some(t) = app.get("init_timeout_secs").and_then(|x| x.as_u64()) {
        // 初始化超时：0 会让「等 sidecar/FFI 就绪」立即超时（应用永远起不来）。
        if t == 0 || t > 3600 {
            return Err(format!(
                "app[{idx}].init_timeout_secs 越界（{t}，允许 1..=3600 秒）"
            ));
        }
    }
    Ok(())
}

/// listener（整体替换）的取值校验：`/api/listener/save` 一次能带进 apps /
/// proxy_rules / page_rules / file_open / autoindex / ssl 等全部子表 ——
/// 绕过分表端点的上限，所以这里必须把它们**一并**全量校验。
fn check_listener_json(l: &Json) -> Result<(), String> {
    if !l.is_object() {
        return Err("listener 必须是对象".into());
    }
    // 端口：serde 已保证能进 u16，但仍是主键级字段，显式判一次。
    if let Some(p) = l.get("port").and_then(|x| x.as_u64()) {
        if p == 0 || p > u16::MAX as u64 {
            return Err(format!("listener.port 越界（{p}，必须是 1..=65535）"));
        }
    }
    if let Some(a) = l.get("address").and_then(|x| x.as_str()) {
        if a.len() > MAX_SHORT_STR || a.chars().any(|c| c.is_control()) {
            return Err("listener.address 过长或含控制字符".into());
        }
    }
    // root：空串会让 `Config::load` 的 resolve_paths 把 `<config 目录>` 当站点根
    // （www 上直接暴露 config.toml —— 里面有管理员口令哈希），"."/".." 同理；
    // 含控制字符的路径在 fs 层还会以怪错冒泡。
    if let Some(r) = l.get("root").and_then(|x| x.as_str()) {
        let rt = r.trim();
        if rt.is_empty() || rt == "." || rt == ".." {
            return Err(format!(
                "listener.root 不能是空串/. /..（会把 config.toml 所在目录当站点根）: {r:?}"
            ));
        }
        if let Err(e) = check_str("listener.root", r, 4096) {
            return Err(e);
        }
    }
    if let Some(sn) = l.get("server_name").and_then(|x| x.as_str()) {
        if sn.len() > MAX_DNS_NAME_LEN || sn.chars().any(|c| c.is_control()) {
            return Err(format!(
                "listener.server_name 越界（> {MAX_DNS_NAME_LEN} 字节或含控制字符）"
            ));
        }
    }
    if let Some(sp) = l.get("status_path").and_then(|x| x.as_str()) {
        if !sp.is_empty() && (!sp.starts_with('/') || sp.len() > MAX_PATH_STR) {
            return Err(format!("listener.status_path 必须以 / 开头且 ≤ {MAX_PATH_STR} 字节: {sp:?}"));
        }
    }
    if let Some(hv) = l.get("http_versions").and_then(|x| x.as_array()) {
        check_len("listener.http_versions", hv.len(), 3)?;
        for (i, v) in hv.iter().enumerate() {
            let Some(s) = v.as_str() else {
                return Err(format!("listener.http_versions[{i}] 必须是字符串"));
            };
            if !HTTP_VERSION_TOKENS.iter().any(|t| t.eq_ignore_ascii_case(s.trim())) {
                return Err(format!(
                    "listener.http_versions[{i}] 不认识: {s:?}（只能是 {}）—— \
                     写错会让该协议静默不服务",
                    HTTP_VERSION_TOKENS.join("/")
                ));
            }
        }
    }
    if let Some(apps) = l.get("apps").and_then(|x| x.as_array()) {
        check_len("listener.apps", apps.len(), MAX_APPS_PER_LISTENER)?;
        for (i, a) in apps.iter().enumerate() {
            check_app_route(a, i)?;
        }
    }
    if let Some(rules) = l.get("proxy_rules").and_then(|x| x.as_array()) {
        check_len("listener.proxy_rules", rules.len(), MAX_LIST_ITEMS)?;
        for (i, r) in rules.iter().enumerate() {
            check_proxy_rule(r, i)?;
        }
    }
    if let Some(rules) = l.get("page_rules").and_then(|x| x.as_array()) {
        check_len("listener.page_rules", rules.len(), MAX_LIST_ITEMS)?;
        for (i, r) in rules.iter().enumerate() {
            check_page_rule(r, i)?;
        }
    }
    if let Some(fo) = l.get("file_open").and_then(|x| x.as_array()) {
        check_len("listener.file_open", fo.len(), MAX_LIST_ITEMS)?;
        // 三种合法形态（内联 "k=mode" 串 / {path,mode} 对象 / map）里，
        // 字符串形态的 mode 由 config.rs::parse_mode 校验（会报错，不会静默丢），
        // 这里补上长度/形状检查。
        for (i, it) in fo.iter().enumerate() {
            match it {
                Json::String(row) => {
                    if row.len() > MAX_PATH_STR {
                        return Err(format!("listener.file_open[{i}] 过长（> {MAX_PATH_STR} 字节）"));
                    }
                    let (k, mode) = row.split_once('=').ok_or_else(|| {
                        format!("listener.file_open[{i}] 缺少 '=': {row:?}")
                    })?;
                    if k.trim().is_empty() {
                        return Err(format!("listener.file_open[{i}] 的键为空"));
                    }
                    let m = mode.trim().to_ascii_lowercase();
                    if !FILE_OPEN_MODES.contains(&m.as_str()) {
                        return Err(format!(
                            "listener.file_open[{i}] mode 不合法: {m:?}（只能是 {}）",
                            FILE_OPEN_MODES.join("/")
                        ));
                    }
                }
                Json::Object(o) => {
                    let Some(p) = o.get("path").and_then(|x| x.as_str()) else {
                        return Err(format!("listener.file_open[{i}] 缺少 path"));
                    };
                    if p.trim().is_empty() || p.len() > MAX_PATH_STR {
                        return Err(format!("listener.file_open[{i}].path 为空或过长"));
                    }
                    // mode 缺失/非法由 serde 的 FileOpenMode 枚举报错（400）。
                }
                _ => return Err(format!("listener.file_open[{i}] 必须是字符串或 {{path,mode}} 对象")),
            }
        }
    }
    if let Some(ai) = l.get("autoindex") {
        if let Some(o) = ai.as_object() {
            if let Some(paths) = o.get("paths").and_then(|x| x.as_array()) {
                check_len("listener.autoindex.paths", paths.len(), MAX_AUTOINDEX_PATHS)
                    ?;
                for (i, p) in paths.iter().enumerate() {
                    let Some(s) = p.as_str() else {
                        return Err(format!("listener.autoindex.paths[{i}] 必须是字符串"));
                    };
                    if s.len() > MAX_PATH_STR {
                        return Err(format!(
                            "listener.autoindex.paths[{i}] 过长（{} > {MAX_PATH_STR}）",
                            s.len()
                        ));
                    }
                }
            }
            if let Some(t) = o.get("upload_threads").and_then(|x| x.as_u64()) {
                if !(MIN_UPLOAD_THREADS..=MAX_UPLOAD_THREADS).contains(&t) {
                    return Err(format!(
                        "listener.autoindex.upload_threads 越界（{t}，允许 \
                         {MIN_UPLOAD_THREADS}..={MAX_UPLOAD_THREADS}）"
                    ));
                }
            }
        }
    }
    if let Some(rl) = l.get("rate_limit").and_then(|x| x.as_object()) {
        // 限流参数：非有限值/负数会让令牌桶算出 NaN 或永远不放行。
        for key in ["rate_per_sec", "burst"] {
            if let Some(n) = rl.get(key).and_then(|x| x.as_f64()) {
                if !n.is_finite() || n < 0.0 || n > 1e9 {
                    return Err(format!(
                        "listener.rate_limit.{key} 越界（{n}，要求有限且 0..=1e9）"
                    ));
                }
            }
        }
    }
    Ok(())
}

// ---------- 通用小工具 ----------

fn toml_table(rows: &[(&str, toml::Value)]) -> toml::Value {
    let mut m = toml::map::Map::new();
    for (k, v) in rows {
        m.insert((*k).into(), v.clone());
    }
    toml::Value::Table(m)
}

async fn collect_body(req: Request<Full<Bytes>>) -> Result<Bytes, String> {
    let (_parts, body) = req.into_parts();
    // Full<Bytes> 本身就是收齐的内存体：collect 立即返回（admin 侧无流式语义）。
    use http_body_util::BodyExt;
    body.collect()
        .await
        .map(|c| c.to_bytes())
        .map_err(|e| format!("body: {e}"))
}

/// 解析 JSON 请求体并交给处理函数；解析失败返回 400。
async fn with_json(
    req: Request<Full<Bytes>>,
    f: impl FnOnce(Json) -> Response<BoxBody>,
) -> Response<BoxBody> {
    match collect_body(req).await {
        Ok(bytes) => match serde_json::from_slice::<Json>(&bytes) {
            Ok(v) => f(v),
            Err(e) => text_err(StatusCode::BAD_REQUEST, format!("invalid JSON: {e}")),
        },
        Err(e) => text_err(StatusCode::BAD_REQUEST, e),
    }
}

/// 解析 form-encoded 请求体（port + path），交给处理函数。
async fn with_form(
    req: Request<Full<Bytes>>,
    f: impl FnOnce(u16, String) -> Response<BoxBody>,
) -> Response<BoxBody> {
    match collect_body(req).await {
        Ok(bytes) => {
            let body = String::from_utf8_lossy(&bytes);
            let port = match form_field(&body, "port").and_then(|p| p.parse::<u16>().ok()) {
                Some(p) if p != 0 => p,
                _ => return text_err(StatusCode::BAD_REQUEST, "missing or invalid port"),
            };
            let path = form_field(&body, "path").unwrap_or_default();
            if path.trim().is_empty() {
                return text_err(StatusCode::BAD_REQUEST, "missing path");
            }
            f(port, path)
        }
        Err(e) => text_err(StatusCode::BAD_REQUEST, e),
    }
}

/// 按端口取 listener docroot；不在 admin 前缀内暴露文件系统。
fn with_listener_root(
    cfg: &Config,
    port: u16,
    f: impl FnOnce(&std::path::Path) -> Response<BoxBody>,
) -> Response<BoxBody> {
    match cfg.listeners.iter().find(|l| l.port == port) {
        Some(lc) => f(&lc.root),
        None => text_err(StatusCode::BAD_REQUEST, "unknown listener port"),
    }
}

fn form_field(body: &str, key: &str) -> Option<String> {
    for part in body.split('&') {
        if let Some((k, v)) = part.split_once('=') {
            if k == key {
                return Some(percent_encoding::percent_decode_str(v).decode_utf8_lossy().into_owned());
            }
        }
    }
    None
}

fn text_ok(s: impl Into<Bytes>) -> Response<BoxBody> {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(full(s))
        .unwrap()
}

fn text_err(st: StatusCode, s: impl Into<Bytes>) -> Response<BoxBody> {
    Response::builder()
        .status(st)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(full(s))
        .unwrap()
}

fn json_ok(s: String) -> Response<BoxBody> {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json; charset=utf-8")
        .body(full(s))
        .unwrap()
}

fn query_str(q: &str, key: &str) -> Option<String> {
    for part in q.split('&') {
        if let Some((k, v)) = part.split_once('=') {
            if k == key {
                return Some(percent_decode(v));
            }
        }
    }
    None
}

fn query_u16(q: &str, key: &str) -> Option<u16> {
    query_str(q, key)?.parse().ok()
}

fn percent_decode(s: &str) -> String {
    percent_encoding::percent_decode_str(s)
        .decode_utf8_lossy()
        .into_owned()
}

fn json_str(s: &str) -> String {
    // P2-12：转义控制字符——文件名含换行/制表时也要产出合法 JSON（list_dir 回显）。
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn serde_json_array(items: &[String]) -> String {
    let mut s = String::from("[");
    for (i, it) in items.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&json_str(it));
    }
    s.push(']');
    s
}

#[derive(Clone, Copy, PartialEq)]
enum RulesKind {
    Page,
    Proxy,
}

/// 页面规则 / 反代规则 API。
/// GET  ?port=N            → 当前规则 JSON 数组
/// POST {port, remove: i}  → 删除第 i 条
/// POST {port, ...fields}  → 追加一条(Page: match_url/action/target;Proxy: path/upstream/ssl_mode)
/// POST 成功后写回 config.toml 并触发热重载(brand-free:文案经 scrub)。
async fn handle_rules_api(
    req: Request<Full<Bytes>>,
    live: &Arc<LiveConfig>,
    kind: RulesKind,
) -> Response<BoxBody> {
    let method = req.method().clone();
    let q = req.uri().query().unwrap_or("").to_string();
    let cfg = live.snapshot();

    if method == Method::GET {
        let port = query_u16(&q, "port").unwrap_or(0);
        let Some(lc) = cfg.listeners.iter().find(|l| l.port == port) else {
            return text_err(StatusCode::BAD_REQUEST, "unknown listener port");
        };
        let mut s = String::from("[");
        match kind {
            RulesKind::Page => {
                for (i, r) in lc.page_rules.iter().enumerate() {
                    if i > 0 {
                        s.push(',');
                    }
                    let target = r
                        .target
                        .as_deref()
                        .map(|t| json_str(&crate::server::page_rules::scrub_brand(t)))
                        .unwrap_or_else(|| "null".into());
                    s.push_str(&format!(
                        "{{\"idx\":{},\"match_url\":{},\"action\":{},\"target\":{}}}",
                        i,
                        json_str(&r.match_url),
                        json_str(&crate::server::page_rules::scrub_brand(&r.action)),
                        target
                    ));
                }
            }
            RulesKind::Proxy => {
                for (i, r) in lc.proxy_rules.iter().enumerate() {
                    if i > 0 {
                        s.push(',');
                    }
                    s.push_str(&format!(
                        "{{\"idx\":{},\"path\":{},\"upstream\":{},\"ssl_mode\":{}}}",
                        i,
                        json_str(&r.path),
                        json_str(&r.upstream),
                        json_str(&r.ssl_mode)
                    ));
                }
            }
        }
        s.push(']');
        return json_ok(s);
    }

    // ---- POST: 增 / 删 ----
    let collected = req.collect().await.ok();
    let bytes = collected.map(|c| c.to_bytes()).unwrap_or_else(Bytes::new);
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return text_err(StatusCode::BAD_REQUEST, "invalid JSON body");
    };
    let Some(port) = v.get("port").and_then(|x| x.as_u64()) else {
        return text_err(StatusCode::BAD_REQUEST, "port required");
    };
    // 端口按 u64 判范围再转换：`as u16` 会把 131165 截断成 9095 ——
    // 于是「给 131165 加一条规则」实际改的是 9095 那个站点的规则表。
    if port == 0 || port > u16::MAX as u64 {
        return bad_request(format!("port 越界（{port}，必须是 1..=65535）"));
    }
    let port = port as u16;
    let cfg_path = live.path().clone();

    let raw = match std::fs::read_to_string(&cfg_path) {
        Ok(r) => r,
        Err(e) => return text_err(StatusCode::INTERNAL_SERVER_ERROR, format!("read config: {e}")),
    };
    let mut doc: toml::Value = match toml::from_str(&raw) {
        Ok(d) => d,
        Err(e) => {
            return text_err(StatusCode::INTERNAL_SERVER_ERROR, format!("parse config: {e}"))
        }
    };
    let Some(listeners) = doc.get_mut("listeners").and_then(|l| l.as_array_mut()) else {
        return text_err(StatusCode::INTERNAL_SERVER_ERROR, "config has no [[listeners]]");
    };
    let Some(li) = listeners
        .iter()
        .position(|l| l.get("port").and_then(|p| p.as_integer()) == Some(port as i64))
    else {
        return text_err(StatusCode::BAD_REQUEST, "unknown listener port");
    };
    let Some(lentry) = listeners.get_mut(li) else {
        return text_err(StatusCode::INTERNAL_SERVER_ERROR, "listener entry missing");
    };
    let key = match kind {
        RulesKind::Page => "page_rules",
        RulesKind::Proxy => "proxy_rules",
    };

    if let Some(rm) = v.get("remove").and_then(|x| x.as_u64()) {
        let Some(arr) = lentry.get_mut(key).and_then(|a| a.as_array_mut()) else {
            return text_err(StatusCode::BAD_REQUEST, "no rules to remove");
        };
        if (rm as usize) >= arr.len() {
            return text_err(StatusCode::BAD_REQUEST, "remove index out of range");
        }
        arr.remove(rm as usize);
    } else {
        // 追加前的取值校验与结构化端点共用同一套（save_page_rules / save_proxy_rules）：
        // 否则「面板表格里的快捷添加」会成为绕过校验的后门。
        if let Err(e) = match kind {
            RulesKind::Page => check_page_rule(&v, 0),
            RulesKind::Proxy => check_proxy_rule(&v, 0),
        } {
            return bad_request(format!("新增规则不合法 —— {e}"));
        }
        let entry = match kind {
            RulesKind::Page => {
                let Some(m) = v.get("match_url").and_then(|x| x.as_str()) else {
                    return text_err(StatusCode::BAD_REQUEST, "match_url required");
                };
                if m.is_empty() {
                    return text_err(StatusCode::BAD_REQUEST, "match_url empty");
                }
                let mut t = toml::value::Table::new();
                // P2-9：保存入口 scrub（与 save_page_rules 一致）。
                t.insert(
                    "match_url".into(),
                    toml::Value::String(crate::server::page_rules::scrub_brand(m)),
                );
                let action = v
                    .get("action")
                    .and_then(|x| x.as_str())
                    .unwrap_or("block")
                    .trim()
                    .to_ascii_lowercase();
                // 同 save_page_rules：落盘前归一化成小写（apply 是精确匹配）。
                if !PAGE_RULE_ACTIONS.contains(&action.as_str()) {
                    return text_err(
                        StatusCode::BAD_REQUEST,
                        format!("invalid page rule action: {action}"),
                    );
                }
                t.insert(
                    "action".into(),
                    toml::Value::String(crate::server::page_rules::scrub_brand(&action)),
                );
                if let Some(tg) = v.get("target").and_then(|x| x.as_str()) {
                    if !tg.is_empty() {
                        t.insert(
                            "target".into(),
                            toml::Value::String(crate::server::page_rules::scrub_brand(tg)),
                        );
                    }
                }
                toml::Value::Table(t)
            }
            RulesKind::Proxy => {
                let Some(p) = v.get("path").and_then(|x| x.as_str()) else {
                    return text_err(StatusCode::BAD_REQUEST, "path required");
                };
                let Some(up) = v.get("upstream").and_then(|x| x.as_str()) else {
                    return text_err(StatusCode::BAD_REQUEST, "upstream required");
                };
                if p.is_empty() || up.is_empty() {
                    return text_err(StatusCode::BAD_REQUEST, "path/upstream empty");
                }
                let mut t = toml::value::Table::new();
                t.insert("path".into(), toml::Value::String(p.to_string()));
                t.insert("upstream".into(), toml::Value::String(up.to_string()));
                if let Some(sm) = v.get("ssl_mode").and_then(|x| x.as_str()) {
                    let sm = sm.trim().to_ascii_lowercase();
                    if !sm.is_empty() {
                        if !SSL_MODES.contains(&sm.as_str()) {
                            return text_err(
                                StatusCode::BAD_REQUEST,
                                format!("invalid ssl_mode: {sm}"),
                            );
                        }
                        t.insert("ssl_mode".into(), toml::Value::String(sm));
                    }
                }
                toml::Value::Table(t)
            }
        };
        // 条数上限（config 级上限见 admin_config_edit::MAX_RULES_PER_LISTENER）。
        let existing = lentry
            .get(key)
            .and_then(|a| a.as_array())
            .map(|a| a.len())
            .unwrap_or(0);
        if let Err(e) = check_len(key, existing + 1, MAX_LIST_ITEMS) {
            return bad_request(e);
        }
        if lentry.get(key).is_none() {
            if let Some(tbl) = lentry.as_table_mut() {
                tbl.insert(key.into(), toml::Value::Array(Vec::new()));
            }
        }
        match lentry.get_mut(key).and_then(|a| a.as_array_mut()) {
            Some(arr) => arr.push(entry),
            None => return text_err(StatusCode::INTERNAL_SERVER_ERROR, "rules array missing"),
        }
    }

    // Validate + atomic write via shared pipeline (rejects bad roots/ports).
    let _ = cfg_path;
    if let Err(e) = cfg_edit::write_tree(&live, &doc) {
        return text_err(StatusCode::BAD_REQUEST, format!("{e:#}"));
    }
    text_ok("ok")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 造请求：`uri_authority` 为真时用绝对 URI（模拟 h2 只有 `:authority` 的场景）。
    fn mk(method: &str, headers: &[(&str, &str)], uri_authority: bool) -> Request<Full<Bytes>> {
        let uri = if uri_authority {
            "https://admin.example:18443/__admin/api/config/toml"
        } else {
            "/__admin/api/config/toml"
        };
        let mut b = Request::builder().method(method).uri(uri);
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        b.body(Full::new(Bytes::new())).unwrap()
    }

    fn allowed(headers: &[(&str, &str)]) -> bool {
        state_change_allowed(&mk("POST", headers, false))
    }

    // ---------- 取值边界 ----------

    fn j(s: &str) -> Json {
        serde_json::from_str(s).unwrap()
    }

    /// 越界数字：端口不能用 `as u16` 截断（131165 → 9095 会改到别的站点），
    /// 权重/线程数/ttl 也不能静默夹紧或截断。
    #[test]
    fn out_of_range_numbers_are_rejected() {
        let e = json_port(&j(r#"{"port":131165}"#), "port").unwrap_err();
        assert_eq!(e.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_port(&j(r#"{"port":9095}"#), "port").unwrap(), 9095);
        assert!(json_port(&j(r#"{"port":0}"#), "port").is_err());
        assert!(json_port(&j(r#"{"port":65535}"#), "port").is_ok());
        // 缺键 / 非数字
        assert!(json_port(&j("{}"), "port").is_err());
        assert!(json_port(&j(r#"{"port":"9095"}"#), "port").is_err());

        // 集合条数上限
        assert!(check_len("rules", MAX_LIST_ITEMS, MAX_LIST_ITEMS).is_ok());
        assert!(check_len("rules", MAX_LIST_ITEMS + 1, MAX_LIST_ITEMS).is_err());
    }

    /// 超长字符串：路径 / 头名值 / DNS 名 / 口令都有上限，且报错信息里带上限值。
    #[test]
    fn oversized_strings_are_rejected() {
        let long = "x".repeat(MAX_PATH_STR + 1);
        let e = check_str("path", &long, MAX_PATH_STR).unwrap_err();
        assert!(e.contains("过长"), "unexpected: {e}");
        assert!(check_str("path", &"x".repeat(MAX_PATH_STR), MAX_PATH_STR).is_ok());
        // 控制字符（换行）也要拒 —— 它们会进入 TOML 值与响应头。
        assert!(check_str("path", "a\nb", MAX_PATH_STR).is_err());

        assert!(check_dns_name("name", &"a".repeat(MAX_DNS_NAME_LEN + 1)).is_err());
        assert!(check_dns_name("name", &format!("{}.example.com", "a".repeat(MAX_DNS_LABEL_LEN + 1))).is_err());
        assert!(check_dns_name("name", "ok.example.com").is_ok());
        assert!(check_dns_name("name", "a..b").is_err());
        assert!(check_dns_name("name", "有中文.example").is_err());
        assert!(check_dns_name("name", &format!("{}.example.com", "a".repeat(MAX_DNS_LABEL_LEN))).is_ok());
    }

    /// 非法枚举：page rule action / file_open mode / ssl_mode / 回源版本 / http_versions。
    #[test]
    fn invalid_enums_are_rejected() {
        // page rule action
        let e = check_page_rule(&j(r#"{"match_url":"/x","action":"delete"}"#), 0).unwrap_err();
        assert!(e.contains("action 不合法"), "unexpected: {e}");
        assert!(check_page_rule(&j(r#"{"match_url":"/x","action":"redirect","target":"/y"}"#), 0).is_ok());
        // proxy ssl_mode
        let e = check_proxy_rule(
            &j(r#"{"path":"/a","upstream":"http://127.0.0.1:8080","ssl_mode":"bogus"}"#),
            0,
        )
        .unwrap_err();
        assert!(e.contains("ssl_mode 不合法"), "unexpected: {e}");
        assert!(check_proxy_rule(
            &j(r#"{"path":"/a","upstream":"https://u.example","ssl_mode":"tor"}"#),
            0
        )
        .is_ok());
        // 回源版本：只有 tls1.2/tls1.3 与 h1/h2 会被识别
        assert!(check_proxy_rule(
            &j(r#"{"path":"/a","upstream":"https://u.example","upstream_tls_version":"1.3"}"#),
            0
        )
        .is_err());
        assert!(check_proxy_rule(
            &j(r#"{"path":"/a","upstream":"https://u.example","upstream_tls_version":"TLSv1.3","upstream_http_version":"h2"}"#),
            0
        )
        .is_ok());
        assert!(check_proxy_rule(
            &j(r#"{"path":"/a","upstream":"https://u.example","upstream_http_version":"http2"}"#),
            0
        )
        .is_err());
        // listener http_versions
        assert!(check_listener_json(&j(r#"{"port":9081,"http_versions":["h1","h4"]}"#)).is_err());
        assert!(check_listener_json(&j(r#"{"port":9081,"http_versions":["h1","H2","h3"]}"#)).is_ok());
    }

    /// 非法 CIDR：`access::cidr_or_exact` 把解析不了的条目当「不匹配」——
    /// deny 里等于拒绝规则静默失效（fail-open），必须在保存时点名拒绝。
    #[test]
    fn invalid_cidr_is_rejected_with_index() {
        assert!(check_ip_access_entry("deny", 0, "10.0.0.0/8").is_ok());
        assert!(check_ip_access_entry("deny", 0, "2001:db8::/32").is_ok());
        assert!(check_ip_access_entry("deny", 0, "127.0.0.1").is_ok());
        assert!(check_ip_access_entry("deny", 0, "*").is_ok());
        for bad in ["10.0.0.0/33", "2001:db8::/129", "10.0.0.O/8", "10.0.0.0/8 # office", ""] {
            let e = check_ip_access_entry("deny", 3, bad).unwrap_err();
            assert!(e.contains("deny[3]"), "错误必须指出是哪一项: {e}");
        }
    }

    /// 注入头：CR/LF 值会造成头部注入/请求走私；非法头名在代理方向会让整条线路
    /// 每个请求 502（`builder.body()` 失败），响应方向则静默丢弃。
    #[test]
    fn header_injection_payloads_are_rejected() {
        assert!(check_header_pair("h", "X-Test", "ok").is_ok());
        for (k, v) in [
            ("X-Test", "a\r\nX-Evil: 1"),
            ("X-Test", "a\nb"),
            ("X Test", "v"),
            ("X-Test:", "v"),
            ("", "v"),
        ] {
            assert!(
                check_header_pair("modify_request_headers", k, v).is_err(),
                "{k:?}:{v:?} must be rejected"
            );
        }
        // 头名/头值超长
        assert!(check_header_pair("h", &"a".repeat(MAX_HEADER_NAME_LEN + 1), "v").is_err());
        assert!(check_header_pair("h", "X-Test", &"v".repeat(MAX_HEADER_VALUE_LEN + 1)).is_err());
    }

    /// 超量集合：apps / rules / 头的数量上限；且 listener 整表替换也要受限
    /// （否则可以绕过 apps/save 等分表端点直接塞进任意多条）。
    #[test]
    fn oversized_collections_are_rejected() {
        let apps: Vec<String> = (0..MAX_APPS_PER_LISTENER + 1)
            .map(|i| format!(r#"{{"engine":"php","paths":["/p{i}"]}}"#))
            .collect();
        let body = format!(r#"{{"port":9095,"apps":[{}]}}"#, apps.join(","));
        let e = check_len(
            "apps",
            j(&body).get("apps").unwrap().as_array().unwrap().len(),
            MAX_APPS_PER_LISTENER,
        )
        .unwrap_err();
        assert!(e.contains("过多"), "unexpected: {e}");

        // listener 里带超量 apps：整表替换路径同样拒绝。
        let lbody = format!(r#"{{"port":9095,"apps":[{}]}}"#, apps.join(","));
        let e = check_listener_json(&j(&lbody)).unwrap_err();
        assert!(e.contains("apps 过多"), "unexpected: {e}");

        // 一条规则里塞超量注入头
        let hs: Vec<String> = (0..MAX_HEADER_ITEMS + 1)
            .map(|i| format!(r#""X-{i}":"v""#))
            .collect();
        let rbody = format!(
            r#"{{"path":"/a","upstream":"http://127.0.0.1:8080","modify_request_headers":{{{}}}}}"#,
            hs.join(",")
        );
        let e = check_proxy_rule(&j(&rbody), 0).unwrap_err();
        assert!(e.contains("项数过多"), "unexpected: {e}");
    }

    /// 语义型边界：match_url/path 必须以 / 开头（否则永远匹配不到请求），
    /// upstream 必须是 http/https 且带 host，redirect target 不能带控制字符
    /// （page_rules::redirect_response 会 `.unwrap()` 构造 Location 头 → panic）。
    #[test]
    fn semantic_bounds_are_enforced() {
        assert!(check_page_rule(&j(r#"{"match_url":"x","action":"block"}"#), 0).is_err());
        assert!(check_page_rule(&j(r#"{"match_url":"/x","action":"rewrite"}"#), 0).is_err());
        assert!(check_page_rule(&j(r#"{"match_url":"/x","action":"redirect","target":"/y\r\nX: 1"}"#), 0).is_err());
        assert!(check_page_rule(&j(r#"{"match_url":"/x","action":"header","target":"X-Test"}"#), 0).is_err());
        assert!(check_page_rule(&j(r#"{"match_url":"/x","action":"header","target":"X-Test: 1"}"#), 0).is_ok());
        assert!(check_proxy_rule(&j(r#"{"path":"a","upstream":"http://h:1"}"#), 0).is_err());
        assert!(check_proxy_rule(&j(r#"{"path":"/a","upstream":"ftp://h"}"#), 0).is_err());
        assert!(check_proxy_rule(&j(r#"{"path":"/a","upstream":"127.0.0.1:8080"}"#), 0).is_err());
        // 合法：与 config.toml / UI 实际会发的形状一致
        assert!(check_proxy_rule(
            &j(r#"{"path":"/api","upstream":"http://127.0.0.1:8080","ssl_mode":"verify","modify_request_headers":{"X-A":"1"},"modify_response_headers":{},"connection_pool":true,"via_tor":false}"#),
            0
        )
        .is_ok());
    }

    /// 核心修复：既无 Origin/Referer 也无「非简单请求」特征时**必须拒绝**
    /// （旧实现是缺 Origin 就整段跳过 = 放行）。
    #[test]
    fn csrf_without_origin_or_marker_is_rejected() {
        assert!(!allowed(&[("host", "admin.example:18443")]));
        // 简单请求的典型形态：表单 POST（简单 Content-Type、无自定义头）。
        assert!(!allowed(&[
            ("host", "admin.example:18443"),
            ("content-type", "application/x-www-form-urlencoded"),
        ]));
        assert!(!allowed(&[
            ("host", "admin.example:18443"),
            ("content-type", "text/plain;charset=UTF-8"),
        ]));
    }

    /// 带来源信息：host[:port] 必须与本请求 Host 同源（scheme 不参与比较）。
    #[test]
    fn csrf_origin_and_referer_must_match_host() {
        assert!(allowed(&[
            ("host", "admin.example:18443"),
            ("origin", "https://admin.example:18443"),
        ]));
        // scheme 变了（反代/回源改 scheme）仍算同源。
        assert!(allowed(&[
            ("host", "admin.example:18443"),
            ("origin", "http://admin.example:18443"),
        ]));
        // 端口不同 → 不同源。
        assert!(!allowed(&[
            ("host", "admin.example:18443"),
            ("origin", "https://admin.example:9081"),
        ]));
        assert!(!allowed(&[
            ("host", "admin.example:18443"),
            ("origin", "https://evil.example"),
        ]));
        // `Origin: null`（沙箱 iframe / file://）不是主机名 → 拒绝。
        assert!(!allowed(&[
            ("host", "admin.example:18443"),
            ("origin", "null"),
        ]));
        // 没有 Origin 时看 Referer，同样必须同源。
        assert!(allowed(&[
            ("host", "admin.example"),
            ("referer", "https://admin.example/__admin/"),
        ]));
        assert!(!allowed(&[
            ("host", "admin.example"),
            ("referer", "https://evil.example/x"),
        ]));
    }

    /// 无来源信息时，「非简单请求」三选一放行：JSON content-type / 自定义头 /
    /// Sec-Fetch-Site。
    #[test]
    fn csrf_non_simple_requests_pass_without_origin() {
        assert!(allowed(&[
            ("host", "admin.example"),
            ("content-type", "application/json"),
        ]));
        assert!(allowed(&[
            ("host", "admin.example"),
            ("content-type", "application/json; charset=utf-8"),
        ]));
        assert!(allowed(&[
            ("host", "admin.example"),
            ("x-crucible-admin", "1"),
        ]));
        assert!(allowed(&[
            ("host", "admin.example"),
            ("sec-fetch-site", "same-origin"),
        ]));
        assert!(allowed(&[
            ("host", "admin.example"),
            ("sec-fetch-site", "None"),
        ]));
        // 反例：自定义头值不是 1、Sec-Fetch-Site 是跨站/同站、JSON 变体拼错。
        assert!(!allowed(&[
            ("host", "admin.example"),
            ("x-crucible-admin", "0"),
        ]));
        assert!(!allowed(&[
            ("host", "admin.example"),
            ("sec-fetch-site", "cross-site"),
        ]));
        assert!(!allowed(&[
            ("host", "admin.example"),
            ("sec-fetch-site", "same-site"),
        ]));
        assert!(!allowed(&[
            ("host", "admin.example"),
            ("content-type", "application/jsonp"),
        ]));
    }

    /// h2 场景：hyper 不保证补 `Host` 头时，同源比较用 URI 的 `:authority`。
    #[test]
    fn csrf_uses_uri_authority_when_host_header_is_absent() {
        assert!(state_change_allowed(&mk(
            "POST",
            &[("origin", "https://admin.example:18443")],
            true
        )));
        assert!(!state_change_allowed(&mk(
            "POST",
            &[("origin", "https://evil.example")],
            true
        )));
    }
}
