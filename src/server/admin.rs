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
use http::{header, Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use serde_json::Value as Json;
use std::sync::Arc;

pub const UI_HTML: &str = include_str!("admin_ui.html");
/// 视频预览（HLS/mp4）辅助脚本，经 include_str! 编进二进制；改后需重链。
pub const HLS_JS: &str = include_str!("admin_hls.light.min.js");

/// CSRF helper（P0-2）：Origin 与 Host 是否同源（剥 scheme 后全等比较）。
fn origin_matches_host(origin: &str, host: &str) -> bool {
    let o = origin.split("://").nth(1).unwrap_or(origin);
    o.eq_ignore_ascii_case(host.trim_end_matches('/'))
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

    // CSRF 防护（P0-2）：浏览器写请求必须同源（Origin 与 Host 一致）；
    // 非浏览器请求（curl/服务端脚本）不带 Origin，由 Basic 凭据本身鉴权，放行。
    if matches!(method, Method::POST | Method::PUT | Method::DELETE | Method::PATCH) {
        if let Some(origin) = req.headers().get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
            let host = req.headers().get(header::HOST).and_then(|v| v.to_str().ok());
            let same = host.map(|h| origin_matches_host(origin, h)).unwrap_or(false);
            if !same {
                return Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .body(full("cross-origin request blocked"))
                    .unwrap();
            }
        }
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
    if path.ends_with("/api/geoip/update/status") && method == Method::GET {
        return admin_geoip::handle_update_status(&req).await;
    }
        return admin_geoip::handle_status_with_live(&req, &live).await;
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
            let Some(port) = v.get("port").and_then(|p| p.as_u64()).map(|p| p as u16) else {
                return text_err(StatusCode::BAD_REQUEST, "missing port");
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
            let interval = v
                .get("evaluate_interval_ms")
                .and_then(|n| n.as_u64())
                .unwrap_or(1000);
            let mut tree = match cfg_edit::load_tree(live.path()) {
                Ok(t) => t,
                Err(e) => return text_err(StatusCode::BAD_REQUEST, format!("{e:#}")),
            };
            let table = toml_table(&[
                ("enabled", toml::Value::Boolean(enabled)),
                ("value_on", toml::Value::String(value_on.into())),
                ("value_off", toml::Value::String(value_off.into())),
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
            let allow: Vec<u16> = v
                .get("listeners_allow")
                .and_then(|a| a.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_u64().map(|n| n as u16))
                        .collect()
                })
                .unwrap_or_default();
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
            let to_arr = |items: &Vec<Json>| -> Result<toml::Value, String> {
                let mut out = Vec::new();
                for it in items {
                    match it.as_str() {
                        Some(s) if !s.trim().is_empty() => {
                            out.push(toml::Value::String(s.trim().into()))
                        }
                        _ => return Err("ip 列表元素必须是字符串".into()),
                    }
                }
                Ok(toml::Value::Array(out))
            };
            let (allow_v, deny_v) = match (to_arr(allow), to_arr(deny)) {
                (Ok(a), Ok(d)) => (a, d),
                (Err(e), _) | (_, Err(e)) => return text_err(StatusCode::BAD_REQUEST, e),
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
        let req65 = crate::server::type65_api::Type65Request {
            name: name.clone(),
            ech_config_list: Some(b64),
            ttl: v["ttl"].as_u64().map(|t| t as u32),
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
    let orig_port = v
        .get("orig_port")
        .and_then(|p| p.as_u64())
        .map(|p| p as u16);
    let Some(lval) = v.get("listener") else {
        return text_err(StatusCode::BAD_REQUEST, "missing listener");
    };
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
    let Some(port) = v.get("port").and_then(|p| p.as_u64()).map(|p| p as u16) else {
        return text_err(StatusCode::BAD_REQUEST, "missing port");
    };
    let Some(apps) = v.get("apps").and_then(|a| a.as_array()) else {
        return text_err(StatusCode::BAD_REQUEST, "missing apps array");
    };
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
    let Some(port) = v.get("port").and_then(|p| p.as_u64()).map(|p| p as u16) else {
        return text_err(StatusCode::BAD_REQUEST, "missing port");
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
    let Some(port) = v.get("port").and_then(|p| p.as_u64()).map(|p| p as u16) else {
        return text_err(StatusCode::BAD_REQUEST, "missing port");
    };
    let Some(entries) = v.get("entries").and_then(|a| a.as_array()) else {
        return text_err(StatusCode::BAD_REQUEST, "missing entries array");
    };
    let mut rows = Vec::with_capacity(entries.len());
    for e in entries {
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
        if !["auto", "preview", "download", "execute"].contains(&mode) {
            return text_err(StatusCode::BAD_REQUEST, format!("invalid mode: {mode}"));
        }
        rows.push(toml::Value::String(format!("{path}={mode}")));
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
    let Some(port) = v.get("port").and_then(|p| p.as_u64()).map(|p| p as u16) else {
        return text_err(StatusCode::BAD_REQUEST, "missing port");
    };
    let enabled = v.get("enabled").and_then(|b| b.as_bool()).unwrap_or(false);
    let paths: Vec<String> = v
        .get("paths")
        .and_then(|a| a.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_else(|| vec!["/".into()]);
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
    let upload_threads = v
        .get("upload_threads")
        .and_then(|n| n.as_u64())
        .unwrap_or(4)
        .clamp(1, 16) as u16;
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
    let Some(port) = v.get("port").and_then(|p| p.as_u64()).map(|p| p as u16) else {
        return text_err(StatusCode::BAD_REQUEST, "missing port");
    };
    let Some(rules) = v.get("rules").and_then(|a| a.as_array()) else {
        return text_err(StatusCode::BAD_REQUEST, "missing rules array");
    };
    let mut out = Vec::with_capacity(rules.len());
    for r in rules {
        let Some(match_url) = r.get("match_url").and_then(|m| m.as_str()).map(str::trim) else {
            return text_err(StatusCode::BAD_REQUEST, "rule missing match_url");
        };
        let action = r
            .get("action")
            .and_then(|a| a.as_str())
            .unwrap_or("redirect")
            .trim();
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

const SSL_MODES: &[&str] = &["verify", "no_verify", "trust_self_signed", "off"];

/// body: {"port": 9081, "rules": [{"path": "/api", "upstream": "http://127.0.0.1:8080",
///   "ssl_mode": "verify", "modify_request_headers": {}, "modify_response_headers": {}}]}
fn save_proxy_rules(live: &Arc<LiveConfig>, v: &Json) -> Response<BoxBody> {
    let Some(port) = v.get("port").and_then(|p| p.as_u64()).map(|p| p as u16) else {
        return text_err(StatusCode::BAD_REQUEST, "missing port");
    };
    let Some(rules) = v.get("rules").and_then(|a| a.as_array()) else {
        return text_err(StatusCode::BAD_REQUEST, "missing rules array");
    };
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
    let Some(port) = v.get("port").and_then(|x| x.as_u64()).map(|x| x as u16) else {
        return text_err(StatusCode::BAD_REQUEST, "port required");
    };
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
                let action = v.get("action").and_then(|x| x.as_str()).unwrap_or("block");
                const PAGE_ACTIONS: &[&str] =
                    &["redirect", "block", "rewrite", "pass", "cache", "header"];
                if !PAGE_ACTIONS.contains(&action) {
                    return text_err(
                        StatusCode::BAD_REQUEST,
                        format!("invalid page rule action: {action}"),
                    );
                }
                t.insert(
                    "action".into(),
                    toml::Value::String(crate::server::page_rules::scrub_brand(action)),
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
                    if !sm.is_empty() {
                        const SSL_MODES: &[&str] =
                            &["verify", "no_verify", "trust_self_signed", "off", "tor"];
                        if !SSL_MODES.contains(&sm) {
                            return text_err(
                                StatusCode::BAD_REQUEST,
                                format!("invalid ssl_mode: {sm}"),
                            );
                        }
                        t.insert("ssl_mode".into(), toml::Value::String(sm.to_string()));
                    }
                }
                toml::Value::Table(t)
            }
        };
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
