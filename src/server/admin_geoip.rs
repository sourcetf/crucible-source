//! Admin GeoIP API handlers (Rust-only; no Python bridge).

use crate::server::geoip_panel::{aliases, covering, db, iputil, lookup, sources, toml_store};
use crate::server::h1::{full, BoxBody};
use crate::server::live_config::LiveConfig;
use http_body_util::BodyExt;
use http::{Method, Request, Response, StatusCode};
use bytes::Bytes;
use http_body_util::Full;
use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

/// `GET /api/geoip/lookup?ip=…` using live config for db path.
pub async fn handle_lookup_with_live(
    req: &Request<Full<Bytes>>,
    live: &Arc<LiveConfig>,
) -> Response<BoxBody> {
    if req.method() != Method::GET {
        return method_not_allowed();
    }
    let ip_s = query_param(req.uri().query().unwrap_or(""), "ip").unwrap_or_default();
    let db_path = resolve_db_path(live);
    lookup_json(&ip_s, db_path.as_deref())
}

/// `GET /api/geoip/status` — panel backend status.
pub async fn handle_status_with_live(
    _req: &Request<Full<Bytes>>,
    live: &Arc<LiveConfig>,
) -> Response<BoxBody> {
    let snap = live.snapshot();
    let db_path = resolve_db_path(live);
    let path_s = db_path
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    let exists = db_path.as_ref().map(|p| p.is_file()).unwrap_or(false);
    let panel = crate::server::geoip_panel::db::panel_db_path();
    let panel_exists = panel.is_file();
    let panel_toml = toml_store::panel_path();
    json_ok(format!(
        "{{\"enabled\":{},\"db_path\":{},\"exists\":{},\"panel_exists\":{},\
\"path_priority_gain\":{},\"panel_toml\":{},\"panel_toml_exists\":{},\
\"message\":\"rust geoip panel §23\"}}",
        snap.geoip.enabled,
        json_str(&path_s),
        exists,
        panel_exists,
        snap.geoip.path_priority_gain,
        json_str(&panel_toml.display().to_string()),
        panel_toml.is_file()
    ))
}

/// `GET|POST /api/geoip/settings` — 面板设置（G-17/G-18）。
///
/// GET：返回**真正生效**的设置（`panel.toml` > `config.toml [geoip]` > 默认）。
/// POST：写 `data/geoip/panel.toml` 并热载，使 enabled/db_path/path_priority_gain
/// 立即生效；优先级与启动时一致。body 支持 JSON（面板）与表单（curl）：
/// `{"enabled":true,"db_path":"...","path_priority_gain":10}`。
/// `db_path: null` / 空串 = 删除面板覆盖（回落 config.toml）。
pub async fn handle_settings(
    req: Request<Full<Bytes>>,
    live: &Arc<LiveConfig>,
) -> Response<BoxBody> {
    let is_get = req.method() == Method::GET;
    let is_post = req.method() == Method::POST;
    if is_get {
            let snap = live.snapshot();
            let panel = toml_store::panel_path();
            let db_s = snap
                .geoip
                .db_path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default();
            let panel_over = match toml_store::load_effective() {
                Ok(c) => serde_json::to_string(&c).unwrap_or_else(|_| "{}".into()),
                Err(e) => {
                    return json_ok(format!(
                        "{{\"error\":{}}}",
                        json_str(&format!("{e:#}"))
                    ))
                }
            };
            json_ok(format!(
                "{{\"ok\":true,\"enabled\":{},\"db_path\":{},\
\"path_priority_gain\":{},\"panel_path\":{},\"panel_overrides\":{}}}",
                snap.geoip.enabled,
                json_str(&db_s),
                snap.geoip.path_priority_gain,
                json_str(&panel.display().to_string()),
                panel_over
            ))
    } else if is_post {
            let (_parts, body) = req.into_parts();
            let bytes = body
                .collect()
                .await
                .map(|c| c.to_bytes())
                .unwrap_or_default();
            let text = String::from_utf8_lossy(&bytes).into_owned();
            // JSON 优先（面板 UI），表单兜底（运维 curl）。
            let mut enabled: Option<bool> = None;
            let mut db_path: Option<Option<PathBuf>> = None; // Some(None) = 清除覆盖
            let mut gain: Option<i64> = None;
            match serde_json::from_str::<serde_json::Value>(&text) {
                Ok(v) if v.is_object() => {
                    if let Some(b) = v.get("enabled") {
                        match b.as_bool() {
                            Some(x) => enabled = Some(x),
                            None => return bad_request("enabled 必须是布尔值"),
                        }
                    }
                    if let Some(p) = v.get("db_path") {
                        if p.is_null() {
                            db_path = Some(None);
                        } else if let Some(s) = p.as_str() {
                            if s.trim().is_empty() {
                                db_path = Some(None);
                            } else {
                                db_path = Some(Some(PathBuf::from(s.trim())));
                            }
                        } else {
                            return bad_request("db_path 必须是字符串或 null");
                        }
                    }
                    if let Some(g) = v.get("path_priority_gain") {
                        match g.as_i64() {
                            Some(x) => gain = Some(x),
                            None => return bad_request("path_priority_gain 必须是整数"),
                        }
                    }
                }
                Ok(_) => return bad_request("body 必须是 JSON 对象"),
                Err(_) => {
                    if let Some(s) = form_field(&text, "enabled") {
                        enabled = Some(s == "1" || s.eq_ignore_ascii_case("true"));
                    }
                    if let Some(s) = form_field(&text, "db_path") {
                        db_path = Some(if s.trim().is_empty() {
                            None
                        } else {
                            Some(PathBuf::from(s.trim()))
                        });
                    }
                    if let Some(s) = form_field(&text, "path_priority_gain") {
                        match s.parse::<i64>() {
                            Ok(x) => gain = Some(x),
                            Err(_) => return bad_request("path_priority_gain 必须是整数"),
                        }
                    }
                    if enabled.is_none() && db_path.is_none() && gain.is_none() {
                        return bad_request("没有可保存的设置（enabled/db_path/path_priority_gain）");
                    }
                }
            }
            if enabled.is_none() && db_path.is_none() && gain.is_none() {
                return bad_request("没有可保存的设置（enabled/db_path/path_priority_gain）");
            }
            let mut panel = match toml_store::load_effective() {
                Ok(c) => c,
                Err(e) => {
                    return bad_request(format!(
                        "现有 panel.toml 非法，请先修正：{e:#}"
                    ))
                }
            };
            // 保存前的原始面板设置：热载失败时回滚到它，避免把一份会让**下次启动
            // 失败**的 panel.toml 留在磁盘上（例如清掉唯一 db_path 但 enabled 仍为真）。
            let panel_before = panel.clone();
            if let Some(b) = enabled {
                panel.enabled = Some(b);
            }
            if let Some(p) = db_path {
                panel.db_path = p;
            }
            if let Some(g) = gain {
                if !(0..=1000).contains(&g) {
                    return bad_request(format!(
                        "path_priority_gain = {g} 越界（允许 0..=1000）"
                    ));
                }
                panel.path_priority_gain = Some(g);
            }
            // 保存前检查组合合法性：enabled=true 而生效配置没有任何 db_path 时，
            // 运行期开关显示已启用但 country 规则永不命中（stored 后才在 reload
            // 失败，会让下次启动也起不来）。这里先拒绝，文件保持原样。
            {
                let snap = live.snapshot();
                let eff_enabled = panel.enabled.unwrap_or(snap.geoip.enabled);
                let eff_db = panel
                    .db_path
                    .clone()
                    .or_else(|| snap.geoip.db_path.clone());
                if eff_enabled && eff_db.is_none() {
                    return bad_request(
                        "geoip.enabled=true 但 config.toml 与 panel.toml 都没有 db_path（要关闭请同时传 enabled=false）",
                    );
                }
            }
            if let Err(e) = toml_store::save_effective(&panel) {
                return json_ok(format!(
                    "{{\"error\":{}}}",
                    json_str(&format!("{e:#}"))
                ));
            }
            // 立即生效：重读 config.toml + panel.toml（与重启同一套加载顺序）。
            if let Err(e) = live.reload() {
                let rolled_back = toml_store::save_effective(&panel_before).is_ok();
                if rolled_back {
                    // 回到旧设置；这次失败不影响正在服务的配置。
                    let _ = live.reload();
                }
                return json_ok(format!(
                    "{{\"ok\":false,\"rolled_back\":{},\"error\":{}}}",
                    rolled_back,
                    json_str(&format!("panel.toml 已保存但热载失败：{e:#}"))
                ));
            }
            let snap = live.snapshot();
            let db_s = snap
                .geoip
                .db_path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default();
            json_ok(format!(
                "{{\"ok\":true,\"enabled\":{},\"db_path\":{},\
\"path_priority_gain\":{},\"panel_path\":{}}}",
                snap.geoip.enabled,
                json_str(&db_s),
                snap.geoip.path_priority_gain,
                json_str(&toml_store::panel_path().display().to_string())
            ))
    } else {
        method_not_allowed()
    }
}

fn bad_request(msg: impl Into<String>) -> Response<BoxBody> {
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .header(http::header::CONTENT_TYPE, "application/json; charset=utf-8")
        .body(full(format!(
            "{{\"error\":{}}}",
            json_str(&msg.into())
        )))
        .unwrap()
}

/// `GET /api/geoip/lookup?ip=…` — standalone (env / default path).
/// 目前路由只接 `handle_lookup_with_live`；保留 standalone 版本供无 LiveConfig 的
/// 部署/脚本使用（G-19：显式标注，避免误以为死代码可以随手删）。
#[allow(dead_code)]
pub async fn handle_lookup(req: &Request<Full<Bytes>>) -> Response<BoxBody> {
    if req.method() != Method::GET {
        return method_not_allowed();
    }
    let ip_s = query_param(req.uri().query().unwrap_or(""), "ip").unwrap_or_default();
    let db_path = crate::server::apps::env_lock::read_static_env("CRUCIBLE_GEOIP_DB")
        .map(PathBuf::from)
        .or_else(|| Some(PathBuf::from("data/geoip/current/geoip.sqlite")));
    lookup_json(&ip_s, db_path.as_deref())
}

/// `GET /api/geoip/filter?country=&isp=&cloud=&family=&prefix=&limit=`
///
/// §23.6：`family`（IPv4|v6）与 `prefix`（前缀包含）是筛选器要求的维度，
/// 此前只支持 country/isp/cloud ⇒ 面板无法按地址族或网段定位。
pub async fn handle_filter_with_live(
    req: &Request<Full<Bytes>>,
    live: &Arc<LiveConfig>,
) -> Response<BoxBody> {
    if req.method() != Method::GET {
        return method_not_allowed();
    }
    let q = req.uri().query().unwrap_or("");
    let country = query_param(q, "country");
    let isp = query_param(q, "isp");
    let cloud = query_param(q, "cloud");
    let family = query_param(q, "family");
    let prefix = query_param(q, "prefix");
    let limit = query_param(q, "limit")
        .and_then(|s| s.parse().ok())
        .unwrap_or(50usize);
    let db_path = resolve_db_path(live);
    let Some(db_path) = db_path else {
        return json_ok("{\"rows\":[],\"error\":\"no_db\"}".into());
    };
    // 国家别名归一化：库里存的是 ISO（CN/US/…），而面板/调用方常传「中国」「China」。
    // `resolve_country_alias` 早就写好（aliases.rs，含 中国/China/CN → CN 这类映射），
    // 但此前**没有任何调用者** ⇒ 传中文名时筛选结果为空、看起来像「库里没有数据」。
    let country_norm = country
        .as_deref()
        .map(|c| crate::server::geoip_panel::aliases::resolve_country_alias(c));
    match db::open(&db_path) {
        Ok(conn) => match crate::server::geoip_panel::ops::filter_prefixes(
            &conn,
            country_norm.as_deref(),
            isp.as_deref(),
            cloud.as_deref(),
            family.as_deref(),
            prefix.as_deref(),
            limit,
        ) {
            Ok(rows) => {
                let items: Vec<String> = rows
                    .iter()
                    .map(|r| {
                        format!(
                            "{{\"prefix\":{},\"country\":{},\"province\":{},\"city\":{},\"isp\":{},\"cloud_provider\":{},\"weight\":{}}}",
                            json_str(&r.prefix),
                            json_str(&r.country),
                            json_str(&r.province),
                            json_str(&r.city),
                            json_str(&r.isp),
                            json_str(&r.cloud_provider),
                            r.weight
                        )
                    })
                    .collect();
                json_ok(format!("{{\"rows\":[{}]}}", items.join(",")))
            }
            Err(e) => json_ok(format!("{{\"error\":{}}}", json_str(&format!("{e:#}")))),
        },
        Err(e) => json_ok(format!("{{\"error\":{}}}", json_str(&format!("{e:#}")))),
    }
}

/// `GET /api/geoip/sources` — panel sources + optional SOURCES.json.
pub async fn handle_sources(_req: &Request<Full<Bytes>>) -> Response<BoxBody> {
    let panel_path = crate::server::geoip_panel::db::panel_db_path();
    let panel_path = panel_path.as_path();
    // G-18：源权重/启停的面板设置以 panel.toml 为准（覆盖 panel_sources 里的旧值；
    // panel.toml 只含显式写下的子键）。旧 sqlite 仍是数据源，未见 panel.toml 的源
    // 原样展示 sqlite 值 —— 旧库无需迁移。
    let overrides = toml_store::source_overrides();
    let mut items = String::new();
    let mut n = 0usize;
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    if panel_path.is_file() {
        if let Ok(conn) = db::open_panel(panel_path) {
            if let Ok(rows) = sources::list_sources(&conn) {
                for s in rows.iter() {
                    seen.insert(s.name.clone());
                    let mut weight = s.weight;
                    let mut enabled = s.enabled;
                    if let Some(o) = overrides.get(&s.name) {
                        if let Some(w) = o.weight {
                            weight = w;
                        }
                        if let Some(e) = o.enabled {
                            enabled = e;
                        }
                    }
                    if n > 0 {
                        items.push(',');
                    }
                    n += 1;
                    items.push_str(&format!(
                        "{{\"name\":{},\"weight\":{},\"enabled\":{},\"url\":{},\"last_commit\":{},\"last_unix\":{}}}",
                        json_str(&s.name),
                        weight,
                        enabled,
                        json_str(&s.url),
                        json_str(&s.last_commit),
                        s.last_unix
                    ));
                }
            }
        }
    }
    // panel.toml 里有、旧 sqlite 里没有的源也要出现（否则面板保存后看不到）。
    for (name, o) in overrides.iter() {
        if seen.contains(name) {
            continue;
        }
        if n > 0 {
            items.push(',');
        }
        n += 1;
        items.push_str(&format!(
            "{{\"name\":{},\"weight\":{},\"enabled\":{},\"url\":\"\",\"last_commit\":\"\",\"last_unix\":0}}",
            json_str(name),
            o.weight.unwrap_or(50),
            o.enabled.unwrap_or(true)
        ));
    }
    let sources_json = std::path::Path::new("data/geoip/current/SOURCES.json");
    // `meta` 是**外部文件**（离线脚本产物）的内容，此前直接拼进 JSON 体。文件一旦不是
    // 合法 JSON（半截写入、BOM、混入日志行），整个响应就不再是合法 JSON ⇒ 前端
    // `JSON.parse` 抛错，GeoIP 数据源面板整块不可用。这里先解析再序列化：合法则原样
    // 保形，非法则回落 `{}`，保证响应体永远是合法 JSON。
    let file_meta = if sources_json.is_file() {
        match sources::load_sources_json(sources_json) {
            Ok(raw) => serde_json::from_str::<serde_json::Value>(&raw)
                .map(|v| v.to_string())
                .unwrap_or_else(|_| "{}".into()),
            Err(_) => "{}".into(),
        }
    } else {
        "{}".into()
    };
    json_ok(format!(
        "{{\"sources\":[{items}],\"meta\":{file_meta}}}"
    ))
}

/// `GET /api/geoip/conflicts`
pub async fn handle_conflicts(_req: &Request<Full<Bytes>>) -> Response<BoxBody> {
    let panel_path = crate::server::geoip_panel::db::panel_db_path();
    let panel_path = panel_path.as_path();
    if !panel_path.is_file() {
        return json_ok("{\"conflicts\":[]}".into());
    }
    match db::open_panel(panel_path) {
        Ok(conn) => match crate::server::geoip_panel::ops::list_conflicts(&conn) {
            Ok(rows) => {
                let mut items = String::new();
                for (i, (id, prefix, field, sources)) in rows.iter().enumerate() {
                    if i > 0 {
                        items.push(',');
                    }
                    items.push_str(&format!(
                        "{{\"id\":{id},\"prefix\":{},\"field\":{},\"sources\":{}}}",
                        json_str(prefix),
                        json_str(field),
                        json_str(sources)
                    ));
                }
                json_ok(format!("{{\"conflicts\":[{items}]}}"))
            }
            Err(e) => json_ok(format!("{{\"error\":{}}}", json_str(&format!("{e:#}")))),
        },
        Err(e) => json_ok(format!("{{\"error\":{}}}", json_str(&format!("{e:#}")))),
    }
}

/// `POST /api/geoip/edit` body: prefix=…&field=…&value=…
pub async fn handle_edit(req: Request<Full<Bytes>>) -> Response<BoxBody> {
    if req.method() != Method::POST {
        return method_not_allowed();
    }
    let (_parts, body) = req.into_parts();
    let bytes = body
        .collect()
        .await
        .map(|c| c.to_bytes())
        .unwrap_or_default();
    let body = String::from_utf8_lossy(&bytes);
    let prefix = form_field(&body, "prefix").unwrap_or_default();
    let field = form_field(&body, "field").unwrap_or_default();
    let value = form_field(&body, "value").unwrap_or_default();
    let weight = form_field(&body, "weight")
        .and_then(|w| w.parse::<i64>().ok())
        .unwrap_or(200);
    if prefix.is_empty() || field.is_empty() {
        return json_ok("{\"error\":\"missing prefix or field\"}".into());
    }
    let panel_path = crate::server::geoip_panel::db::panel_db_path();
    let panel_path = panel_path.as_path();
    match db::open_panel(panel_path) {
        Ok(conn) => {
            if crate::server::geoip_panel::ops::upsert_edit(
                &conn,
                &prefix,
                &field,
                &value,
                weight,
            )
            .is_ok()
            {
                json_ok("{\"ok\":true}".into())
            } else {
                json_ok("{\"error\":\"edit failed\"}".into())
            }
        }
        Err(e) => json_ok(format!("{{\"error\":{}}}", json_str(&format!("{e:#}")))),
    }
}

/// `GET /api/geoip/edits?limit=` — 当前手工覆盖列表（仅 admin 前缀暴露）。
pub async fn handle_edits(req: &Request<Full<Bytes>>) -> Response<BoxBody> {
    if req.method() != Method::GET {
        return method_not_allowed();
    }
    let limit = query_param(req.uri().query().unwrap_or(""), "limit")
        .and_then(|s| s.parse().ok())
        .unwrap_or(200usize);
    let panel_path = crate::server::geoip_panel::db::panel_db_path();
    let panel_path = panel_path.as_path();
    if !panel_path.is_file() {
        return json_ok("{\"edits\":[]}".into());
    }
    match db::open_panel(panel_path) {
        Ok(conn) => match crate::server::geoip_panel::ops::list_edits(&conn, limit) {
            Ok(rows) => {
                let items: Vec<String> = rows
                    .iter()
                    .map(|(id, prefix, field, value, weight)| {
                        format!(
                            "{{\"id\":{id},\"prefix\":{},\"field\":{},\"value\":{},\"weight\":{weight}}}",
                            json_str(prefix),
                            json_str(field),
                            json_str(value)
                        )
                    })
                    .collect();
                json_ok(format!("{{\"edits\":[{}]}}", items.join(",")))
            }
            Err(e) => json_ok(format!("{{\"error\":{}}}", json_str(&format!("{e:#}")))),
        },
        Err(e) => json_ok(format!("{{\"error\":{}}}", json_str(&format!("{e:#}")))),
    }
}

/// `POST /api/geoip/edit/delete` body: id=
pub async fn handle_edit_delete(req: Request<Full<Bytes>>) -> Response<BoxBody> {
    if req.method() != Method::POST {
        return method_not_allowed();
    }
    let (_parts, body) = req.into_parts();
    let bytes = body
        .collect()
        .await
        .map(|c| c.to_bytes())
        .unwrap_or_default();
    let body = String::from_utf8_lossy(&bytes);
    let Some(id) = form_field(&body, "id").and_then(|s| s.parse::<i64>().ok()) else {
        return json_ok("{\"error\":\"missing id\"}".into());
    };
    let panel_path = crate::server::geoip_panel::db::panel_db_path();
    let panel_path = panel_path.as_path();
    match db::open_panel(panel_path) {
        Ok(conn) => {
            match crate::server::geoip_panel::ops::delete_edit(&conn, id) {
                Ok(true) => json_ok("{\"ok\":true}".into()),
                Ok(false) => json_ok("{\"error\":\"not found\"}".into()),
                Err(e) => json_ok(format!("{{\"error\":{}}}", json_str(&format!("{e:#}")))),
            }
        }
        Err(e) => json_ok(format!("{{\"error\":{}}}", json_str(&format!("{e:#}")))),
    }
}

/// `POST /api/geoip/conflicts/resolve` body: id=
pub async fn handle_conflict_resolve(req: Request<Full<Bytes>>) -> Response<BoxBody> {
    if req.method() != Method::POST {
        return method_not_allowed();
    }
    let (_parts, body) = req.into_parts();
    let bytes = body
        .collect()
        .await
        .map(|c| c.to_bytes())
        .unwrap_or_default();
    let body = String::from_utf8_lossy(&bytes);
    let Some(id) = form_field(&body, "id").and_then(|s| s.parse::<i64>().ok()) else {
        return json_ok("{\"error\":\"missing id\"}".into());
    };
    let panel_path = crate::server::geoip_panel::db::panel_db_path();
    let panel_path = panel_path.as_path();
    match db::open_panel(panel_path) {
        Ok(conn) => match crate::server::geoip_panel::ops::resolve_conflict(&conn, id) {
            Ok(true) => json_ok("{\"ok\":true}".into()),
            Ok(false) => json_ok("{\"error\":\"not found\"}".into()),
            Err(e) => json_ok(format!("{{\"error\":{}}}", json_str(&format!("{e:#}")))),
        },
        Err(e) => json_ok(format!("{{\"error\":{}}}", json_str(&format!("{e:#}")))),
    }
}

/// `GET /api/geoip/audit?limit=`
pub async fn handle_audit(req: &Request<Full<Bytes>>) -> Response<BoxBody> {
    if req.method() != Method::GET {
        return method_not_allowed();
    }
    let limit = query_param(req.uri().query().unwrap_or(""), "limit")
        .and_then(|s| s.parse().ok())
        .unwrap_or(100usize);
    let panel_path = crate::server::geoip_panel::db::panel_db_path();
    let panel_path = panel_path.as_path();
    if !panel_path.is_file() {
        return json_ok("{\"audit\":[]}".into());
    }
    match db::open_panel(panel_path) {
        Ok(conn) => match crate::server::geoip_panel::ops::list_audit(&conn, limit) {
            Ok(rows) => {
                let mut items = String::new();
                for (i, (id, action, detail, ts)) in rows.iter().enumerate() {
                    if i > 0 {
                        items.push(',');
                    }
                    items.push_str(&format!(
                        "{{\"id\":{id},\"action\":{},\"detail\":{},\"ts\":{ts}}}",
                        json_str(action),
                        json_str(detail)
                    ));
                }
                json_ok(format!("{{\"audit\":[{items}]}}"))
            }
            Err(e) => json_ok(format!("{{\"error\":{}}}", json_str(&format!("{e:#}")))),
        },
        Err(e) => json_ok(format!("{{\"error\":{}}}", json_str(&format!("{e:#}")))),
    }
}

/// `GET /api/geoip/cron` | `POST name=&schedule=&enabled=`
pub async fn handle_cron(req: Request<Full<Bytes>>) -> Response<BoxBody> {
    let panel_path = crate::server::geoip_panel::db::panel_db_path();
    let panel_path = panel_path.as_path();
    match req.method() {
        &Method::GET => {
            if !panel_path.is_file() {
                return json_ok("{\"cron\":[]}".into());
            }
            match db::open_panel(panel_path) {
                Ok(conn) => match crate::server::geoip_panel::ops::list_cron(&conn) {
                    Ok(rows) => {
                        let mut items = String::new();
                        for (i, (id, name, schedule, enabled, last_run)) in rows.iter().enumerate()
                        {
                            if i > 0 {
                                items.push(',');
                            }
                            items.push_str(&format!(
                                "{{\"id\":{id},\"name\":{},\"schedule\":{},\"enabled\":{},\"last_run\":{last_run}}}",
                                json_str(name),
                                json_str(schedule),
                                *enabled != 0
                            ));
                        }
                        json_ok(format!("{{\"cron\":[{items}]}}"))
                    }
                    Err(e) => json_ok(format!("{{\"error\":{}}}", json_str(&format!("{e:#}")))),
                },
                Err(e) => json_ok(format!("{{\"error\":{}}}", json_str(&format!("{e:#}")))),
            }
        }
        &Method::POST => {
            let (_parts, body) = req.into_parts();
            let bytes = body
                .collect()
                .await
                .map(|c| c.to_bytes())
                .unwrap_or_default();
            let body = String::from_utf8_lossy(&bytes);
            let name = form_field(&body, "name").unwrap_or_default();
            let schedule = form_field(&body, "schedule").unwrap_or_else(|| "daily".into());
            let enabled = form_field(&body, "enabled")
                .map(|s| s == "1" || s.eq_ignore_ascii_case("true"))
                .unwrap_or(true);
            if name.is_empty() {
                return json_ok("{\"error\":\"missing name\"}".into());
            }
            match db::open_panel(panel_path) {
                Ok(conn) => {
                    if crate::server::geoip_panel::ops::upsert_cron(
                        &conn, &name, &schedule, enabled,
                    )
                    .is_ok()
                    {
                        json_ok("{\"ok\":true}".into())
                    } else {
                        json_ok("{\"error\":\"cron upsert failed\"}".into())
                    }
                }
                Err(e) => json_ok(format!("{{\"error\":{}}}", json_str(&format!("{e:#}")))),
            }
        }
        _ => method_not_allowed(),
    }
}

/// `POST /api/geoip/sources` body: name=&enabled=&weight=
pub async fn handle_source_set(req: Request<Full<Bytes>>) -> Response<BoxBody> {
    if req.method() != Method::POST {
        return method_not_allowed();
    }
    let (_parts, body) = req.into_parts();
    let bytes = body
        .collect()
        .await
        .map(|c| c.to_bytes())
        .unwrap_or_default();
    let body = String::from_utf8_lossy(&bytes);
    let name = form_field(&body, "name").unwrap_or_default();
    if name.is_empty() {
        return json_ok("{\"error\":\"missing name\"}".into());
    }
    let enabled = form_field(&body, "enabled").map(|s| s == "1" || s.eq_ignore_ascii_case("true"));
    let weight = form_field(&body, "weight").and_then(|s| s.parse().ok());
    let panel_path = crate::server::geoip_panel::db::panel_db_path();
    let panel_path = panel_path.as_path();
    match db::open_panel(panel_path) {
        Ok(conn) => match crate::server::geoip_panel::ops::set_source(&conn, &name, enabled, weight)
        {
            Ok(()) => {
                // G-18：源权重/启停同时写入 panel.toml（面板设置以它为准）。
                // sqlite 写成功但 toml 写失败时明确告知，而不是假装全部成功。
                match toml_store::update_source(&name, weight, enabled) {
                    Ok(()) => json_ok("{\"ok\":true}".into()),
                    Err(e) => json_ok(format!(
                        "{{\"ok\":true,\"panel_toml_saved\":false,\"warning\":{}}}",
                        json_str(&format!("source 已写入 panel.sqlite，但 panel.toml 保存失败：{e:#}"))
                    )),
                }
            }
            Err(e) => json_ok(format!(
                "{{\"error\":{}}}",
                json_str(&format!("source update failed: {e:#}"))
            )),
        },
        Err(e) => json_ok(format!("{{\"error\":{}}}", json_str(&format!("{e:#}")))),
    }
}

/// `POST /api/geoip/update` — spawn offline merge script.
pub async fn handle_update_trigger(_req: Request<Full<Bytes>>) -> Response<BoxBody> {
    let root = std::path::Path::new(".");
    match crate::server::geoip_panel::ops::spawn_geoip_update(root) {
        Ok(()) => json_ok("{\"ok\":true,\"spawned\":\"geoip_update.sh\"}".into()),
        // 失败也带 `ok:false`：前端按 HTTP 状态判断成功与否，只回 {"error":...} 会被当成
        // 「已触发」并显示成功提示（实际被并发保护挡下了）。
        Err(e) => json_ok(format!(
            "{{\"ok\":false,\"error\":{}}}",
            json_str(&format!("{e:#}"))
        )),
    }
}

fn form_field(body: &str, key: &str) -> Option<String> {
    for part in body.split('&') {
        if let Some((k, v)) = part.split_once('=') {
            if k == key {
                return Some(decode_component(v));
            }
        }
    }
    None
}

/// 解一个 `application/x-www-form-urlencoded` / query 组件。
///
/// 为什么不能直接 `percent_decode_str`：它只认 `%XX`，**不认 `+`**，而前端
/// （`admin_ui.html` 的 `fpost` / 冲突裁决的 `URLSearchParams`）以及浏览器本身
/// 都把空格编成 `+`。于是 "China Telecom" 到达服务端是 `China+Telecom`，被原样
/// 存进 `panel_edits.value`（覆盖值被写坏）或拿去 LIKE 匹配（多词 ISP/Cloud
/// 筛选恒空，表现为「库里没数据」）。顺序必须是先 `+`→空格再百分号解码：
/// 编码器会把字面 `+` 编成 `%2B`，先解百分号再替换会把 `%2B` 错当空格。
fn decode_component(v: &str) -> String {
    let spaced = v.replace('+', " ");
    percent_encoding::percent_decode_str(&spaced)
        .decode_utf8_lossy()
        .into_owned()
}

/// `GET /api/geoip/update/status?since=<bytes>` — 离线更新的进度。
///
/// 返回自 `since` 偏移之后的日志增量（脚本全程 tee 到 update.log），
/// 以及进程是否还在跑（依据 spawn 时写下的 update.pid）。
/// 前端据此轮询：触发 → 记下当前日志大小 → 每 1.5s 取增量增量显示。
pub async fn handle_update_status(req: &Request<Full<Bytes>>) -> Response<BoxBody> {
    use std::io::{Read, Seek, SeekFrom};
    let q = req.uri().query().unwrap_or("");
    let since: u64 = form_field(q, "since").and_then(|v| v.parse().ok()).unwrap_or(0);

    let log_path = std::path::Path::new("data/geoip/logs/update.log");
    let pid_path = std::path::Path::new("data/geoip/logs/update.pid");

    let pid: Option<u32> = std::fs::read_to_string(pid_path)
        .ok()
        .and_then(|s| s.trim().parse().ok());
    // 「在跑」的判定以**脚本自己的锁目录 + 命令行**为准：只看 pid 会被 pid 复用骗到
    // （实测：脚本早退出了，pid 被别的进程接手，面板就一直显示「进行中」）。
    let lock_dir = std::path::Path::new("data/geoip/logs/update.lock");
    let lock_pid: Option<i32> = std::fs::read_to_string(lock_dir.join("pid"))
        .ok()
        .and_then(|s| s.trim().parse().ok());
    let running = lock_pid
        .map(crate::server::geoip_panel::ops::proc_is_geoip_update)
        .unwrap_or(false);
    if !running {
        let _ = std::fs::remove_file(pid_path);
    }

    let mut chunk = String::new();
    let mut size: u64 = 0;
    let mut truncated = false;
    if let Ok(mut f) = std::fs::File::open(log_path) {
        if let Ok(md) = f.metadata() {
            size = md.len();
        }
        let from = since.min(size);
        if f.seek(SeekFrom::Start(from)).is_ok() {
            // 上限 256 KiB：一次轮询不该把整个日志灌给浏览器。
            let mut buf = vec![0u8; 256 * 1024];
            if let Ok(n) = f.read(&mut buf) {
                if (size - from) > n as u64 {
                    truncated = true;
                }
                chunk = String::from_utf8_lossy(&buf[..n]).into_owned();
            }
        }
    }
    // `done` 必须看**日志尾部**，而不是从 `since` 开始的那段分片：分片可能落在好几轮之前的
    // 旧 "done" 上（面板传 since=0、或缓存的偏移比日志短时都会），于是更新刚起步就报「已完成」。
    // 尾部 4KiB 足以覆盖最后写入的那一行；再要求 `!running`，因为「跑完了」的语义是
    // 「没有进程在跑 **且** 日志末尾写了 done」。
    let tail_done = {
        let mut s = String::new();
        if let Ok(mut f) = std::fs::File::open(log_path) {
            if f.seek(SeekFrom::Start(size.saturating_sub(4096))).is_ok() {
                let mut buf = Vec::new();
                if f.read_to_end(&mut buf).is_ok() {
                    s = String::from_utf8_lossy(&buf).into_owned();
                }
            }
        }
        s.contains("geoip_update done")
    };
    let done = !running && tail_done;
    let resp = serde_json::json!({
        "running": running,
        "pid": pid,
        "from": since,
        "to": size,
        "done": done,
        "truncated": truncated,
        "log": chunk,
    });
    json_ok(resp.to_string())
}

/// `GET /api/geoip/status` — standalone env path（同上，路由只用 `_with_live` 版本）。
#[allow(dead_code)]
pub async fn handle_status(_req: &Request<Full<Bytes>>) -> Response<BoxBody> {
    let db_path = crate::server::apps::env_lock::read_static_env("CRUCIBLE_GEOIP_DB")
        .unwrap_or_else(|| "data/geoip/current/geoip.sqlite".into());
    let exists = std::path::Path::new(&db_path).is_file();
    json_ok(format!(
        "{{\"enabled\":{},\"db_path\":{},\"message\":\"rust geoip panel\"}}",
        exists,
        json_str(&db_path)
    ))
}

/// Public `/api/geoip/*` routes (no admin prefix) when `geoip.enabled`.
/// 泛型 body：h1（Incoming）/ h2（Full<Bytes>）统一调用。安全策略：GeoIP API
/// 仅 admin 面板（鉴权后）暴露，公共路径一律拒绝（当前直接 None）。
pub async fn try_handle_public<T>(
    _req: &Request<T>,
    _live: &Arc<LiveConfig>,
) -> Option<Response<BoxBody>> {
    // Security: GeoIP APIs are admin-only (no anonymous panel data).
    None
}

fn resolve_db_path(live: &Arc<LiveConfig>) -> Option<PathBuf> {
    let snap = live.snapshot();
    snap.geoip
        .db_path
        .clone()
        .or_else(|| {
            crate::server::apps::env_lock::read_static_env("CRUCIBLE_GEOIP_DB").map(PathBuf::from)
        })
        .or_else(|| Some(PathBuf::from("data/geoip/current/geoip.sqlite")))
}

fn lookup_json(ip_s: &str, db_path: Option<&std::path::Path>) -> Response<BoxBody> {
    if ip_s.is_empty() {
        return json_ok("{\"error\":\"missing ip query param\"}".to_string());
    }
    let Ok(ip) = IpAddr::from_str(ip_s) else {
        return json_ok(format!(
            "{{\"ip\":{},\"status\":\"invalid\",\"country\":null,\"label\":null}}",
            json_str(ip_s)
        ));
    };
    // v4-mapped（`::ffff:1.2.3.4`）折回 v4 再查：covering 按地址族分流，带着 `::ffff:`
    // 前缀会被当成 v6 去查 ipv6 表，于是同一个地址在双栈入口下查不到任何 v4 数据
    // （面板显示「无结果」）。与 rate_limit/access/basic_auth 的归一化口径一致。
    let ip = iputil::unmap_v4_mapped(ip);
    let Some(db_path) = db_path else {
        return json_ok(format!(
            "{{\"ip\":{},\"status\":\"no_db\",\"country\":null,\"label\":null}}",
            json_str(ip_s)
        ));
    };
    if !db_path.is_file() {
        return json_ok(format!(
            "{{\"ip\":{},\"status\":\"no_db\",\"db_path\":{},\"country\":null,\"label\":null}}",
            json_str(ip_s),
            json_str(&db_path.display().to_string())
        ));
    }

    match db::open(db_path) {
        Ok(conn) => {
            // 一次扫描同时拿到合并结果与命中的前缀行：原先这里先调一次
            // load_covering_prefixes，lookup_merged 内部又调一次 —— 同一个请求把
            // ipv4/ipv6 全表扫了两遍，而这是面板最热的路径（且两张表都没有可用的
            // 数值范围索引，见 covering.rs::load_from_range_table 的说明）。
            match covering::lookup_merged_with_rows(&conn, &ip.to_string()) {
                Ok((m, covering_rows)) => {
                    let mut gr = lookup::GeoResult::from_merged(m);
                    if !gr.isp.is_empty() {
                        gr.isp = aliases::resolve_isp_alias(&gr.isp);
                        gr.label = lookup::format_label(&gr);
                    }
                    let covering_json: Vec<String> = covering_rows
                        .iter()
                        .map(|p| {
                            format!(
                                "{{\"prefix\":{},\"bits\":{},\"weight\":{},\
\"country\":{},\"province\":{},\"city\":{},\"district\":{},\
\"isp\":{},\"asn\":{},\"as_org\":{},\
\"cloud_provider\":{},\"cloud_region\":{},\"cloud_service\":{},\
\"hosting\":{},\"division_code\":{},\"dc\":{}}}",
                                json_str(&p.prefix),
                                p.bits,
                                p.weight,
                                json_str(&p.country),
                                json_str(&p.province),
                                json_str(&p.city),
                                json_str(&p.district),
                                json_str(&p.isp),
                                json_str(&p.asn),
                                json_str(&p.as_org),
                                json_str(&p.cloud_provider),
                                json_str(&p.cloud_region),
                                json_str(&p.cloud_service),
                                json_str(&p.hosting),
                                json_str(&p.division_code),
                                json_str(&p.dc)
                            )
                        })
                        .collect();
                    json_ok(format!(
                        "{{\"ip\":{},\"status\":\"ok\",\
\"country\":{},\"province\":{},\"region\":{},\"city\":{},\"district\":{},\
\"isp\":{},\"asn\":{},\"as_org\":{},\"net_org\":{},\
\"cloud_provider\":{},\"cloud_region\":{},\"cloud_service\":{},\
\"hosting\":{},\"division_code\":{},\"dc\":{},\
\"prefix\":{},\"bits\":{},\"weight\":{},\"commit_unix\":{},\
\"prefixes_merged\":{},\"label\":{},\
\"covering\":[{}]}}",
                        json_str(ip_s),
                        json_str(&gr.country),
                        json_str(&gr.province),
                        json_str(&gr.region),
                        json_str(&gr.city),
                        json_str(&gr.district),
                        json_str(&gr.isp),
                        json_str(&gr.asn),
                        json_str(&gr.as_org),
                        json_str(&gr.net_org),
                        json_str(&gr.cloud_provider),
                        json_str(&gr.cloud_region),
                        json_str(&gr.cloud_service),
                        json_str(&gr.hosting),
                        json_str(&gr.division_code),
                        json_str(&gr.dc),
                        json_str(&gr.prefix),
                        gr.bits,
                        gr.weight,
                        gr.commit_unix,
                        gr.prefixes_merged,
                        json_str(&gr.label),
                        covering_json.join(","),
                    ))
                }
                Err(e) => json_ok(format!(
                    "{{\"ip\":{},\"status\":\"error\",\"message\":{}}}",
                    json_str(ip_s),
                    json_str(&format!("{e:#}"))
                )),
            }
        }
        Err(e) => json_ok(format!(
            "{{\"ip\":{},\"status\":\"error\",\"message\":{}}}",
            json_str(ip_s),
            json_str(&format!("{e:#}"))
        )),
    }
}

fn query_param(q: &str, key: &str) -> Option<String> {
    for part in q.split('&') {
        if let Some((k, v)) = part.split_once('=') {
            if k == key {
                return Some(decode_component(v));
            }
        }
    }
    None
}

fn json_str(s: &str) -> String {
    // 交给 serde_json：手工拼接漏掉控制字符（`\n`/`\t`/`\r` 与其余 <0x20）时，
    // 值里一个换行就能让整个响应不再是合法 JSON —— 前端 `JSON.parse` 立刻失败，
    // 该面板模块直接不可用。值来源包括面板写入的 `edit.value`（`%0A` 可注入）
    // 与外部 GeoIP 库字段；同文件的 `handle_conflict_source` 早就用 serde_json，这里与它一致。
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string())
}

/// 与 `json_str` 相同但**不带外层引号**（用 serde_json 生成再剥引号，
/// 控制字符与转义一次处理干净）。
fn json_escape(s: &str) -> String {
    let q = json_str(s);
    q.strip_prefix('"')
        .and_then(|x| x.strip_suffix('"'))
        .unwrap_or(&q)
        .to_string()
}

fn json_ok(body: String) -> Response<BoxBody> {
    Response::builder()
        .status(StatusCode::OK)
        .header(http::header::CONTENT_TYPE, "application/json; charset=utf-8")
        .body(full(body))
        .unwrap()
}

fn method_not_allowed() -> Response<BoxBody> {
    Response::builder()
        .status(StatusCode::METHOD_NOT_ALLOWED)
        .body(full("method not allowed"))
        .unwrap()
}

// GET /api/geoip/conflicts/source?id=&src=&field=  查某源在某冲突前缀的字段值
pub async fn handle_conflict_source(req: Request<Full<Bytes>>) -> Response<BoxBody> {
    let uri = req.uri();
    let params = match uri.query() {
        Some(q) => q,
        None => return json_ok(r#"{"error":"missing query"}"#.into()),
    };
    let mut id_val: Option<i64> = None;
    let mut src: Option<String> = None;
    let mut field: Option<String> = None;
    for pair in params.split('&') {
        let mut kv = pair.splitn(2, '=');
        let k = kv.next().unwrap_or("");
        let v = kv.next().unwrap_or("");
        match k {
            "id" => id_val = v.parse().ok(),
            "src" => src = Some(url_decode(v)),
            "field" => field = Some(url_decode(v)),
            _ => {}
        }
    }
    let (Some(id), Some(s), Some(f)) = (id_val, src, field) else {
        return json_ok(r#"{"error":"missing id/src/field"}"#.into());
    };
    let panel_path = crate::server::geoip_panel::db::panel_db_path();
    let panel_path = panel_path.as_path();
    let panel = match db::open_panel(panel_path) {
        Ok(c) => c,
        Err(e) => return json_ok(format!(r#"{{"error":"{}"}}"#, json_escape(&format!("{e:#}")))),
    };
    let row: Option<(String, String)> = panel
        .query_row(
            "SELECT prefix,field FROM panel_conflicts WHERE id=?",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .ok();
    let Some((prefix, _conflict_field)) = row else {
        return json_ok(r#"{"error":"conflict not found"}"#.into());
    };
    let covering_path = std::path::Path::new("data/geoip/current/geoip.sqlite");
    let conn = match db::open(covering_path) {
        Ok(c) => c,
        Err(e) => return json_ok(format!(r#"{{"error":"{}"}}"#, json_escape(&format!("open covering: {e:#}")))),
    };
    let value = crate::server::geoip_panel::ops::get_covering_field(&conn, &s, &prefix, &f)
        .ok()
        .flatten()
        .unwrap_or_default();
    // 表名是 `geoip`（另有 ipv4/ipv6/anycast/panel_edits/panel_conflicts），
    // **没有** `covering` 这张表 —— 原查询每次都报 "no such table"，
    // 又被 .unwrap_or(0) 吞掉，于是冲突解决界面永远显示 commit_unix=0，
    // 管理员据此判断「哪个来源更可信」时看到的是错的来源时间戳。
    // 另外：同一前缀可能有多个来源，按 commit_unix 取最新的一条。
    let commit_unix: i64 = conn
        .query_row(
            "SELECT COALESCE(commit_unix, 0) FROM geoip WHERE source = ? AND prefix = ?
             ORDER BY COALESCE(commit_unix, 0) DESC LIMIT 1",
            [&s, &prefix],
            |r| r.get(0),
        )
        .unwrap_or(0);
    let resp = serde_json::json!({
        "value": value,
        "commit_unix": commit_unix,
        "source": s,
        "prefix": prefix,
        "field": f
    });
    json_ok(serde_json::to_string(&resp).unwrap_or_default().into())
}

fn url_decode(s: &str) -> String {
    let mut r = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if hex.len() == 2 {
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    r.push(byte as char);
                }
            }
        } else if c == '+' {
            r.push(' ');
        } else {
            r.push(c);
        }
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 表单/查询解码：空格（前端编成 `+`）必须还原；`%2B` 是字面加号，不能被当成空格。
    #[test]
    fn form_and_query_decode_plus_as_space() {
        // 前端 fpost/URLSearchParams 把 "China Telecom" 编成 "China+Telecom"
        assert_eq!(form_field("value=China+Telecom", "value").unwrap(), "China Telecom");
        assert_eq!(
            query_param("isp=China+Telecom&limit=50", "isp").unwrap(),
            "China Telecom"
        );
        // 字面加号：编码器产出 %2B —— 先替换 '+' 再百分号解码才不会误伤
        assert_eq!(form_field("value=a%2Bb", "value").unwrap(), "a+b");
        // UTF-8 百分号编码
        assert_eq!(form_field("country=%E4%B8%AD%E5%9B%BD", "country").unwrap(), "中国");
        // 缺失键
        assert!(form_field("value=x", "other").is_none());
        assert!(query_param("a=1", "b").is_none());
    }
}

