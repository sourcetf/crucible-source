//! Admin GeoIP API handlers (Rust-only; no Python bridge).

use crate::server::geoip_panel::{aliases, covering, db, lookup, sources};
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
    let panel = std::path::Path::new("data/geoip/panel.sqlite");
    let panel_exists = panel.is_file();
    json_ok(format!(
        "{{\"enabled\":{},\"db_path\":{},\"exists\":{},\"panel_exists\":{},\"message\":\"rust geoip panel §23\"}}",
        snap.geoip.enabled,
        json_str(&path_s),
        exists,
        panel_exists
    ))
}

/// `GET /api/geoip/lookup?ip=…` — standalone (env / default path).
pub async fn handle_lookup(req: &Request<Full<Bytes>>) -> Response<BoxBody> {
    if req.method() != Method::GET {
        return method_not_allowed();
    }
    let ip_s = query_param(req.uri().query().unwrap_or(""), "ip").unwrap_or_default();
    let db_path = std::env::var("CRUCIBLE_GEOIP_DB")
        .ok()
        .map(PathBuf::from)
        .or_else(|| Some(PathBuf::from("data/geoip/current/geoip.sqlite")));
    lookup_json(&ip_s, db_path.as_deref())
}

/// `GET /api/geoip/filter?country=&isp=&cloud=&limit=`
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
    let limit = query_param(q, "limit")
        .and_then(|s| s.parse().ok())
        .unwrap_or(50usize);
    let db_path = resolve_db_path(live);
    let Some(db_path) = db_path else {
        return json_ok("{\"rows\":[],\"error\":\"no_db\"}".into());
    };
    match db::open(&db_path) {
        Ok(conn) => match crate::server::geoip_panel::ops::filter_prefixes(
            &conn,
            country.as_deref(),
            isp.as_deref(),
            cloud.as_deref(),
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
    let panel_path = std::path::Path::new("data/geoip/panel.sqlite");
    let mut items = String::new();
    if panel_path.is_file() {
        if let Ok(conn) = db::open_panel(panel_path) {
            if let Ok(rows) = sources::list_sources(&conn) {
                for (i, s) in rows.iter().enumerate() {
                    if i > 0 {
                        items.push(',');
                    }
                    items.push_str(&format!(
                        "{{\"name\":{},\"weight\":{},\"enabled\":{},\"url\":{},\"last_commit\":{},\"last_unix\":{}}}",
                        json_str(&s.name),
                        s.weight,
                        s.enabled,
                        json_str(&s.url),
                        json_str(&s.last_commit),
                        s.last_unix
                    ));
                }
            }
        }
    }
    let sources_json = std::path::Path::new("data/geoip/current/SOURCES.json");
    let file_meta = if sources_json.is_file() {
        match sources::load_sources_json(sources_json) {
            Ok(raw) => raw,
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
    let panel_path = std::path::Path::new("data/geoip/panel.sqlite");
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
    let panel_path = std::path::Path::new("data/geoip/panel.sqlite");
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
    let panel_path = std::path::Path::new("data/geoip/panel.sqlite");
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
    let panel_path = std::path::Path::new("data/geoip/panel.sqlite");
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
    let panel_path = std::path::Path::new("data/geoip/panel.sqlite");
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
    let panel_path = std::path::Path::new("data/geoip/panel.sqlite");
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
    let panel_path = std::path::Path::new("data/geoip/panel.sqlite");
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
    let panel_path = std::path::Path::new("data/geoip/panel.sqlite");
    match db::open_panel(panel_path) {
        Ok(conn) => {
            if crate::server::geoip_panel::ops::set_source(&conn, &name, enabled, weight).is_ok() {
                json_ok("{\"ok\":true}".into())
            } else {
                json_ok("{\"error\":\"source update failed\"}".into())
            }
        }
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
                return Some(
                    percent_encoding::percent_decode_str(v)
                        .decode_utf8_lossy()
                        .into_owned(),
                );
            }
        }
    }
    None
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
    // kill(pid, 0)：只探测存在性，不发信号。进程没了就顺手清掉 pid 文件，
    // 免得 pid 被复用后误报「还在跑」。
    let running = match pid {
        Some(p) => {
            let alive = unsafe { libc::kill(p as i32, 0) } == 0;
            if !alive {
                let _ = std::fs::remove_file(pid_path);
            }
            alive
        }
        None => false,
    };

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

/// `GET /api/geoip/status` — standalone env path.
pub async fn handle_status(_req: &Request<Full<Bytes>>) -> Response<BoxBody> {
    let db_path = std::env::var("CRUCIBLE_GEOIP_DB")
        .unwrap_or_else(|_| "data/geoip/current/geoip.sqlite".into());
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
        .or_else(|| std::env::var("CRUCIBLE_GEOIP_DB").ok().map(PathBuf::from))
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
\"country\":{},\"province\":{},\"city\":{},\"district\":{},\
\"isp\":{},\"asn\":{},\"as_org\":{},\
\"cloud_provider\":{},\"cloud_region\":{},\"cloud_service\":{},\
\"hosting\":{},\"division_code\":{},\"dc\":{},\
\"bits\":{},\"prefixes_merged\":{},\"label\":{},\
\"covering\":[{}]}}",
                        json_str(ip_s),
                        json_str(&gr.country),
                        json_str(&gr.province),
                        json_str(&gr.city),
                        json_str(&gr.district),
                        json_str(&gr.isp),
                        json_str(&gr.asn),
                        json_str(&gr.as_org),
                        json_str(&gr.cloud_provider),
                        json_str(&gr.cloud_region),
                        json_str(&gr.cloud_service),
                        json_str(&gr.hosting),
                        json_str(&gr.division_code),
                        json_str(&gr.dc),
                        gr.bits,
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
                return Some(
                    percent_encoding::percent_decode_str(v)
                        .decode_utf8_lossy()
                        .into_owned(),
                );
            }
        }
    }
    None
}

fn json_str(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// 与 `json_str` 相同但**不带外层引号**，用于已预置引号的 JSON 字面量内部
/// （避免出现 `""…""` 这种非法 JSON）。
fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
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
    let panel_path = std::path::Path::new("data/geoip/panel.sqlite");
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

