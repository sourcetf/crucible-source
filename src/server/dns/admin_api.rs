//! DNS 管理面板 API（鉴权由 admin.rs 的 Basic gate 完成，这里只做路由与落盘/reconcile）。
//! 面板编辑持久化到 state/dns/etc/panel.toml（整体覆盖 config.toml 的 [dns]，见 dns::effective）。

use super::*;
use crate::server::h1::{full, BoxBody};
use http::{Method, Response, StatusCode};
use serde_json::{json, Value};
use std::sync::Arc;

pub async fn handle(
    req: http::Request<http_body_util::Full<bytes::Bytes>>,
    live: &Arc<crate::server::live_config::LiveConfig>,
) -> Response<BoxBody> {
    match handle_inner(req, live).await {
        Ok(resp) => resp,
        Err(e) => Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(full(json!({"error": e}).to_string()))
            .unwrap(),
    }
}

/// 内部实现返回 Result —— 主体大量 `?` 直通错误信息（v2：半成品 handle 返回
/// Response 却在分支里用 `?`，从未编译通过；拆分后语义不变）。
async fn handle_inner(
    req: http::Request<http_body_util::Full<bytes::Bytes>>,
    live: &Arc<crate::server::live_config::LiveConfig>,
) -> Result<Response<BoxBody>, String> {
    use http_body_util::BodyExt;
    let path = req.uri().path().to_string();
    let method = req.method().clone();
    let query_str = req.uri().query().unwrap_or("").to_string();
    let snap = live.snapshot();
    let mut dc = effective(&snap);

    let result: Result<Value, String> = if method == Method::GET {
        match path.as_str() {
            p if p.ends_with("/api/dns/status") => status_json(&dc),
            p if p.ends_with("/api/dns/acme") => Ok(acme::status(&dc.acme)),
            p if p.ends_with("/api/dns/config") => {
                serde_json::to_value(&dc).map_err(|e| e.to_string())
            }
            p if p.ends_with("/api/dns/zones") => {
                list_zones().map(|zs| json!({"zones": zs})).map_err(|e| e.to_string())
            }
            p if p.ends_with("/api/dns/records") => {
                let q = req.uri().query().unwrap_or("");
                let zone = q
                    .split('&')
                    .find_map(|kv| kv.strip_prefix("zone="))
                    .unwrap_or("");
                // 从区的记录不在 DB 里：named 传输后写进自己的 zone 文件。面板要显示就得读盘
                // 上那份（readonly 告知前端不要给编辑/删除）。文件还没生成（传输未完成）时
                // 返回空表 + note，而不是 500 —— 那只是「还没同步过来」。
                let kind = super::zone_kind_of(zone).unwrap_or_default();
                if !kind.is_empty() && kind != "master" {
                    match super::list_secondary_records(zone) {
                        Ok(rs) => Ok(json!({"records": rs, "readonly": true, "kind": kind})),
                        Err(e) => Ok(json!({
                            "records": [],
                            "readonly": true,
                            "kind": kind,
                            "note": format!("{e:#}"),
                        })),
                    }
                } else {
                    list_records(zone)
                        .map(|rs| json!({"records": rs}))
                        .map_err(|e| e.to_string())
                }
            }
            _ => Err("not found".into()),
        }
    } else if method == Method::POST {
        let (_, body) = req.into_parts();
        let bytes = body
            .collect()
            .await
            .map_err(|e| format!("body: {e}"))?
            .to_bytes();
        let v: Value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).map_err(|e| format!("json: {e}"))?
        };
        match path.as_str() {
            p if p.ends_with("/api/dns/config") => {
                dc = serde_json::from_value(v).map_err(|e| e.to_string())?;
                persist_and_reconcile(&dc).await?;
                Ok(json!({"ok": true, "status": "reconciled"}))
            }
            p if p.ends_with("/api/dns/modes") => {
                dc.modes.root = v["root"].as_bool().unwrap_or(dc.modes.root);
                dc.modes.recursive = v["recursive"].as_bool().unwrap_or(dc.modes.recursive);
                dc.modes.authoritative = v["authoritative"]
                    .as_bool()
                    .or_else(|| v["auth"].as_bool())
                    .unwrap_or(dc.modes.authoritative);
                dc.enabled = v["enabled"].as_bool().unwrap_or(true);
                dc.ecs = v["ecs"].as_bool().unwrap_or(dc.ecs);
                persist_and_reconcile(&dc).await?;
                Ok(json!({"ok": true, "modes": dc.modes}))
            }
            p if p.ends_with("/api/dns/zones") => {
                let action = v["action"].as_str().unwrap_or("add");
                match action {
                    // .zone 文本导入：mode=merge 追加、mode=replace 先清空本分区记录。
                    // 解析阶段全量校验，任何一行不合法就整体失败（不落半截数据）。
                    "import" => {
                        let name = v["name"].as_str().ok_or("name?")?.to_string();
                        let text = v["text"].as_str().ok_or("text?")?;
                        let mode = v["mode"].as_str().unwrap_or("merge").to_string();
                        if !valid_name(&name) {
                            return Err(format!("bad zone name {name:?}"));
                        }
                        let recs = parse_zone_text(text, &name)?;
                        if mode == "replace" {
                            del_zone_records(&name).map_err(|e| e.to_string())?;
                        }
                        let mut n = 0usize;
                        for r in &recs {
                            add_record(&name, "", &r.name, &r.rtype, r.ttl, &r.rdata)
                                .map_err(|e| e.to_string())?;
                            n += 1;
                        }
                        // 本 match 各分支统一返回 ()（函数尾部回 {"ok":true}），
                        // 条数记日志；前端刷新记录表即可看到「共 N 条」。
                        log::info!("dns import: zone={name} mode={mode} imported={n}");
                    }
                    "del" => {
                        let name = v["name"].as_str().ok_or("name?")?;
                        del_zone(name).map_err(|e| e.to_string())?;
                    }
                    _ => {
                        let name = v["name"].as_str().ok_or("name?")?;
                        let kind = v["kind"].as_str().unwrap_or("master");
                        let primaries: Vec<String> = json_strs(&v["primaries"]);
                        let axfr: Vec<String> = json_strs(&v["axfr_acl"]);
                        let refresh = v["refresh_hours"].as_u64().unwrap_or(24);
                        add_zone(kind, name, &primaries, &axfr, refresh)
                            .map_err(|e| e.to_string())?;
                    }
                }
                reconcile_current(&live).await?;
                Ok(json!({"ok": true}))
            }
            p if p.ends_with("/api/dns/records") => {
                let action = v["action"].as_str().unwrap_or("add");
                match action {
                    "del" => {
                        let id = v["id"].as_i64().ok_or("id?")?;
                        del_record(id).map_err(|e| e.to_string())?;
                    }
                    _ => {
                        let zone = v["zone"].as_str().ok_or("zone?")?;
                        let name = v["name"].as_str().unwrap_or("@");
                        let rtype = v["rtype"].as_str().ok_or("rtype?")?;
                        let ttl = v["ttl"].as_u64().unwrap_or(3600) as u32;
                        let rdata = v["rdata"].as_str().ok_or("rdata?")?;
                        let line = v["line"].as_str().unwrap_or("");
                        add_record(zone, line, name, rtype, ttl, rdata)
                            .map_err(|e| e.to_string())?;
                    }
                }
                reconcile_current(&live).await?;
                Ok(json!({"ok": true}))
            }
            // DNSSEC（需求 3/4/5）：策略保存 / 一键生成 / 私钥上传
            p if p.ends_with("/api/dns/dnssec") => {
                let action = v["action"].as_str().unwrap_or("policy");
                match action {
                    "keygen" => {
                        let zone = v["zone"].as_str().ok_or("zone?")?;
                        let role = v["role"].as_str().unwrap_or("zsk").to_string();
                        let alg = v["algorithm"]
                            .as_str()
                            .unwrap_or("ECDSAP256SHA256")
                            .to_string();
                        let z = zone.to_string();
                        let name = tokio::task::spawn_blocking(move || keygen(&z, &role, &alg))
                            .await
                            .map_err(|e| e.to_string())?
                            .map_err(|e| e.to_string())?;
                        Ok(json!({"ok": true, "key": name}))
                    }
                    "upload" => {
                        let filename = v["filename"].as_str().ok_or("filename?")?;
                        let b64 = v["b64"].as_str().ok_or("b64?")?;
                        let p = upload_key(filename, b64).map_err(|e| e.to_string())?;
                        Ok(json!({"ok": true, "path": p.to_string_lossy()}))
                    }
                    _ => {
                        dc.dnssec = serde_json::from_value(v["dnssec"].clone())
                            .map_err(|e| format!("dnssec: {e}"))?;
                        persist_and_reconcile(&dc).await?;
                        Ok(json!({"ok": true, "status": "reconciled"}))
                    }
                }
            }
            // AXFR 白名单（需求 6）：全局传出 ACL + slave zone 的 primaries/传入 ACL
            p if p.ends_with("/api/dns/axfr") => {
                let action = v["action"].as_str().unwrap_or("zone_acl");
                match action {
                    "global" => {
                        dc.axfr_out_acl = json_strs(&v["axfr_out_acl"]);
                        persist_and_reconcile(&dc).await?;
                        Ok(json!({"ok": true}))
                    }
                    _ => {
                        let name = v["name"].as_str().ok_or("name?")?;
                        let primaries: Vec<String> = json_strs(&v["primaries"]);
                        let axfr: Vec<String> = json_strs(&v["axfr_acl"]);
                        let refresh = v["refresh_hours"].as_u64().unwrap_or(24);
                        add_zone("slave", name, &primaries, &axfr, refresh)
                            .map_err(|e| e.to_string())?;
                        reconcile_current(&live).await?;
                        Ok(json!({"ok": true}))
                    }
                }
            }
            // RPZ override（需求 7）
            p if p.ends_with("/api/dns/override") => {
                let action = v["action"].as_str().unwrap_or("add");
                if action == "del" {
                    let name = v["name"].as_str().ok_or("name?")?;
                    dc.rpz.retain(|r| r.name != name);
                } else {
                    dc.rpz.push(RpzRule {
                        name: v["name"].as_str().ok_or("name?")?.to_string(),
                        rtype: v["rtype"].as_str().unwrap_or("nxdomain").to_string(),
                        value: v["value"].as_str().unwrap_or("").to_string(),
                    });
                }
                persist_and_reconcile(&dc).await?;
                Ok(json!({"ok": true, "rpz": dc.rpz}))
            }
            // 分线路（需求 10）
            //
            // 面板只提交 {enabled, lines}，若整体替换 `dc.geo`，`#[serde(default)]`
            // 会把管理员在 config.toml 里写的 mmdb（city/asn 库路径、license_key、
            // asn_to_line/country_to_line/isp_contains 映射）全部抹成空值——
            // 一次「保存并应用」就静默丢掉分线路数据库配置。改为按字段合并。
            p if p.ends_with("/api/dns/geo") => {
                if let Some(enabled) = v["geo"]["enabled"].as_bool() {
                    dc.geo.enabled = enabled;
                }
                if v["geo"]["lines"].is_array() {
                    dc.geo.lines = serde_json::from_value(v["geo"]["lines"].clone())
                        .map_err(|e| format!("geo.lines: {e}"))?;
                }
                // 高级字段仅在显式提交时才覆盖，缺省保留原值。
                if v["geo"].get("mmdb").map(|x| x.is_object()).unwrap_or(false) {
                    dc.geo.mmdb = serde_json::from_value(v["geo"]["mmdb"].clone())
                        .map_err(|e| format!("geo.mmdb: {e}"))?;
                }
                persist_and_reconcile(&dc).await?;
                Ok(json!({"ok": true, "lines": dc.geo.lines.len()}))
            }
            // DoT/DoH（需求 9）
            p if p.ends_with("/api/dns/dot_doh") => {
                if v["dot"].is_object() {
                    dc.dot =
                        serde_json::from_value(v["dot"].clone()).map_err(|e| format!("dot: {e}"))?;
                }
                if v["doh"].is_object() {
                    dc.doh =
                        serde_json::from_value(v["doh"].clone()).map_err(|e| format!("doh: {e}"))?;
                }
                persist_and_reconcile(&dc).await?;
                Ok(json!({"ok": true}))
            }
            // root zone（需求 2）：立即刷新 / 设置频率
            p if p.ends_with("/api/dns/rootzone") => {
                let action = v["action"].as_str().unwrap_or("refresh");
                match action {
                    "set" => {
                        dc.rootzone.refresh_hours = v["refresh_hours"].as_u64().unwrap_or(24);
                        persist_and_reconcile(&dc).await?;
                        Ok(json!({"ok": true}))
                    }
                    _ => {
                        let d2 = dc.clone();
                        let path = tokio::task::spawn_blocking(move || rootzone_refresh(&d2))
                            .await
                            .map_err(|e| e.to_string())?
                            .map_err(|e| e.to_string())?;
                        Ok(json!({"ok": true, "path": path}))
                    }
                }
            }
            p if p.ends_with("/api/dns/acme/issue") => {
                let c = dc.acme.clone();
                let r = tokio::task::spawn_blocking(move || {
                    // 复用 issue_if_missing（有证书且未到期则 no-op）
                    acme::cert_valid(&acme::cert_path(&c.domain));
                    c
                })
                .await
                .map_err(|e| e.to_string())?;
                let _ = r;
                // 真正的签发是阻塞外部工具调用，走 blocking
                let c2 = dc.acme.clone();
                let issued = tokio::task::spawn_blocking(move || acme_issue(&c2))
                    .await
                    .map_err(|e| e.to_string())?;
                issued.map(|_| json!({"ok": true}))
            }
            p if p.ends_with("/api/dns/test-split") => {
                // 面板调试：给定客户端 IP 返回命中的分线路（需求 10 验证入口）
                let body_q = query_str.clone();
                let mut ip = String::new();
                for kv in body_q.split('&') {
                    if let Some(v) = kv.strip_prefix("ip=") {
                        ip = v.to_string();
                    }
                }
                let addr: std::net::IpAddr = ip
                    .parse()
                    .map_err(|_| format!("bad ip {ip:?}"))?;
                let fwd = super::resolve_fwd_dest(&dc, Some(addr));
                let mut hit = "default".to_string();
                if dc.geo.enabled {
                    hit = super::geoip::line_for(&dc.geo.mmdb, addr)
                        .unwrap_or_else(|| {
                            dc.geo.lines.iter()
                                .find(|l| l.cidrs.iter().any(|c| super::cidr_contains(c, addr)))
                                .map(|l| l.name.clone())
                                .unwrap_or_else(|| "default".into())
                        });
                }
                Ok(json!({"ip": ip, "line": hit, "fwd_dest": fwd.to_string()}))
            }
            // GeoIP 管理（需求 9）：手动 sync / status / 查表
            p if p.ends_with("/api/dns/geoip/sync") => {
                let force = v["force"].as_bool().unwrap_or(false);
                let mmdb = dc.geo.mmdb.clone();
                let mut run_sync = true;
                if !force {
                    let stamp = super::state_root().join("geo").join("last_sync.txt");
                    let age_days = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs() / 86_400)
                        .unwrap_or(0)
                        .saturating_sub(
                            std::fs::read_to_string(&stamp).ok()
                                .and_then(|s| s.trim().parse::<u64>().ok())
                                .unwrap_or(0),
                        );
                    if age_days < mmdb.sync_days { run_sync = false; }
                }
                // 空操作的原因（空串 = 本次真的会同步）。所有跳过路径都必须在这里说清楚，
                // 否则响应会把「什么都没干」说成 synced。
                let skip_reason = if !mmdb.is_active() {
                    "mmdb 未启用（未配置 db 路径）"
                } else if mmdb.license_key.is_empty() {
                    "未配置 MaxMind license_key"
                } else if !run_sync {
                    "未到同步周期（可加 force=1 强制）"
                } else {
                    ""
                };
                let do_sync = skip_reason.is_empty();
                let r = if do_sync {
                    tokio::task::spawn_blocking(move || super::geoip::ensure_synced(&mmdb, force))
                        .await
                        .map_err(|e| e.to_string())?
                } else {
                    Ok(())
                };
                match r {
                    Ok(_) => {
                        // 清缓存 reader 让下次 lookup 读新 db
                        super::geoip::reset_cache();
                        // `synced` 只回答「这次真的同步了吗」。此前直接回 run_sync（= 是否
                        // 到期/被强制），没密钥或未启用时明明是空操作，接口却回 true ——
                        // 与 07988d6 修掉的「面板说刚同步、数据却在老化」是同一类假报告。
                        Ok(json!({"ok": true, "synced": do_sync, "reason": skip_reason}))
                    }
                    Err(e) => Ok(json!({"ok": false, "error": e.to_string()})),
                }
            }
            p if p.ends_with("/api/dns/geoip/status") => {
                Ok(super::geoip::status())
            }
            p if p.ends_with("/api/dns/geoip/lines") => {
                let lines: Vec<serde_json::Value> = dc.geo.lines.iter().map(|l| json!({
                    "name": l.name, "cidrs": l.cidrs, "rule_count": l.cidrs.len()
                })).collect();
                let mmdb_info = json!({
                    "enabled": dc.geo.mmdb.is_active(),
                    "city_db": dc.geo.mmdb.city_db(),
                    "asn_db": dc.geo.mmdb.asn_db(),
                    "sync_days": dc.geo.mmdb.sync_days,
                    "has_license": !dc.geo.mmdb.license_key.is_empty(),
                    "country_map": dc.geo.mmdb.country_to_line.len(),
                    "asn_map": dc.geo.mmdb.asn_to_line.len(),
                    "isp_map": dc.geo.mmdb.isp_contains.len(),
                    "reader": super::geoip::status(),
                });
                Ok(json!({ "lines": lines, "mmdb": mmdb_info }))
            }
            p if p.ends_with("/api/dns/reload") => {
                reconcile_current(&live).await?;
                Ok(json!({"ok": true}))
            }
            // JSP 编译按钮（§7.5/§8）：sidecar jar precompile 优先，输出原样回显
            p if p.ends_with("/api/apps/jsp/compile") => {
                let docroot = v["docroot"].as_str().unwrap_or("www-apps/jsp").to_string();
                // Fail-closed: reject shell metacharacters / traversal (was `sh -c` injection).
                if docroot.is_empty()
                    || docroot.contains('\0')
                    || docroot.contains("..")
                    || !docroot.chars().all(|c| {
                        c.is_ascii_alphanumeric()
                            || matches!(c, '/' | '\\' | '.' | '-' | '_' | ' ')
                    })
                {
                    return Err("bad docroot".into());
                }
                let java = [
                    "/usr/local/jdk-17/bin/java",
                    "/usr/local/bin/java",
                    "java",
                ]
                .into_iter()
                .find(|cand| *cand == "java" || std::path::Path::new(cand).is_file())
                .unwrap_or("java");
                let jar = "libs/jsp-sidecar/target/jsp-sidecar.jar";
                if !std::path::Path::new(jar).is_file() {
                    return Err(format!("jsp sidecar missing: {jar}"));
                }
                let out = tokio::process::Command::new(java)
                    .arg("-jar")
                    .arg(jar)
                    .arg("precompile")
                    .arg(&docroot)
                    .output()
                    .await
                    .map_err(|e| e.to_string())?;
                let mut output = String::from_utf8_lossy(&out.stdout).to_string();
                if !out.stderr.is_empty() {
                    output.push_str(&String::from_utf8_lossy(&out.stderr));
                }
                output.push_str(&format!("\nexit={}\n", out.status.code().unwrap_or(-1)));
                Ok(json!({
                    "ok": out.status.success(),
                    "output": output
                }))
            }
            _ => Err("not found".into()),
        }
    } else {
        Err("method not allowed".into())
    };

    let v = result?;
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(full(v.to_string()))
        .unwrap())
}

fn json_strs(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default()
}

async fn persist_and_reconcile(dc: &DnsConfig) -> Result<(), String> {
    let etc = state_root().join("etc");
    std::fs::create_dir_all(&etc).map_err(|e| e.to_string())?;
    let text = toml::to_string_pretty(dc).map_err(|e| e.to_string())?;
    std::fs::write(etc.join("panel.toml"), text).map_err(|e| e.to_string())?;
    let d2 = dc.clone();
    tokio::task::spawn_blocking(move || reconcile(&d2))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())
}

/// 面板改动后的 reconcile。
/// 修正（v2）：以 live snapshot 的 effective() 为底（panel.toml 若存在则覆盖）——
/// 旧实现用 Config::default()，导致从未保存过 panel.toml 的部署里
/// zones/records 改动 reconcile 时读到 disabled 而静默 no-op（假生效）。
async fn reconcile_current(
    live: &std::sync::Arc<crate::server::live_config::LiveConfig>,
) -> Result<(), String> {
    let dc = effective(&live.snapshot());
    let d2 = dc;
    tokio::task::spawn_blocking(move || reconcile(&d2))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())
}

fn status_json(dc: &DnsConfig) -> Result<Value, String> {
    let zones = list_zones().map_err(|e| e.to_string())?;
    let conn = store().map_err(|e| e.to_string())?;
    let records: i64 = conn
        .query_row("SELECT COUNT(*) FROM records", [], |r| r.get(0))
        .map_err(|e| e.to_string())?;
    let named = named_alive(dc);
    Ok(json!({
        "enabled": dc.enabled,
        "test_mode": dc.test_mode,
        "modes": dc.modes,
        "port": dc.port_or_default(),
        "rndc_port": dc.rndc_port_or_default(),
        "named_running": named,
        "zones": zones,
        "records": records,
        "dnssec": dc.dnssec,
        "dnssec_keys": dnssec_key_list(),
        "rpz_rules": dc.rpz.len(),
        "rpz": dc.rpz,
        "geo_lines": dc.geo.lines.len(),
        "geo": dc.geo,
        "dot": dc.dot,
        "doh": dc.doh,
        "doh_hostnames": dc.doh.hostnames,
        "rootzone": dc.rootzone,
        "axfr_out_acl": dc.axfr_out_acl,
        "recursion_acl": dc.recursion_acl,
        "ecs": dc.ecs,
        "acme": dc.acme,
        "rootzone_last_ok": meta_get("root_last_ok").ok().flatten(),
    }))
}


/// 手动触发签发（admin POST /api/dns/acme/issue）。
fn acme_issue(c: &crate::server::dns::acme::AcmeCfg) -> Result<(), String> {
    use std::process::Command;
    // 与 acme::startup 相同的探测逻辑；这里同步执行并把错误回传面板
    let domain = crate::server::dns::acme::safe_domain_segment(&c.domain)
        .ok_or_else(|| format!("unsafe domain {:?}", c.domain))?
        .to_string();
    let webroot = c
        .webroot
        .clone()
        .unwrap_or_else(|| crate::server::dns::acme::acme_root().join("www").display().to_string());
    let out_dir = crate::server::dns::acme::acme_root().join(&domain);
    std::fs::create_dir_all(&out_dir).map_err(|e| e.to_string())?;
    for bin in ["/usr/local/bin/acme.sh"] {
        if std::path::Path::new(bin).is_file() {
            let st = Command::new(bin)
                .arg("--issue")
                .arg("-d").arg(&domain)
                .arg("--webroot").arg(&webroot)
                .arg("-m").arg(&c.email)
                .arg("--force")
                .status();
            if st.map(|x| x.success()).unwrap_or(false) {
                return Ok(());
            }
        }
    }
    Err("no acme client (acme.sh/acme-client/certbot) — 请手动放置证书或安装工具".into())
}

/// `GET /api/dns/zones/export?name=<zone>` —— 按 RFC1035 导出单个分区（.zone 下载）。
///
/// 直接复用 `gen_zone_file`（与写入 named 用的 zone 文件同一套生成逻辑），
/// 保证「导出的文本」和「服务实际加载的」一致，不会出现两套格式。
pub async fn handle_zone_export(
    req: &http::Request<http_body_util::Full<bytes::Bytes>>,
) -> Response<BoxBody> {
    let q = req.uri().query().unwrap_or("");
    let zone = q
        .split('&')
        .find_map(|kv| kv.strip_prefix("name="))
        .map(|v| {
            percent_encoding::percent_decode_str(v)
                .decode_utf8_lossy()
                .into_owned()
        })
        .unwrap_or_default()
        .trim()
        .to_string();
    let bad = |st: StatusCode, msg: String| -> Response<BoxBody> {
        Response::builder()
            .status(st)
            .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(full(msg))
            .unwrap()
    };
    if zone.is_empty() {
        return bad(StatusCode::BAD_REQUEST, "name= 必填".into());
    }
    let zones = match list_zones() {
        Ok(z) => z,
        Err(e) => return bad(StatusCode::INTERNAL_SERVER_ERROR, format!("zones: {e}")),
    };
    let Some(z) = zones.into_iter().find(|z| z.name == zone) else {
        return bad(StatusCode::NOT_FOUND, format!("zone {zone} 不存在"));
    };
    let recs = match list_records(&zone) {
        Ok(r) => r,
        Err(e) => return bad(StatusCode::INTERNAL_SERVER_ERROR, format!("records: {e}")),
    };
    let text = gen_zone_file(&zone, &z.kind, &recs);
    let fname = zone
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' { c } else { '_' })
        .collect::<String>();
    Response::builder()
        .status(StatusCode::OK)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(
            http::header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{fname}.zone\""),
        )
        .body(full(text))
        .unwrap()
}

// ---------------------------------------------------------------- .zone 导入

/// 解析 RFC1035 主文件的务实子集，供面板导入 .zone 使用。
///
/// 支持：`;` 注释（引号内的 `;` 不算）、空行、括号续行、`$ORIGIN` / `$TTL`、
/// 引号包裹的 rdata、省略 owner（沿用上一条）、可选 TTL 与 class、`1h/30m/2d` 式 TTL。
/// **不支持** `$INCLUDE` / `$GENERATE` —— 遇到直接报错，不猜语义。
///
/// 先全量解析、再落库：任何一行不合法就整体失败并报出行号，不会写进半截数据。
/// zone 文件解析出的单条记录（导入口与「读从区落盘文件」共用）。
pub(super) struct ZoneRec {
    pub(super) name: String,
    pub(super) rtype: String,
    pub(super) ttl: u32,
    pub(super) rdata: String,
}

fn strip_zone_comment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut inq = false;
    for ch in s.chars() {
        match ch {
            '"' => {
                inq = !inq;
                out.push(ch);
            }
            ';' if !inq => break,
            _ => out.push(ch),
        }
    }
    out
}

/// DNS 惯例的 TTL 写法：纯数字或 1s/30m/2h/3d/1w。
fn parse_ttl(tok: &str) -> Option<u32> {
    let t = tok.trim();
    if t.is_empty() {
        return None;
    }
    let (num, mult) = match t.chars().last()?.to_ascii_lowercase() {
        's' => (&t[..t.len() - 1], 1u32),
        'm' => (&t[..t.len() - 1], 60),
        'h' => (&t[..t.len() - 1], 3600),
        'd' => (&t[..t.len() - 1], 86400),
        'w' => (&t[..t.len() - 1], 604800),
        _ => (t, 1),
    };
    if num.is_empty() {
        return None;
    }
    num.parse::<u32>().ok().map(|v| v.saturating_mul(mult))
}

/// 按空白切词，但引号内的空白算作同一个词；返回字节区间，便于原样取回 rdata。
fn zone_tokens(s: &str) -> Vec<(usize, usize)> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < b.len() {
        while i < b.len() && (b[i] as char).is_whitespace() {
            i += 1;
        }
        if i >= b.len() {
            break;
        }
        let start = i;
        let mut inq = false;
        while i < b.len() {
            let c = b[i] as char;
            if c == '"' {
                inq = !inq;
                i += 1;
                continue;
            }
            if !inq && c.is_whitespace() {
                break;
            }
            i += 1;
        }
        out.push((start, i));
    }
    out
}

/// 解析 RFC1035 master 文件文本（导入口与「读从区落盘文件」共用）。
pub(super) fn parse_zone_text(text: &str, origin: &str) -> Result<Vec<ZoneRec>, String> {
    let mut cur_origin = origin.trim_end_matches('.').to_ascii_lowercase();
    let mut default_ttl: u32 = 3600;
    let mut last_owner: Option<String> = None;
    let mut out: Vec<ZoneRec> = Vec::new();

    let mut buf = String::new();
    let mut depth: i32 = 0;
    let mut start_line = 0usize;

    for (idx, raw) in text.lines().enumerate() {
        let lineno = idx + 1;
        let clean = strip_zone_comment(raw);
        if clean.trim().is_empty() && depth == 0 {
            continue;
        }
        if buf.is_empty() {
            start_line = lineno;
        }
        // 行首有空白 = 沿用上一条 owner（RFC1035 的省略写法）
        let omits_owner = buf.is_empty() && raw.starts_with([' ', '\t']);
        for ch in clean.chars() {
            if ch == '(' {
                depth += 1;
            } else if ch == ')' {
                depth -= 1;
            }
        }
        if depth < 0 {
            return Err(format!("第 {lineno} 行: 多余的 )"));
        }
        buf.push_str(clean.trim());
        buf.push(' ');
        if depth > 0 {
            continue;
        }
        let logical = std::mem::take(&mut buf);
        let toks = zone_tokens(&logical);
        if toks.is_empty() {
            continue;
        }
        let first = &logical[toks[0].0..toks[0].1];
        if first.starts_with('$') {
            match first.to_ascii_uppercase().as_str() {
                "$ORIGIN" => {
                    if toks.len() < 2 {
                        return Err(format!("第 {start_line} 行: $ORIGIN 缺少参数"));
                    }
                    cur_origin = logical[toks[1].0..toks[1].1]
                        .trim_end_matches('.')
                        .to_ascii_lowercase();
                }
                "$TTL" => {
                    if toks.len() < 2 {
                        return Err(format!("第 {start_line} 行: $TTL 缺少参数"));
                    }
                    let t = &logical[toks[1].0..toks[1].1];
                    default_ttl = parse_ttl(t)
                        .ok_or_else(|| format!("第 {start_line} 行: 无法解析 TTL {t:?}"))?;
                }
                other => {
                    return Err(format!(
                        "第 {start_line} 行: 不支持指令 {other}（导入只处理记录与 $ORIGIN/$TTL）"
                    ))
                }
            }
            continue;
        }

        let mut ti = 0usize;
        let owner_raw = if omits_owner {
            last_owner.clone().unwrap_or_else(|| "@".to_string())
        } else {
            ti = 1;
            first.to_string()
        };
        // 可选 TTL / class（顺序任意，各最多一次）
        let mut ttl: Option<u32> = None;
        let mut class_seen = false;
        while ti < toks.len() {
            let t = &logical[toks[ti].0..toks[ti].1];
            let up = t.to_ascii_uppercase();
            if !class_seen && (up == "IN" || up == "CH" || up == "HS") {
                class_seen = true;
                ti += 1;
                continue;
            }
            if ttl.is_none() {
                if let Some(v) = parse_ttl(t) {
                    ttl = Some(v);
                    ti += 1;
                    continue;
                }
            }
            break;
        }
        if ti >= toks.len() {
            return Err(format!("第 {start_line} 行: 缺少记录类型"));
        }
        let rtype = logical[toks[ti].0..toks[ti].1].to_ascii_uppercase();
        let type_end = toks[ti].1;
        if !RR_TYPES.contains(&rtype.as_str()) {
            return Err(format!("第 {start_line} 行: 不支持的记录类型 {rtype}"));
        }
        // rdata 原样取回（保留引号，TXT 引号内的空格不会被切碎）
        let rdata = logical[type_end..].trim().to_string();
        if rdata.is_empty() {
            return Err(format!("第 {start_line} 行: {rtype} 缺少记录值"));
        }

        // owner 归一成「分区内相对名」：@ 与顶点 -> "@"；绝对名去掉 zone 后缀
        let mut name = owner_raw.trim().trim_end_matches('.').to_ascii_lowercase();
        if name == "@" || name == cur_origin {
            name = "@".to_string();
        } else if name.len() > cur_origin.len()
            && name.ends_with(cur_origin.as_str())
            && name.as_bytes()[name.len() - cur_origin.len() - 1] == b'.'
        {
            name = name[..name.len() - cur_origin.len() - 1].to_string();
        } else if owner_raw.trim().ends_with('.') {
            // 绝对名却不在本分区内 —— 拒绝，否则会把外部名字塞进本区
            return Err(format!(
                "第 {start_line} 行: {owner_raw} 不在本分区 {cur_origin} 内"
            ));
        }
        if name.is_empty() {
            name = "@".to_string();
        }
        if !valid_name(&name) {
            return Err(format!("第 {start_line} 行: 记录名 {name:?} 不合法"));
        }
        last_owner = Some(name.clone());
        out.push(ZoneRec {
            name,
            rtype,
            ttl: ttl.unwrap_or(default_ttl),
            rdata,
        });
    }
    if depth != 0 {
        return Err(format!("第 {start_line} 行: 括号未闭合"));
    }
    if out.is_empty() {
        return Err("没有解析到任何记录".to_string());
    }
    Ok(out)
}
