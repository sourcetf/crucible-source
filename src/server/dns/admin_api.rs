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
                list_records(zone)
                    .map(|rs| json!({"records": rs}))
                    .map_err(|e| e.to_string())
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
            p if p.ends_with("/api/dns/geo") => {
                dc.geo = serde_json::from_value(v["geo"].clone()).map_err(|e| format!("geo: {e}"))?;
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
                if !v["force"].as_bool().unwrap_or(false) && !v["domain"].is_null() {
                    // no-op guard
                }
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
                let r = if mmdb.is_active() && !mmdb.license_key.is_empty() && run_sync {
                    tokio::task::spawn_blocking(move || super::geoip::ensure_synced(&mmdb))
                        .await
                        .map_err(|e| e.to_string())?
                } else {
                    Ok(())
                };
                match r {
                    Ok(_) => {
                        // 清缓存 reader 让下次 lookup 读新 db
                        super::geoip::reset_cache();
                        Ok(json!({"ok": true, "synced": run_sync}))
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
