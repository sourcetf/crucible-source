//! GeoIP 分线路匹配 —— MaxMind GeoLite2-City + GeoLite2-ASN
//!
//! 使用 `maxminddb` crate，通过其 `maxminddb::geoip2` 子模块提供 `City`/`Asn` 模型。
//! ASN 数据库 `autonomous_system_number` (u32), `autonomous_system_organization` (string)
//! country 数据库 `country.iso_code` (string)。
//!
//! 安全约束（Mimosa 注入）：下载 host 必须是 `download.maxmind.com`，下载完成后做 tar 路径白名单。

use std::io::{Cursor, Read};
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use flate2::read::GzDecoder;
use maxminddb::Reader;
use maxminddb::geoip2 as mmdb_geo;
use mmdb_geo::{Asn, City};
use serde::{Deserialize, Serialize};
use tar::Archive;

use super::GeoMmdbCfg;

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct GeoInfo {
    pub country_iso: Option<String>,
    pub asn: Option<String>,
    pub as_org: Option<String>,
    pub isp_contains: Option<String>,
}

// Reader 不能 Clone（内部带 mmap），用 Arc 共享；同进程内 only ever holds 1 city + 1 asn
type MmdbReader = Reader<Vec<u8>>;
type ArcReader = Arc<MmdbReader>;

static CITY_DB: std::sync::Mutex<Option<(String, Option<ArcReader>)>> =
    std::sync::Mutex::new(None);
static ASN_DB: std::sync::Mutex<Option<(String, Option<ArcReader>)>> = std::sync::Mutex::new(None);

/// clear cached reader (after a fresh sync)
pub fn reset_cache() {
    *CITY_DB.lock().unwrap() = None;
    *ASN_DB.lock().unwrap() = None;
}

fn open_db(path: &str) -> Option<ArcReader> {
    if !Path::new(path).exists() {
        return None;
    }
    match Reader::open_readfile(path) {
        Ok(db) => {
            log::info!("geoip: opened mmdb {path}");
            Some(Arc::new(db))
        }
        Err(e) => {
            log::warn!("geoip: cannot open {path}: {e}");
            None
        }
    }
}

fn city_db(cfg: &GeoMmdbCfg) -> Option<ArcReader> {
    let mut slot = CITY_DB.lock().unwrap();
    let path = cfg.city_db();
    let need = match slot.as_ref() {
        None => true,
        Some((p, _)) => p != &path,
    };
    if need {
        let db = open_db(&path);
        *slot = Some((path, db));
    }
    slot.as_ref().and_then(|(_, db)| db.clone())
}

fn asn_db(cfg: &GeoMmdbCfg) -> Option<ArcReader> {
    let mut slot = ASN_DB.lock().unwrap();
    let path = cfg.asn_db();
    let need = match slot.as_ref() {
        None => true,
        Some((p, _)) => p != &path,
    };
    if need {
        let db = open_db(&path);
        *slot = Some((path, db));
    }
    slot.as_ref().and_then(|(_, db): &(_, _)| db.clone())
}

fn lookup_city(cfg: &GeoMmdbCfg, ip: IpAddr) -> Option<GeoInfo> {
    let db = city_db(cfg)?;
    let v: City = db.lookup(ip).ok()?;
    let mut info = GeoInfo::default();
    if let Some(c) = &v.country {
        if let Some(iso) = &c.iso_code {
            info.country_iso = Some(iso.to_string());
        }
    }
    // City DB 的 traits (enterprise level) 含 AS 信息；GeoLite2 标准城市库不带 AS 字段，
    // 所以 city 仅作归属地判断。AS/ISP 从单独 ASN 库查。
    Some(info)
}

fn lookup_asn(cfg: &GeoMmdbCfg, ip: IpAddr) -> Option<GeoInfo> {
    let db = asn_db(cfg)?;
    let v: Asn = db.lookup(ip).ok()?;
    let mut info = GeoInfo::default();
    if let Some(n) = v.autonomous_system_number {
        info.asn = Some(format!("AS{n}"));
    }
    if let Some(org) = &v.autonomous_system_organization {
        info.as_org = Some(org.to_string());
        info.isp_contains = Some(org.to_string());
    }
    Some(info)
}

/// 根据 cfg + 客户端 IP 返回匹配线路名 (None = default)
pub fn line_for(cfg: &GeoMmdbCfg, ip: IpAddr) -> Option<String> {
    let info = lookup_city(cfg, ip).or_else(|| lookup_asn(cfg, ip))?;
    // 优先 asn → isp_contains → country
    if let Some(asn) = &info.asn {
        let asn_num = asn.trim_start_matches("AS");
        for (k, v) in &cfg.asn_to_line {
            let kk = k.trim_start_matches("AS");
            if kk == asn_num {
                return Some(v.clone());
            }
        }
    }
    if let Some(isp) = &info.isp_contains {
        let lisp = isp.to_ascii_lowercase();
        for (k, v) in &cfg.isp_contains {
            if lisp.contains(&k.to_ascii_lowercase()) {
                return Some(v.clone());
            }
        }
    }
    if let Some(iso) = &info.country_iso {
        for (k, v) in &cfg.country_to_line {
            if k.eq_ignore_ascii_case(iso) {
                return Some(v.clone());
            }
        }
    }
    None
}

/// 下载 MaxMind GeoLite2-City + ASN tar.gz → 解 tar → 落盘
pub fn ensure_synced(cfg: &GeoMmdbCfg) -> Result<()> {
    if cfg.license_key.is_empty() {
        log::debug!("geoip: no license_key, skip sync");
        return Ok(());
    }
    let dir = super::state_root().join("geo");
    std::fs::create_dir_all(&dir).context("create geo dir")?;
    let target_city = dir.join("GeoLite2-City.mmdb");
    let target_asn = dir.join("GeoLite2-ASN.mmdb");
    let stamp = dir.join("last_sync.txt");
    if cfg.sync_days > 0 && stamp.exists() {
        let now_day = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() / 86_400)
            .unwrap_or(0);
        let last = std::fs::read_to_string(&stamp)
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(0);
        if now_day.saturating_sub(last) < cfg.sync_days {
            return Ok(());
        }
    }
    if !target_city.exists() {
        fetch_edition(&cfg.license_key, "GeoLite2-City", &target_city)?;
    }
    if !target_asn.exists() {
        fetch_edition(&cfg.license_key, "GeoLite2-ASN", &target_asn)?;
    }
    std::fs::write(&stamp, current_day_stamp()?.to_string())?;
    Ok(())
}

fn current_day_stamp() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() / 86_400)
        .unwrap_or(0))
}

/// Mimosa 注入约束：host 必须是 MaxMind 官方下载域；任何重定向也强制 re-validate。
fn fetch_edition(license: &str, edition: &str, dst: &Path) -> Result<()> {
    // license key 不能出现在日志里
    let url = format!(
        "https://download.maxmind.com/app/geoip_download?edition_id={edition}&suffix=tar.gz&license_key={license}"
    );
    log::info!("geoip: downloading edition={edition} → {}", dst.display());
    // 主动 host 白名单校验
    if let Err(e) = validate_outbound_host("download.maxmind.com") {
        bail!("geoip host rejected: {e}");
    }
    let resp = ureq::get(&url)
        .timeout(std::time::Duration::from_secs(120))
        .call()
        .context("maxmind http")?;
    if resp.get_url() != url {
        // 重定向到非白名单域 — 拒绝
        if let Some(host) = url_host(resp.get_url()) {
            validate_outbound_host(&host)
                .with_context(|| format!("redirect host {host} rejected"))?;
        }
    }
    let mut data = Vec::with_capacity(
        resp.header("Content-Length")
            .and_then(|s| s.parse().ok())
            .unwrap_or(2_000_000),
    );
    resp.into_reader().take(200_000_000).read_to_end(&mut data)?;
    let gz = GzDecoder::new(Cursor::new(data));
    let mut tar = Archive::new(gz);
    for e in tar.entries().context("tar entries")? {
        let mut e = e?;
        let p = e.path()?.to_path_buf();
        // tar path traversal 防护：只允许 `GeoLite2-XXX_<date>/XXX.mmdb`
        let p_str = p.to_string_lossy();
        if !p_str.starts_with(&format!("{edition}_")) {
            continue;
        }
        if p.extension().and_then(|x| x.to_str()) == Some("mmdb") {
            // 二次防御：归一化路径不能含 `..` 或绝对路径
            let safe = p
                .components()
                .all(|c| matches!(c, std::path::Component::Normal(_)));
            if !safe {
                bail!("geoip: tar path traversal detected: {p_str}");
            }
            let mut f = std::fs::File::create(dst)?;
            std::io::copy(&mut e, &mut f)?;
            log::info!("geoip: extracted {edition} → {}", dst.display());
            return Ok(());
        }
    }
    bail!("no mmdb inside {edition} tar")
}

fn url_host(u: &str) -> Option<String> {
    url::Url::parse(u).ok().and_then(|x| x.host_str().map(|s| s.to_string()))
}

/// Mimosa 注入：拒绝环回 / 私有 / 保留。
pub fn validate_outbound_host(host: &str) -> Result<()> {
    use std::net::IpAddr;
    let h = host.trim_start_matches('[').trim_end_matches(']');
    // 字面域名不做 IP 解析（避免 getaddrinfo 触发 DNS 泄漏），但若本来就是 IP 字面则校验
    if let Ok(ip) = h.parse::<IpAddr>() {
        if is_disallowed_ip(&ip) {
            bail!("outbound host {host} is disallowed");
        }
    }
    // 域名白名单：只允许 *.maxmind.com / 已知可信域（在这里就是 MaxMind）
    if !host.eq_ignore_ascii_case("download.maxmind.com")
        && !host.to_ascii_lowercase().ends_with(".maxmind.com")
    {
        bail!("outbound host {host} not in allowlist");
    }
    Ok(())
}

fn is_disallowed_ip(ip: &IpAddr) -> bool {
    use std::net::IpAddr::*;
    match ip {
        V4(v) => {
            v.is_loopback()
                || v.is_private()
                || v.is_link_local()
                || v.is_unspecified()
                || v.is_broadcast()
                || v.is_multicast()
                || v.is_documentation()
                || v.octets()[0] == 0 // 0.0.0.0/8
        }
        V6(v) => {
            v.is_loopback()
                || v.is_unspecified()
                || v.is_multicast()
                || v.is_unique_local()
                || v.is_unicast_link_local()
        }
    }
}

/// 对外：给 panel 看的状态
pub fn status() -> serde_json::Value {
    serde_json::json!({
        "city_loaded": CITY_DB.lock().unwrap().is_some(),
        "asn_loaded": ASN_DB.lock().unwrap().is_some(),
    })
}
