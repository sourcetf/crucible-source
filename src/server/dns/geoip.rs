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
    *lock_city() = None;
    *lock_asn() = None;
}

/// **容忍 poisoning** 的取锁：这两个缓存是「进程级的分线路数据库句柄」，任何一处持有
/// 守卫时 panic（例如 `open_db` 里的日志、mmap 失败路径）都会把 Mutex 永久标记为 poisoned
/// —— 此后所有 `.lock().unwrap()` 全部 panic，GeoIP 分线路功能**永久失效且无恢复**。
/// 缓存本身只是一个 `Option`，被 poisoning 保护的数据并不需要「拒绝访问」语义。
fn lock_city() -> std::sync::MutexGuard<'static, Option<(String, Option<ArcReader>)>> {
    CITY_DB.lock().unwrap_or_else(|e| e.into_inner())
}

fn lock_asn() -> std::sync::MutexGuard<'static, Option<(String, Option<ArcReader>)>> {
    ASN_DB.lock().unwrap_or_else(|e| e.into_inner())
}

/// 缓存键：路径 + 文件 mtime/大小。
///
/// **只看路径的缓存永不失效**：`ensure_synced` 用 `rename` 换掉 mmdb 文件后路径不变
/// （新 inode），槽里的 `Arc<Reader<Vec<u8>>>`（mmap 全量内存快照）仍指向旧数据 ——
/// 周期同步/面板同步每次都报成功，分线路却一直按旧库匹配；文件一时打不开时缓存的
/// `(path, None)` 也会永久粘住，恢复后不再重试。带 mtime+len 后，文件被替换（或从
/// 缺失恢复）在下一次查询就会重载，无需任何调用方配合。
fn db_fingerprint(path: &str) -> String {
    match std::fs::metadata(path) {
        Ok(md) => {
            let mtime = md
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            format!("{path}|{mtime}|{}", md.len())
        }
        Err(_) => format!("{path}|absent"),
    }
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
    let mut slot = lock_city();
    let path = cfg.city_db();
    let key = db_fingerprint(&path);
    let need = match slot.as_ref() {
        None => true,
        Some((k, _)) => k != &key,
    };
    if need {
        let db = open_db(&path);
        *slot = Some((key, db));
    }
    slot.as_ref().and_then(|(_, db)| db.clone())
}

fn asn_db(cfg: &GeoMmdbCfg) -> Option<ArcReader> {
    let mut slot = lock_asn();
    let path = cfg.asn_db();
    let key = db_fingerprint(&path);
    let need = match slot.as_ref() {
        None => true,
        Some((k, _)) => k != &key,
    };
    if need {
        let db = open_db(&path);
        *slot = Some((key, db));
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

/// ASN 归一：去空白、去 `AS` 前缀（**大小写不敏感**）。
///
/// 配置里写 `as13335` 必须命中库里的 `AS13335`/`13335`；原先
/// `trim_start_matches("AS")` 大小写敏感，小写键静默失效（规则不命中且无日志）。
fn normalize_asn(s: &str) -> String {
    let up = s.trim().to_ascii_uppercase();
    up.strip_prefix("AS").unwrap_or(&up).to_string()
}

/// 根据 cfg + 客户端 IP 返回匹配线路名 (None = default)
pub fn line_for(cfg: &GeoMmdbCfg, ip: IpAddr) -> Option<String> {
    // 必须**两个库都查**再做字段级合并。原先用 `or_else`：GeoLite2-City 覆盖了
    // 绝大多数可路由地址，于是 lookup_asn 几乎永远不会被调用，info.asn /
    // isp_contains 恒为空 —— cfg.asn_to_line / ISP 规则永不命中（分线路静默失效，
    // 只剩 country 兜底），且没有任何日志或错误提示。
    let info = match (lookup_city(cfg, ip), lookup_asn(cfg, ip)) {
        (Some(mut c), Some(a)) => {
            c.asn = c.asn.or(a.asn);
            c.as_org = c.as_org.or(a.as_org);
            c.isp_contains = c.isp_contains.or(a.isp_contains);
            c
        }
        (Some(c), None) => c,
        (None, Some(a)) => a,
        (None, None) => return None,
    };
    // 优先 asn → isp_contains → country
    if let Some(asn) = &info.asn {
        let asn_num = normalize_asn(asn);
        for (k, v) in &cfg.asn_to_line {
            if normalize_asn(k) == asn_num {
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
pub fn ensure_synced(cfg: &GeoMmdbCfg, force: bool) -> Result<()> {
    if cfg.license_key.is_empty() {
        log::debug!("geoip: no license_key, skip sync");
        return Ok(());
    }
    let dir = super::state_root().join("geo");
    std::fs::create_dir_all(&dir).context("create geo dir")?;
    // 下载目标 = 查询实际读取的路径（`cfg.city_db()`/`cfg.asn_db()`）。
    // 旧实现固定写 `state/geo/GeoLite2-*.mmdb`：运维配了 `db_path_city`/`db_path_asn`
    // 时，同步写 A、查询读 B —— 面板回 synced:true、时间戳刷新，实际使用的库永不更新
    // （自同步对这类部署完全失效）。
    let target_city = std::path::PathBuf::from(cfg.city_db());
    let target_asn = std::path::PathBuf::from(cfg.asn_db());
    let stamp = dir.join("last_sync.txt");
    if !force && cfg.sync_days > 0 && stamp.exists() {
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
    // **到这里就一定要真的下载**。
    //
    // 旧实现还有一层 `if !target.exists()` 的门槛：文件一旦存在就永不更新，而时间戳
    // 照样被刷新、接口照样回 `synced:true` —— 面板显示「刚同步过」，数据却一直老化。
    // 判断「该不该同步」是上面那段（以及调用方的 force）的职责，不该在这里再拦一次。
    fetch_edition(&cfg.license_key, "GeoLite2-City", &target_city)?;
    fetch_edition(&cfg.license_key, "GeoLite2-ASN", &target_asn)?;
    std::fs::write(&stamp, current_day_stamp()?.to_string())?;
    // 新库已落盘：立刻清 reader 缓存，本次同步在同进程的**下一次查询**就生效。
    // （db_fingerprint 的 mtime 键也会发现 rename 后的变化，这里是让面板
    // status/日志同步地反映「刚更新」，不依赖下一次 lookup 的时序。）
    reset_cache();
    Ok(())
}

fn current_day_stamp() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() / 86_400)
        .unwrap_or(0))
}

/// MaxMind 官方下载域白名单（含子域）。不在表里的 host 一律拒绝。
const MMDB_ALLOWED_HOSTS: &[&str] = &[
    "download.maxmind.com",
    "maxmind.com",
    "www.maxmind.com",
    "geolite.maxmind.com",
];

/// host 是否在白名单内（精确匹配或 `.` 后缀匹配；大小写不敏感）。
fn host_allowlisted(host: &str) -> bool {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    MMDB_ALLOWED_HOSTS
        .iter()
        .any(|a| h == *a || h.ends_with(&format!(".{a}")))
}

/// 受限 HTTPS GET：只访问白名单主机，且**每一跳重定向都重新校验**。
///
/// 为什么必须逐跳校验：`license_key` 在 URL 查询串里（MaxMind 的下载接口就是这样）。
/// 若允许自动跟随重定向，攻击者只要让上游回一个 302 到自己的域名（或一个开放重定向），
/// 就能把 license key 带走，甚至把本机当成 SSRF 跳板去打内网。
///
/// `timeout_secs` 同时约束连接与整体读取（ureq 的 `timeout` 覆盖两者），
/// 避免一个不响应的对端把同步任务永久挂住（本模块跑在周期任务里）。
fn http_get_allowlisted(url: &str, timeout_secs: u64) -> Result<ureq::Response> {
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(timeout_secs))
        // 自己处理重定向（默认会跟 5 跳），这样才能逐跳做白名单校验。
        .redirects(0)
        .build();
    let mut current = url.to_string();
    for _hop in 0..6 {
        let parsed = url::Url::parse(&current).with_context(|| format!("bad url {current}"))?;
        let host = parsed.host_str().unwrap_or("").to_string();
        if !host_allowlisted(&host) {
            bail!("geoip: refusing non-allowlisted host {host:?}（只允许 MaxMind 官方下载域）");
        }
        match agent.get(&current).call() {
            Ok(resp) => return Ok(resp),
            Err(ureq::Error::Status(code, resp)) if (300..400).contains(&code) => {
                let loc = resp
                    .header("Location")
                    .context("geoip: redirect without Location")?
                    .to_string();
                // 相对 Location 也要能跟（用 URL join），跟完下一轮再校验 host。
                current = parsed
                    .join(&loc)
                    .with_context(|| format!("geoip: bad redirect Location {loc:?}"))?
                    .to_string();
                continue;
            }
            Err(ureq::Error::Status(code, _)) => bail!("geoip: HTTP {code} for {current}"),
            Err(e) => return Err(anyhow::Error::new(e).context(format!("geoip: GET {current}"))),
        }
    }
    bail!("geoip: too many redirects (>{})", 5)
}

/// Mimosa 注入约束：host 必须是 MaxMind 官方下载域；**每一跳**重定向都先校验再访问。
fn fetch_edition(license: &str, edition: &str, dst: &Path) -> Result<()> {
    // license key 不能出现在日志里
    let url = format!(
        "https://download.maxmind.com/app/geoip_download?edition_id={edition}&suffix=tar.gz&license_key={license}"
    );
    log::info!("geoip: downloading edition={edition} → {}", dst.display());
    // 自同步目标已改为查询路径（可被配置成别的目录），先保证父目录存在。
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("mkdir {}", parent.display()))?;
    }
    let resp = http_get_allowlisted(&url, 5).with_context(|| format!("maxmind {edition}"))?;
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
            // 先写临时文件、成功后再原子改名。
            //
            // 本函数现在**会在文件已存在时覆盖它**（ensure_synced 去掉了「文件存在就
            // 跳过」的旧门槛），所以不能再直接写 dst —— 下载或解包中途失败会把还能用的
            // 旧库毁掉，而它是地理分流与 GeoIP 查询的唯一数据源。
            let mut tmp = dst.as_os_str().to_os_string();
            tmp.push(".tmp");
            let tmp_path = std::path::PathBuf::from(tmp);
            let mut f = std::fs::File::create(&tmp_path)?;
            if let Err(e) = std::io::copy(&mut e, &mut f) {
                drop(f);
                let _ = std::fs::remove_file(&tmp_path);
                return Err(e).context("geoip: write temp mmdb");
            }
            drop(f);
            std::fs::rename(&tmp_path, dst)?;
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

/// 对外：给 panel 看的状态。
///
/// 判定「已加载」必须看**reader 本身**，不能看缓存槽是否存在：槽里记的是路径，
/// 文件不存在/打不开时槽内是 `(path, None)` —— `is_some()` 会把它报成已加载，
/// 面板于是显示一个根本没打开的库（与「synced:true 但什么都没同步」同类假报告）。
pub fn status() -> serde_json::Value {
    fn loaded(slot: &std::sync::Mutex<Option<(String, Option<ArcReader>)>>) -> bool {
        // 与 lock_city/lock_asn 一样**容忍 poisoning**：本函数是面板请求路径
        // （`GET /api/dns/geoip/status` / `/lines`）。此前这两个缓存里任一处
        // 在持锁时 panic（open_db 的日志/mmap 失败路径），Mutex 永久 poisoned，
        // 面板的每一个 GeoIP 请求就在这里 `.unwrap()` panic —— 缓存本身只是
        // 一个 `Option`，被 poisoning 保护的数据并不需要「拒绝访问」语义。
        slot.lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|(_, db)| db.is_some())
            .unwrap_or(false)
    }
    serde_json::json!({
        "city_loaded": loaded(&CITY_DB),
        "asn_loaded": loaded(&ASN_DB),
    })
}


#[cfg(test)]
mod allowlist_tests {
    use super::host_allowlisted;

    #[test]
    fn only_maxmind_hosts_pass() {
        assert!(host_allowlisted("download.maxmind.com"));
        assert!(host_allowlisted("Download.MaxMind.com"));
        assert!(host_allowlisted("maxmind.com"));
        assert!(host_allowlisted("a.maxmind.com"));
        assert!(!host_allowlisted("evil.com"));
        assert!(!host_allowlisted("maxmind.com.evil.com"));
        assert!(!host_allowlisted("notmaxmind.com"));
        assert!(!host_allowlisted(""));
    }
}
