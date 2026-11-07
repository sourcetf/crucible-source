//! GeoIP panel maintenance operations (import, purge, rebuild, hand edits).

use crate::server::geoip_panel::covering::MergedFields;
use anyhow::{Context, Result};
use rusqlite::Connection;
use std::path::Path;

// G-19：`rebuild_covering` / `rebuild_covering_conn` 全树无调用者（索引由
// `db::open` 的迁移 DDL 与离线 `geoip_common.init_schema` 维护），已删除。

/// 面板可编辑字段白名单（与 [`apply_field`] 一一对应）。落库前校验：
/// 旧实现字段拼错照样入库、接口回 ok，但 `apply_field` 的 `_ => {}` 让它永远不生效。
const EDIT_FIELDS: &[&str] = &[
    "country",
    "province",
    "region",
    "city",
    "district",
    "isp",
    "asn",
    "as_org",
    "cloud_provider",
    "cloud_region",
    "cloud_service",
    "hosting",
    "division_code",
    "dc",
];

/// 面板手工覆盖对融合结果有**最高优先级**（§23.5.7「手改（errata）：高优先级，防被
/// 自动更新覆盖」）。命中判定用**真正的网络包含**（`iputil::ip_in_cidr`），不是字符串
/// 前后缀 LIKE。
///
/// 旧实现把绝大多数人工勘误静默废掉，两处根因：
/// 1. `w >= merged.weight`：`merged.weight` 是所有覆盖行源权重的 max（生产层
///    300–990），而面板默认 200、冲突裁决流程 250 ⇒ 条件恒假，管理员写入的覆盖、
///    接口回 `{"ok":true}`、lookup 却继续返回多源融合结果；
/// 2. `?1 LIKE prefix || '%' OR prefix LIKE ?1 || '%'`：`10.0.0.0/8` 的段级编辑命中
///    不了 `10.1.2.0/24` 的查询（漏），存 `1.2.3.4` 又会命中 `1.2.3.40/32`（误）。
///
/// 现在：命中即应用（空值不覆盖非空，见 [`apply_field`]）；同一字段多条命中时按
/// weight、id 升序应用，**最后写入的**（权重最高、其次最晚录入）生效。
pub fn apply_panel_edits(panel: &Connection, ip: &str, merged: &mut MergedFields) -> Result<()> {
    // 没有任何源数据命中时不做「勘误」：覆盖的语义是修正融合结果，不是凭空造数据。
    if merged.prefixes_merged == 0 {
        return Ok(());
    }
    let Some(ip) = crate::server::geoip_panel::iputil::parse_ip(ip) else {
        return Ok(());
    };
    let mut stmt = panel.prepare(
        "SELECT field, value, weight, prefix FROM panel_edits
         -- 升序：同一字段多条命中时最后应用的那条生效（配合无条件写入 = 高权重胜出）。
         -- 附带 id 使同权重时结果确定，不依赖行扫描顺序。
         ORDER BY weight ASC, id ASC",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, String>(3)?,
        ))
    })?;
    for row in rows {
        let (field, value, _weight, prefix) = row?;
        if edit_prefix_hits_ip(&prefix, ip) {
            apply_field(merged, &field, &value);
        }
    }
    Ok(())
}

/// 该条编辑是否命中查询 IP：CIDR / 单个 IP（`iputil::ip_in_cidr`，两侧都会折 v4-mapped），
/// 兼容历史库里写成 `start-end` 区间的行。其它形态（包括旧 LIKE 语义的垃圾值）不命中。
fn edit_prefix_hits_ip(prefix: &str, ip: std::net::IpAddr) -> bool {
    use crate::server::geoip_panel::iputil;
    let p = prefix.trim();
    if p.is_empty() {
        return false;
    }
    let ip = iputil::unmap_v4_mapped(ip);
    if iputil::ip_in_cidr(p, ip) {
        return true;
    }
    if let Some((s, e)) = p.split_once('-') {
        let ip_s = ip.to_string();
        return match ip {
            std::net::IpAddr::V4(_) => iputil::ipv4_in_range(&ip_s, s.trim(), e.trim()),
            std::net::IpAddr::V6(_) => iputil::ipv6_in_range(&ip_s, s.trim(), e.trim()),
        };
    }
    false
}

fn apply_field(m: &mut MergedFields, field: &str, value: &str) {
    // Empty never overwrites non-empty (§23.5).
    let set = |dst: &mut String| {
        if value.is_empty() && !dst.is_empty() {
            return;
        }
        *dst = value.to_string();
    };
    // 字段名容忍历史数据里的空白/大小写；新写入由 [`upsert_edit`] 白名单把关。
    match field.trim().to_ascii_lowercase().as_str() {
        "country" => set(&mut m.country),
        "province" => set(&mut m.province),
        "region" => set(&mut m.region),
        "city" => set(&mut m.city),
        "district" => set(&mut m.district),
        "isp" => set(&mut m.isp),
        "asn" => set(&mut m.asn),
        "as_org" => set(&mut m.as_org),
        "cloud_provider" => set(&mut m.cloud_provider),
        "cloud_region" => set(&mut m.cloud_region),
        "cloud_service" => set(&mut m.cloud_service),
        "hosting" => set(&mut m.hosting),
        "division_code" => set(&mut m.division_code),
        "dc" => set(&mut m.dc),
        _ => {}
    }
}

/// Insert or update a hand edit and audit log entry (§23.6 UPSERT).
///
/// 落库前校验并归一：`prefix` 必须是合法 CIDR（单个 IP 等价 /32、/128，主机位清零，
/// v4-mapped 折 v4）——旧实现不校验，`%`/`_` 直接入库后配合 LIKE 就是一条全局覆盖；
/// `field` 必须在白名单内——拼错只入库不生效、面板却回 ok。
pub fn upsert_edit(
    panel: &Connection,
    prefix: &str,
    field: &str,
    value: &str,
    weight: i64,
) -> Result<()> {
    let prefix = crate::server::geoip_panel::iputil::normalize_cidr_prefix(prefix)
        .ok_or_else(|| anyhow::anyhow!("invalid edit prefix {prefix:?}（需要 CIDR 或单个 IP）"))?;
    let field = field.trim().to_ascii_lowercase();
    if !EDIT_FIELDS.contains(&field.as_str()) {
        anyhow::bail!(
            "invalid edit field {field:?}（可用字段：{}）",
            EDIT_FIELDS.join(", ")
        );
    }
    // 权重参与的只有「同字段多条编辑谁最后生效」；负值无意义，截到 0。
    let weight = weight.max(0);
    // Ensure unique key for UPSERT (prefix, field).
    panel.execute_batch(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_panel_edits_pf ON panel_edits(prefix, field);",
    )?;
    panel.execute(
        "INSERT INTO panel_edits(prefix, field, value, weight) VALUES(?1, ?2, ?3, ?4)
         ON CONFLICT(prefix, field) DO UPDATE SET
           value = excluded.value,
           weight = excluded.weight",
        rusqlite::params![prefix, field, value, weight],
    )?;
    panel.execute(
        "INSERT INTO panel_audit(action, detail) VALUES('edit', ?1)",
        rusqlite::params![format!("{prefix} {field}={value} w={weight}")],
    )?;
    Ok(())
}

/// List unresolved conflicts from panel DB.
pub fn list_conflicts(panel: &Connection) -> Result<Vec<(i64, String, String, String)>> {
    let mut stmt = panel.prepare(
        "SELECT id, prefix, field, sources FROM panel_conflicts WHERE resolved = 0 ORDER BY id DESC LIMIT 200",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
        ))
    })?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

/// Audit log rows for Admin (newest first).
pub fn list_audit(panel: &Connection, limit: usize) -> Result<Vec<(i64, String, String, i64)>> {
    let lim = limit.min(500);
    let mut stmt = panel.prepare(
        "SELECT id, action, detail, COALESCE(ts, 0) FROM panel_audit ORDER BY id DESC LIMIT ?1",
    )?;
    let rows = stmt.query_map(rusqlite::params![lim as i64], |row| {
        Ok((
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
        ))
    })?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

/// List panel_cron rows.
pub fn list_cron(panel: &Connection) -> Result<Vec<(i64, String, String, i64, i64)>> {
    let mut stmt = panel.prepare(
        "SELECT id, name, schedule, COALESCE(enabled, 1), COALESCE(last_run, 0)
         FROM panel_cron ORDER BY id ASC",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
            row.get(4)?,
        ))
    })?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

/// Upsert a cron row (by name).
pub fn upsert_cron(
    panel: &Connection,
    name: &str,
    schedule: &str,
    enabled: bool,
) -> Result<()> {
    panel.execute(
        "INSERT INTO panel_cron(name, schedule, enabled, last_run)
         VALUES(?1, ?2, ?3, 0)
         ON CONFLICT(name) DO UPDATE SET schedule=excluded.schedule, enabled=excluded.enabled",
        rusqlite::params![name, schedule, if enabled { 1 } else { 0 }],
    )?;
    panel.execute(
        "INSERT INTO panel_audit(action, detail) VALUES('cron', ?1)",
        rusqlite::params![format!("{name} schedule={schedule} enabled={enabled}")],
    )?;
    Ok(())
}

/// P1-4：计划任务的 schedule 白名单解析（§23.6「计划任务：执行脚本」）。
///
/// **保守**：只认下面这几种写法；任何其它字符串（尤其是 5 段 cron 表达式
/// `0 3 * * *`）一律返回 `None` ⇒ **绝不执行**，只记一次 warn。面板里写错一个
/// 表达式绝不能让服务器按错误的频率反复跑重活（下载 + 13 个 enrich）。
///
/// 支持：`hourly` / `daily` / `weekly` / `daily HH:MM` / `HH:MM`（=每日该时刻）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CronSchedule {
    /// 每 3600s（自上次运行起算）。
    Hourly,
    /// `None` = 每 86400s；`Some((h,m))` = 每天本地时间 h:m。
    Daily(Option<(u8, u8)>),
    /// 每 7*86400s（自上次运行起算）。
    Weekly,
}

/// 解析 schedule（见 [`CronSchedule`]）；无法识别返回 `None`。
pub fn parse_schedule(s: &str) -> Option<CronSchedule> {
    let t = s.trim().to_ascii_lowercase();
    match t.as_str() {
        "" => None,
        "hourly" | "@hourly" => Some(CronSchedule::Hourly),
        "daily" | "@daily" | "midnight" => Some(CronSchedule::Daily(None)),
        "weekly" | "@weekly" => Some(CronSchedule::Weekly),
        _ => {
            let hm = t.strip_prefix("daily ").map(str::trim).or_else(|| {
                // 纯 `HH:MM` 也当作每日（规格白名单里的 `HH:MM`（每日））。
                if t.contains(':') {
                    Some(t.as_str())
                } else {
                    None
                }
            })?;
            parse_hhmm(hm).map(|hm| CronSchedule::Daily(Some(hm)))
        }
    }
}

/// 解析 `HH:MM`（24 小时制，严格的 5 字符形式），越界/畸形返回 `None`。
fn parse_hhmm(s: &str) -> Option<(u8, u8)> {
    let s = s.trim();
    let (h, m) = s.split_once(':')?;
    if h.is_empty() || m.is_empty() || m.contains(':') {
        return None;
    }
    // 只接受指定位数（"3:00" 也放过：容忍运维手写；但拒绝 "03:0" 之外的怪值靠范围校验）。
    let h: u8 = h.parse().ok()?;
    let m: u8 = m.parse().ok()?;
    if h > 23 || m > 59 {
        return None;
    }
    Some((h, m))
}

/// 本地时间下的「今天 HH:MM」的 unix 秒（若晚于 now 则回退到昨天 —— 取**最近一次**已到点）。
///
/// 用 libc `localtime_r`（进程已链接 libc；与脚本用 `date` 得到的本地时间一致），避免
/// 引入时区依赖。失败时（极不可能）回落 UTC 语义（tm 全 0 时会走 `now` 分支）。
fn last_occurrence_local(now: i64, h: u8, m: u8) -> i64 {
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let t = now as libc::time_t;
    let ok = unsafe { !libc::localtime_r(&t, &mut tm).is_null() };
    if !ok {
        // 回落：按「距上次整点」的粗粒度判定（不会误执行，只是不精确）。
        return now - (now.rem_euclid(86400));
    }
    let sod = tm.tm_hour as i64 * 3600 + tm.tm_min as i64 * 60 + tm.tm_sec as i64;
    let today_at = now - sod + h as i64 * 3600 + m as i64 * 60;
    if today_at > now {
        today_at - 86400
    } else {
        today_at
    }
}

/// 该 schedule 在 `now` 时点是否到期（`last_run == 0` = 从未运行 ⇒ 视为到期）。
///
/// 间隔型（hourly/weekly/daily 无时刻）按「自上次运行起算」；时刻型（daily HH:MM /
/// HH:MM）按「最近一次该时刻是否已过且晚于上次运行」。
pub fn schedule_due(sched: &CronSchedule, last_run: i64, now: i64) -> bool {
    if last_run <= 0 {
        return true;
    }
    match sched {
        CronSchedule::Hourly => now - last_run >= 3600,
        CronSchedule::Daily(None) => now - last_run >= 86400,
        CronSchedule::Weekly => now - last_run >= 7 * 86400,
        CronSchedule::Daily(Some((h, m))) => last_occurrence_local(now, *h, *m) > last_run,
    }
}

/// 记一次计划任务运行（更新 `last_run` + `last_status` + 审计）。
pub fn mark_cron_run(panel: &Connection, id: i64, status: &str) -> Result<()> {
    let now = now_unix();
    panel.execute(
        "UPDATE panel_cron SET last_run = ?1, last_status = ?2 WHERE id = ?3",
        rusqlite::params![now, status, id],
    )?;
    panel.execute(
        "INSERT INTO panel_audit(action, detail) VALUES('cron_run', ?1)",
        rusqlite::params![format!("#{id} {status}")],
    )?;
    Ok(())
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// 无法识别的 schedule 只 warn 一次（同一条字符串），避免每 60s 刷一条日志。
fn warn_unrecognized_schedule_once(schedule: &str) {
    static SEEN: std::sync::Mutex<Option<std::collections::HashSet<String>>> =
        std::sync::Mutex::new(None);
    let mut g = SEEN.lock().unwrap_or_else(|e| e.into_inner());
    let set = g.get_or_insert_with(std::collections::HashSet::new);
    if set.insert(schedule.to_string()) {
        log::warn!(
            "geoip cron: 无法识别的 schedule {schedule:?} —— 不会执行该任务。\
             支持 hourly/daily/weekly/daily HH:MM/HH:MM"
        );
    }
}

/// P1-4：执行器 —— 读 `panel_cron`，判定「到点」并触发离线更新脚本（单飞）。
///
/// 由 `server::mod` 的周期任务每 60s 调用一次。到点的任务一律跑
/// `[geoip] update_script`（P1-11 可配），触发与面板按钮共用 `spawn_geoip_update_script`
/// 的单实例保护（锁目录 + 进程扫描 + 进程内 Mutex）⇒ **不会并发跑两次**。
/// 失败只 warn，绝不影响进程存活。返回本次成功触发的任务数。
pub fn run_due_crons(geoip: &crate::config::GeoIpConfig) -> usize {
    let root = Path::new(".");
    let panel_path = crate::server::geoip_panel::db::panel_db_path();
    if !panel_path.is_file() {
        return 0;
    }
    let conn = match crate::server::geoip_panel::db::open_panel(&panel_path) {
        Ok(c) => c,
        Err(e) => {
            log::warn!("geoip cron: 打开面板库失败: {e:#}");
            return 0;
        }
    };
    let rows = match list_cron(&conn) {
        Ok(r) => r,
        Err(e) => {
            log::warn!("geoip cron: 读取 panel_cron 失败: {e:#}");
            return 0;
        }
    };
    let now = now_unix();
    let mut spawned = 0usize;
    // 每个 schedule 字符串只 warn 一次（跨调用）。
    for (_id, _name, schedule, enabled, last_run) in rows {
        if enabled == 0 {
            continue;
        }
        let Some(sched) = parse_schedule(&schedule) else {
            warn_unrecognized_schedule_once(&schedule);
            continue;
        };
        if !schedule_due(&sched, last_run, now) {
            continue;
        }
        let script = geoip.update_script_path();
        match spawn_geoip_update_script(root, Some(script.as_path()), None) {
            Ok(()) => {
                // 只有**真正触发**了才推进 last_run：被并发保护挡下（另一轮在跑）时
                // 不改时间戳，下一 tick 会自然重试。
                if let Err(e) = mark_cron_run(&conn, _id, "spawned") {
                    log::warn!("geoip cron: 记 last_run 失败: {e:#}");
                }
                spawned += 1;
                log::info!(
                    "geoip cron: 任务 {} (schedule={schedule}) 到期，已触发更新脚本",
                    _name
                );
            }
            Err(e) => {
                log::warn!("geoip cron: 触发更新脚本失败: {e:#}");
            }
        }
    }
    spawned
}

// ------------------------------ P1-9 自定义 geofeed 列表 ------------------------------

/// 一行自定义 geofeed（面板列表展示）。
#[derive(Clone, Debug, Default)]
pub struct GeofeedRow {
    pub id: i64,
    pub url: String,
    pub enabled: bool,
    pub last_fetch: i64,
    pub last_status: String,
}

/// 列出面板里的自定义 geofeed URL。
pub fn list_geofeed(panel: &Connection) -> Result<Vec<GeofeedRow>> {
    let mut stmt = panel.prepare(
        "SELECT id, url, COALESCE(enabled, 1), COALESCE(last_fetch, 0), COALESCE(last_status, '')
         FROM panel_geofeed ORDER BY id ASC",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(GeofeedRow {
            id: row.get(0)?,
            url: row.get(1)?,
            enabled: row.get::<_, i64>(2)? != 0,
            last_fetch: row.get(3)?,
            last_status: row.get(4)?,
        })
    })?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

/// 新增一个自定义 geofeed URL（幂等；只接受 http/https）。
pub fn add_geofeed(panel: &Connection, url: &str) -> Result<()> {
    let url = url.trim();
    if url.is_empty() {
        anyhow::bail!("geofeed url 不能为空");
    }
    let lower = url.to_ascii_lowercase();
    if !(lower.starts_with("http://") || lower.starts_with("https://")) {
        anyhow::bail!("geofeed url 必须是 http(s):// 地址");
    }
    panel.execute(
        "INSERT INTO panel_geofeed(url, enabled, last_fetch, last_status)
         VALUES(?1, 1, 0, '') ON CONFLICT(url) DO NOTHING",
        rusqlite::params![url],
    )?;
    panel.execute(
        "INSERT INTO panel_audit(action, detail) VALUES('geofeed_add', ?1)",
        rusqlite::params![url],
    )?;
    Ok(())
}

/// 删除一个自定义 geofeed URL。
pub fn delete_geofeed(panel: &Connection, id: i64) -> Result<bool> {
    let n = panel.execute("DELETE FROM panel_geofeed WHERE id = ?1", rusqlite::params![id])?;
    if n > 0 {
        panel.execute(
            "INSERT INTO panel_audit(action, detail) VALUES('geofeed_delete', ?1)",
            rusqlite::params![format!("geofeed #{id} removed")],
        )?;
    }
    Ok(n > 0)
}

/// 供离线脚本消费的「供给层」：把启用的 geofeed URL 写成 JSON 文件。
///
/// 选这条路径的理由（§23.6「自定义 geofeed 列表：添加 URL；批量刷新」）：生产路径**禁止**
/// 调 Python，但批量下载 geofeed 属于离线更新工作，只能由 `scripts/geoip_*` 做。于是
/// Rust 侧只负责把面板库里的 URL 落成一个纯数据文件（`custom_geofeed.json`），
/// `geoip_update.sh --only=geofeed` 再让 `geoip_enrich_geofeed.py --urls-file` 读它并导入。
/// 这样 Rust 与 Python 之间只有一份**声明式数据**（不是命令执行桥），符合 §23.1 铁律 2/3。
pub fn write_geofeed_supply(path: &Path, urls: &[String]) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("mkdir {}", dir.display()))?;
    }
    let body = serde_json::json!({ "urls": urls });
    // 原子写（同目录 tmp + rename）：与 toml_store 同策，避免半截文件被脚本读到。
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(".tmp");
    let tmp = std::path::PathBuf::from(tmp);
    let text = serde_json::to_string_pretty(&body).context("encode custom geofeed json")?;
    if let Err(e) = std::fs::write(&tmp, text) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("write {}", tmp.display()));
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("rename {} -> {}", tmp.display(), path.display()));
    }
    Ok(())
}

/// 自定义 geofeed 供给层路径（`CRUCIBLE_GEOIP_CUSTOM_GEOFEED` 覆盖 → 默认）。
pub fn custom_geofeed_supply_path() -> std::path::PathBuf {
    crate::server::apps::env_lock::read_static_env("CRUCIBLE_GEOIP_CUSTOM_GEOFEED")
        .filter(|s| !s.trim().is_empty())
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("data/geoip/sources/custom_geofeed.json"))
}

/// 收集启用的 geofeed URL（供批量刷新写供给层）。
pub fn enabled_geofeed_urls(panel: &Connection) -> Result<Vec<String>> {
    Ok(list_geofeed(panel)?
        .into_iter()
        .filter(|r| r.enabled)
        .map(|r| r.url)
        .collect())
}

// ------------------------------ P2-17 筛选下拉取值 ------------------------------

/// 从三张表（geoip/ipv4/ipv6）取某列的去重值（面板筛选 datalist 用）。
///
/// `field` 只接受白名单列名（country/province/city/isp），拼接进 SQL 前先校验 ——
/// 这是内部调用，但保持「不接受任意列名」的防御性。
pub fn distinct_values(conn: &Connection, field: &str, limit: usize) -> Result<Vec<String>> {
    let col = match field {
        "country" | "province" | "city" | "isp" | "region" => field,
        _ => anyhow::bail!("invalid distinct field: {field}"),
    };
    let lim = limit.min(1000);
    let sql = format!(
        "SELECT v FROM (
             SELECT {col} AS v FROM geoip WHERE {col} IS NOT NULL AND {col} != ''
             UNION SELECT {col} FROM ipv4 WHERE {col} IS NOT NULL AND {col} != ''
             UNION SELECT {col} FROM ipv6 WHERE {col} IS NOT NULL AND {col} != ''
         ) ORDER BY v LIMIT ?1"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(rusqlite::params![lim as i64], |r| r.get::<_, String>(0))?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

/// Toggle / set source weight+enabled.
///
/// 校验：既没给 enabled 也没给 weight ⇒ 无事可做（报错，别假成功）；给了值但
/// `panel_sources` 里没有该 name（面板/表单拼错）⇒ 0 行受影响，报错而不是回 ok。
/// 旧实现只 `UPDATE ... WHERE name=?` 后无条件 `Ok(())`，于是改一个不存在的源名
/// 面板回 `{"ok":true}`、审计也记了，实际什么都没发生（与「覆盖假成功」同类）。
pub fn set_source(
    panel: &Connection,
    name: &str,
    enabled: Option<bool>,
    weight: Option<i64>,
) -> Result<()> {
    if enabled.is_none() && weight.is_none() {
        anyhow::bail!("nothing to update for source {name:?}（enabled/weight 都为空）");
    }
    let mut affected = 0usize;
    if let Some(en) = enabled {
        affected += panel.execute(
            "UPDATE panel_sources SET enabled = ?1 WHERE name = ?2",
            rusqlite::params![if en { 1 } else { 0 }, name],
        )?;
    }
    if let Some(w) = weight {
        affected += panel.execute(
            // 消费方：**离线合并** `scripts/geoip_merge.py` 的
            // `PANEL_SOURCE_OVERRIDES`（读 panel.toml / panel.sqlite）——它按源名覆盖
            // `LAYER_WEIGHTS`，`enabled=false` 的层整层跳过。此前面板写入无任何消费者
            // （Wave-25 判定为伪实现），现改权重/启用会在**下一次合并**生效。
            "UPDATE panel_sources SET weight = ?1 WHERE name = ?2",
            rusqlite::params![w, name],
        )?;
    }
    if affected == 0 {
        anyhow::bail!("unknown geoip source {name:?}（panel_sources 无此行）");
    }
    panel.execute(
        "INSERT INTO panel_audit(action, detail) VALUES('source', ?1)",
        rusqlite::params![format!("{name} enabled={enabled:?} weight={weight:?}")],
    )?;
    Ok(())
}

/// 进程表里是否还有 `geoip_update.sh`（不依赖锁，兜住「锁已清但进程还在」）。
fn any_geoip_update_running() -> bool {
    std::process::Command::new("pgrep")
        .args(["-f", "geoip_update\\.sh"])
        .output()
        .ok()
        .map(|o| !String::from_utf8_lossy(&o.stdout).trim().is_empty())
        .unwrap_or(false)
}

/// 读脚本锁目录里的 pid（脚本自己在 mkdir 成功后写入）。
fn read_lock_pid(lock_dir: &Path) -> Option<i32> {
    std::fs::read_to_string(lock_dir.join("pid"))
        .ok()
        .and_then(|s| s.trim().parse::<i32>().ok())
        .filter(|p| *p > 1)
}

/// 该 pid 是否真是我们的 geoip_update.sh —— 防 pid 复用把「已结束」误判成「在跑」。
pub fn proc_is_geoip_update(pid: i32) -> bool {
    if unsafe { libc::kill(pid, 0) } != 0 {
        return false;
    }
    std::process::Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "command="])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("geoip_update.sh"))
        .unwrap_or(false)
}

/// 进程内串行化「检查→spawn」这一步。
///
/// 锁文件与进程扫描都是**快照**：两个并发请求（面板双点、两个人同时点、或与 cron 撞上）
/// 可以同时通过两道检查、然后各 spawn 一个 updater，而 merge/enrich 不是为并发写的
/// （同一份 SQLite 会被两个进程同时改 → `database is locked`，代码注释里记过
/// 「实测一次误操作就出现了 4 个并发更新进程」）。跨进程那两道检查保留，这里补上
/// **进程内**的原子性。
static SPAWN_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Spawn offline geoip_update.sh (non-blocking).
///
/// P1-11：脚本路径与 `--only=<源名>` 都可配 —— 前者来自 `[geoip] update_script`
/// （默认 `scripts/geoip_update.sh`），后者来自 `/api/geoip/update?only=`。
pub fn spawn_geoip_update(root: &Path) -> Result<()> {
    spawn_geoip_update_script(root, None, None)
}

/// Spawn the (configurable) offline update script, optionally with `--only=<name>`.
///
/// `script` 为 `None`/空 ⇒ 沿用 `root/scripts/geoip_update.sh`；绝对路径原样使用。
/// `only` 为 `None`/空 ⇒ 全链更新（不带 `--only`）。
pub fn spawn_geoip_update_script(
    root: &Path,
    script: Option<&Path>,
    only: Option<&str>,
) -> Result<()> {
    let script = match script {
        Some(p) if !p.as_os_str().is_empty() => {
            if p.is_absolute() {
                p.to_path_buf()
            } else {
                root.join(p)
            }
        }
        _ => root.join("scripts/geoip_update.sh"),
    };
    if !script.is_file() {
        anyhow::bail!("missing {}", script.display());
    }
    // 注意：`_guard` 必须活到 spawn 之后（drop 即放锁），所以绑定在函数作用域里。
    let _guard = SPAWN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let pid_file = root.join("data/geoip/logs/update.pid");
    let lock_dir = root.join("data/geoip/logs/update.lock");
    // 单实例保护：面板按钮点两次、两个人同时点、或按钮与 cron 撞上，都会拉起第二个 updater，
    // 而 merge/enrich 不是为并发写的（两个进程同时改同一个 SQLite）—— 轻则互相覆盖、
    // 重则把库写坏。实测一次误操作就出现了 4 个并发更新进程。
    //
    // 存活判定**不能只看 pid**：pid 会被复用（实测踩到 —— 脚本早已退出，pid 24327 被别的
    // 进程接手，面板于是永远报「更新已在进行中」）。这里以脚本自己的锁目录为准，并要求那个
    // pid 的命令行**确实是 geoip_update.sh**。
    if let Some(p) = read_lock_pid(&lock_dir) {
        if proc_is_geoip_update(p) {
            anyhow::bail!("geoip 更新已在进行中（pid={p}），等它跑完再触发");
        }
    }
    // 锁**不是**充分条件：脚本正常收尾会用自己的 trap 清掉锁，但主进程可能因为别的原因
    // 还挂着（实测：脚本记完 done、锁也清了，进程却卡住没退，于是第二轮被放行、两轮同时
    // 写库 → 后一轮的 merge 撞上 `database is locked` 直接失败）。所以再扫一遍进程表。
    if any_geoip_update_running() {
        anyhow::bail!("geoip 更新已有进程在运行（锁已过期但进程仍在），等它结束再触发");
    }
    let mut cmd = std::process::Command::new("bash");
    cmd.arg(&script);
    if let Some(only) = only.map(str::trim).filter(|s| !s.is_empty()) {
        // 与脚本的解析一致（`--only=X` 形式，避免某些源名以 `-` 开头时被 getopt 误读）。
        cmd.arg(format!("--only={only}"));
    }
    let child = cmd
        .current_dir(root)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("spawn geoip_update.sh")?;
    // 记 pid：脚本是全链最慢的一步（要下载 + 13 个 enrich），面板要能显示
    // 「还在跑 / 跑完了」，而脚本自己的进度在 data/geoip/logs/update.log 里
    // （它用 tee 全程落盘）。没有这个文件，后端只能干说一句「已启动」。
    if let Some(dir) = pid_file.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(&pid_file, child.id().to_string());
    Ok(())
}

/// 面板筛选聚合（P2-18 / §23.10 模块职责表）：实现已迁至 [`super::filter_agg`]。
///
/// 这里 `pub use` 重新导出，保持既有调用点（`admin_geoip::handle_filter_with_live`
/// 与 `ops.rs` 单测里的 `filter_prefixes`）完全不变。
pub use super::filter_agg::{filter_prefixes, FilterRow};

/// 列出当前手工覆盖（panel_edits，最新在前）。
pub fn list_edits(panel: &Connection, limit: usize) -> Result<Vec<(i64, String, String, String, i64)>> {
    let lim = limit.min(500);
    let mut stmt = panel.prepare(
        "SELECT id, prefix, field, value, COALESCE(weight, 200)
         FROM panel_edits ORDER BY id DESC LIMIT ?1",
    )?;
    let rows = stmt.query_map(rusqlite::params![lim as i64], |row| {
        Ok((
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
            row.get(4)?,
        ))
    })?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

/// 删除一条手工覆盖（§23.6 面板撤销入口）。
pub fn delete_edit(panel: &Connection, id: i64) -> Result<bool> {
    let n = panel.execute("DELETE FROM panel_edits WHERE id = ?1", rusqlite::params![id])?;
    if n > 0 {
        panel.execute(
            "INSERT INTO panel_audit(action, detail) VALUES('edit_delete', ?1)",
            rusqlite::params![format!("edit #{id} removed")],
        )?;
    }
    Ok(n > 0)
}

/// 标记冲突为已处理（Admin 面板「已处理」按钮）。
pub fn resolve_conflict(panel: &Connection, id: i64) -> Result<bool> {
    let n = panel.execute(
        "UPDATE panel_conflicts SET resolved = 1 WHERE id = ?1",
        rusqlite::params![id],
    )?;
    if n > 0 {
        panel.execute(
            "INSERT INTO panel_audit(action, detail) VALUES('conflict_resolve', ?1)",
            rusqlite::params![format!("conflict #{id} resolved")],
        )?;
    }
    Ok(n > 0)
}

    /// 获取 covering 表中某源在某前缀的某字段值（冲突裁决 UI 用）。
    pub fn get_covering_field(
        conn: &Connection,
        source: &str,
        prefix: &str,
        field: &str,
    ) -> Result<Option<String>> {
        let safe_field = match field {
            "ip_start" | "ip_end" | "bits" | "weight" | "source" | "prefix"
            | "country" | "region" | "province" | "city" | "district" | "isp"
            | "asn" | "as_org" | "cloud_provider" | "cloud_region" | "cloud_service"
            | "hosting" | "division_code" | "dc" | "commit_unix"
            | "e_country" | "e_province" | "e_city" | "e_district"
            | "e_isp" | "e_asn" | "e_as_org" | "e_cloud_provider"
            | "e_cloud_region" | "e_cloud_service" | "e_hosting" => field,
            _ => anyhow::bail!("invalid field name: {}", field),
        };
        let sql = format!(
            "SELECT {} FROM geoip WHERE source=? AND prefix=? LIMIT 1",
            safe_field
        );
        let val: Option<String> =
            conn.query_row(&sql, [source, prefix], |r| r.get(0))?;
        Ok(val)
    }


#[cfg(test)]
mod tests {
    use super::*;

    fn panel_db() -> Connection {
        crate::server::geoip_panel::db::open_panel(std::path::Path::new(":memory:")).unwrap()
    }

    /// prefix/field 落库前校验：通配符 prefix、非法 CIDR、白名单外字段一律拒绝；
    /// 合法 prefix 归一后入库、负权重截 0、同键 UPSERT 不新增行。
    #[test]
    fn upsert_edit_validates_and_normalizes() {
        let panel = panel_db();
        assert!(upsert_edit(&panel, "%", "country", "US", 200).is_err(), "% 是 LIKE 通配符，必须拒绝");
        assert!(upsert_edit(&panel, "_", "country", "US", 200).is_err());
        assert!(upsert_edit(&panel, "10.0.0.0/33", "country", "US", 200).is_err());
        assert!(upsert_edit(&panel, "10.0.0", "country", "US", 200).is_err());
        assert!(upsert_edit(&panel, "10.0.0.0/8", "contry", "US", 200).is_err());
        upsert_edit(&panel, "10.0.0.1/8", "  Country ", "US", -5).unwrap();
        let (p, f, v, w): (String, String, String, i64) = panel
            .query_row("SELECT prefix, field, value, weight FROM panel_edits", [], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
            })
            .unwrap();
        assert_eq!(p, "10.0.0.0/8", "主机位清零");
        assert_eq!(f, "country", "字段名 trim + 小写");
        assert_eq!(v, "US");
        assert_eq!(w, 0, "负权重截到 0");
        upsert_edit(&panel, "10.0.0.0/8", "country", "DE", 300).unwrap();
        let n: i64 = panel
            .query_row("SELECT count(*) FROM panel_edits", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1, "同 (prefix, field) 是 UPSERT，不新增行");
    }

    /// 筛选必须覆盖 §23 双 schema 的 ipv4/ipv6 表（旧实现只查 geoip，v6 行永远筛不到）。
    #[test]
    fn filter_covers_ipv4_ipv6_tables() {
        let conn = crate::server::geoip_panel::db::open(std::path::Path::new(":memory:")).unwrap();
        conn.execute(
            "INSERT INTO geoip(ip_start, ip_end, country, city, weight, prefix)
             VALUES('1.2.4.0','1.2.4.255','CN','Beijing',80,'1.2.4.0/24')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO ipv4(start, end, country, city, weight, prefix)
             VALUES('8.8.8.0','8.8.8.255','US','Mountain View',80,'8.8.8.0/24')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO ipv6(start, end, country, city, weight, prefix)
             VALUES('2001:db8::','2001:db8::ffff','US','Documentation',50,'2001:db8::/112')",
            [],
        )
        .unwrap();
        let all = filter_prefixes(&conn, None, None, None, None, None, 100).unwrap();
        assert!(all.iter().any(|r| r.prefix == "1.2.4.0/24"));
        assert!(all.iter().any(|r| r.prefix == "8.8.8.0/24"), "ipv4 表行必须被筛到");
        assert!(all.iter().any(|r| r.prefix == "2001:db8::/112"), "ipv6 表行必须被筛到");
        let us = filter_prefixes(&conn, Some("us"), None, None, None, None, 100).unwrap();
        assert!(us.iter().any(|r| r.city == "Mountain View"));
        assert!(us.iter().any(|r| r.city == "Documentation"));
        assert!(!us.iter().any(|r| r.country == "CN"));

        // §23.6 新维度：family=IPv4|v6 与 prefix 包含匹配。
        let v6 = filter_prefixes(&conn, None, None, None, Some("v6"), None, 100).unwrap();
        assert!(v6.iter().any(|r| r.prefix == "2001:db8::/112"), "family=v6 应保留 IPv6 行");
        assert!(!v6.iter().any(|r| r.prefix.contains('.')), "family=v6 不应含 IPv4 行：{:?}", v6.iter().map(|r| &r.prefix).collect::<Vec<_>>());
        let v4 = filter_prefixes(&conn, None, None, None, Some("IPv4"), None, 100).unwrap();
        assert!(v4.iter().any(|r| r.prefix == "8.8.8.0/24"), "family=IPv4 别名应生效");
        assert!(!v4.iter().any(|r| r.prefix.contains(':')), "family=IPv4 不应含 IPv6 行");
        // 拼写错误/未知 family 不应把结果筛空（按「不过滤」处理）。
        let bogus = filter_prefixes(&conn, None, None, None, Some("v5"), None, 100).unwrap();
        assert_eq!(bogus.len(), all.len(), "未知 family 应等同不过滤");
        let by_prefix = filter_prefixes(&conn, None, None, None, None, Some("2001:db8"), 100).unwrap();
        assert_eq!(by_prefix.len(), 1);
        assert_eq!(by_prefix[0].prefix, "2001:db8::/112");
        let by_prefix_v4 = filter_prefixes(&conn, None, None, None, Some("v4"), Some("8.8.8"), 100).unwrap();
        assert_eq!(by_prefix_v4.len(), 1);
        assert_eq!(by_prefix_v4[0].prefix, "8.8.8.0/24");
    }

    /// P1-4：schedule 白名单解析必须**保守** —— 只认五种写法，5 段 cron 表达式一律拒绝。
    #[test]
    fn cron_schedule_whitelist_parsing() {
        assert_eq!(parse_schedule(" hourly "), Some(CronSchedule::Hourly));
        assert_eq!(parse_schedule("daily"), Some(CronSchedule::Daily(None)));
        assert_eq!(parse_schedule("weekly"), Some(CronSchedule::Weekly));
        assert_eq!(parse_schedule("03:30"), Some(CronSchedule::Daily(Some((3, 30)))));
        assert_eq!(
            parse_schedule("daily 23:59"),
            Some(CronSchedule::Daily(Some((23, 59))))
        );
        // 绝不能因面板里写了奇怪表达式就定时跑重活。
        assert_eq!(parse_schedule("0 3 * * *"), None);
        assert_eq!(parse_schedule("every 5 minutes"), None);
        assert_eq!(parse_schedule("25:00"), None);
        assert_eq!(parse_schedule(""), None);
    }

    /// P1-4：间隔型到期判定（确定性，不依赖本地时区）。
    #[test]
    fn cron_due_intervals() {
        let now = 1_000_000_000i64;
        assert!(schedule_due(&CronSchedule::Hourly, 0, now), "从未运行 ⇒ 到期");
        assert!(!schedule_due(&CronSchedule::Hourly, now - 10, now));
        assert!(schedule_due(&CronSchedule::Hourly, now - 3600, now));
        assert!(!schedule_due(&CronSchedule::Daily(None), now - 100, now));
        assert!(schedule_due(&CronSchedule::Daily(None), now - 86_400, now));
        assert!(!schedule_due(&CronSchedule::Weekly, now - 86_400, now));
        assert!(schedule_due(&CronSchedule::Weekly, now - 7 * 86_400, now));
    }

    /// 源管理不得假成功：无字段可改、或源名不存在，都必须报错（旧实现无条件回 ok）。
    #[test]
    fn set_source_rejects_unknown_and_noop() {
        let panel = panel_db();
        assert!(set_source(&panel, "x", None, None).is_err(), "无事可做应报错");
        assert!(set_source(&panel, "nope", Some(true), None).is_err(), "未知源名应报错");
        panel
            .execute(
                "INSERT INTO panel_sources(name, weight, enabled) VALUES('demo', 50, 1)",
                [],
            )
            .unwrap();
        set_source(&panel, "demo", Some(false), Some(80)).unwrap();
        let (en, w): (i64, i64) = panel
            .query_row(
                "SELECT enabled, weight FROM panel_sources WHERE name='demo'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(en, 0);
        assert_eq!(w, 80);
    }
}
