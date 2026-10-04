//! GeoIP panel maintenance operations (import, purge, rebuild, hand edits).

use crate::server::geoip_panel::covering::MergedFields;
use crate::server::geoip_panel::db;
use anyhow::{Context, Result};
use rusqlite::Connection;
use std::path::Path;

/// Rebuild covering indexes and normalize prefix metadata in `geoip.sqlite`.
pub fn rebuild_covering(db_path: &Path) -> Result<()> {
    let conn = db::open(db_path)?;
    rebuild_covering_conn(&conn)?;
    Ok(())
}

/// Same as [`rebuild_covering`] using an open connection.
pub fn rebuild_covering_conn(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE INDEX IF NOT EXISTS idx_geoip_cover ON geoip(ip_start, ip_end);
         CREATE INDEX IF NOT EXISTS idx_geoip_start ON geoip(ip_start);
         UPDATE geoip SET bits = COALESCE(bits, 0) WHERE bits IS NULL;
         UPDATE geoip SET weight = COALESCE(weight, 0) WHERE weight IS NULL;
         UPDATE geoip SET prefix = ip_start || '-' || ip_end
           WHERE prefix IS NULL OR prefix = '';
         ANALYZE geoip;",
    )
    .context("geoip rebuild_covering")?;
    Ok(())
}

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

/// Toggle / set source weight+enabled.
pub fn set_source(
    panel: &Connection,
    name: &str,
    enabled: Option<bool>,
    weight: Option<i64>,
) -> Result<()> {
    if let Some(en) = enabled {
        panel.execute(
            "UPDATE panel_sources SET enabled = ?1 WHERE name = ?2",
            rusqlite::params![if en { 1 } else { 0 }, name],
        )?;
    }
    if let Some(w) = weight {
        panel.execute(
            "UPDATE panel_sources SET weight = ?1 WHERE name = ?2",
            rusqlite::params![w, name],
        )?;
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
pub fn spawn_geoip_update(root: &Path) -> Result<()> {
    let script = root.join("scripts/geoip_update.sh");
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
    let child = std::process::Command::new("bash")
        .arg(&script)
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

/// 一条筛选结果（Admin 面板表格展示用）。
pub struct FilterRow {
    pub prefix: String,
    pub country: String,
    pub province: String,
    pub city: String,
    pub isp: String,
    pub cloud_provider: String,
    pub weight: i64,
}

/// 转义 LIKE 元字符（`%` `_` `\`），避免面板输入的 `%` 被当成通配符。
/// 配合 SQL 侧的 `ESCAPE '\'` 使用。
fn like_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        if matches!(ch, '%' | '_' | '\\') {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

/// Filter geoip rows by country/isp/cloud（Admin 面板筛选；结果携带字段供表格渲染）。
///
/// 三张表都要查：`geoip`（主表）与 §23 双 schema 的 `ipv4`/`ipv6` range 表。
/// 旧实现只 `FROM geoip` —— 写入 `ipv4`/`ipv6` 表的行（v6 demo/镜像数据）在面板里
/// 永远筛不到，表现为「库里有数据、筛选结果为空」。列名差异（ip_start/ip_end vs
/// start/end、缺 dc）在子查询里对齐。
pub fn filter_prefixes(
    conn: &Connection,
    country: Option<&str>,
    isp: Option<&str>,
    cloud: Option<&str>,
    limit: usize,
) -> Result<Vec<FilterRow>> {
    let lim = limit.min(500);
    let c = country.unwrap_or("").to_ascii_lowercase();
    let i = isp.unwrap_or("").to_ascii_lowercase();
    let cl = cloud.unwrap_or("").to_ascii_lowercase();
    // 过滤下推到 SQL。原实现是 `ORDER BY weight DESC LIMIT 5000` 之后再在 Rust 里
    // 按 country/isp/cloud 过滤 —— 命中的行只要排在权重前 5000 之外就被**静默截断**
    // （面板显示「没有结果」，其实数据存在）。这里的 LIMIT 作用在过滤后的结果集上。
    // 大小写：SQLite 的 LIKE 对 ASCII 不区分大小写（等价于原来的 to_ascii_lowercase
    // 包含匹配）；lower() 只为把意图写死，非 ASCII 与原来一样不做大小写折叠。
    let where_clause = "WHERE (?1 = ''
                 OR lower(COALESCE(country, '')) LIKE '%' || ?1 || '%' ESCAPE '\\'
                 OR lower(COALESCE(province, '')) LIKE '%' || ?1 || '%' ESCAPE '\\'
                 OR lower(COALESCE(city, '')) LIKE '%' || ?1 || '%' ESCAPE '\\')
           AND (?2 = '' OR lower(COALESCE(isp, '')) LIKE '%' || ?2 || '%' ESCAPE '\\')
           AND (?3 = '' OR lower(COALESCE(cloud_provider, '')) LIKE '%' || ?3 || '%' ESCAPE '\\')";
    let sql = format!(
        "SELECT prefix, country, province, city, isp, cloud_provider, weight FROM (
             SELECT COALESCE(prefix, ip_start || '-' || ip_end) AS prefix,
                    COALESCE(country, '') AS country, COALESCE(province, '') AS province,
                    COALESCE(city, '') AS city, COALESCE(isp, '') AS isp,
                    COALESCE(cloud_provider, '') AS cloud_provider,
                    COALESCE(weight, 0) AS weight
               FROM geoip {where_clause}
             UNION ALL
             SELECT COALESCE(prefix, start || '-' || end), COALESCE(country, ''),
                    COALESCE(province, ''), COALESCE(city, ''), COALESCE(isp, ''),
                    COALESCE(cloud_provider, ''), COALESCE(weight, 0)
               FROM ipv4 {where_clause}
             UNION ALL
             SELECT COALESCE(prefix, start || '-' || end), COALESCE(country, ''),
                    COALESCE(province, ''), COALESCE(city, ''), COALESCE(isp, ''),
                    COALESCE(cloud_provider, ''), COALESCE(weight, 0)
               FROM ipv6 {where_clause}
         ) ORDER BY weight DESC LIMIT ?4"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(
        rusqlite::params![
            like_escape(&c),
            like_escape(&i),
            like_escape(&cl),
            lim as i64
        ],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, i64>(6)?,
            ))
        },
    )?;
    let mut out = Vec::new();
    for row in rows {
        let (prefix, country, province, city, isp, cloud_provider, weight) = row?;
        out.push(FilterRow {
            prefix,
            country,
            province,
            city,
            isp,
            cloud_provider,
            weight,
        });
    }
    Ok(out)
}

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
        let all = filter_prefixes(&conn, None, None, None, 100).unwrap();
        assert!(all.iter().any(|r| r.prefix == "1.2.4.0/24"));
        assert!(all.iter().any(|r| r.prefix == "8.8.8.0/24"), "ipv4 表行必须被筛到");
        assert!(all.iter().any(|r| r.prefix == "2001:db8::/112"), "ipv6 表行必须被筛到");
        let us = filter_prefixes(&conn, Some("us"), None, None, 100).unwrap();
        assert!(us.iter().any(|r| r.city == "Mountain View"));
        assert!(us.iter().any(|r| r.city == "Documentation"));
        assert!(!us.iter().any(|r| r.country == "CN"));
    }
}
