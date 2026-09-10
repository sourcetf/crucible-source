//! GeoIP panel CRUD 操作（实际 OpenBSD 完整实现见远端）。
//!
//! Panel 数据库 schema:
//! - panel_edits: id, prefix, field, value, weight, created_at
//! - panel_conflicts: id, prefix, field, sources, resolved, created_at
//! - panel_sources: id, name, weight, enabled, url, last_commit, last_unix
//! - panel_cron: id, name, schedule, enabled, last_run, last_status
//! - panel_audit: id, action, detail, ts, created_at

use crate::server::geoip_panel::db;
use anyhow::{anyhow, Result};
use rusqlite::{Connection, OptionalExtension};
use std::path::Path;

/// GeoIP 前缀查询结果行
#[derive(Debug, Clone)]
pub struct PrefixRow {
    pub prefix: String,
    pub country: String,
    pub province: String,
    pub city: String,
    pub isp: String,
    pub cloud_provider: String,
    pub weight: i64,
}

/// 过滤并返回匹配条件的前缀列表
pub fn filter_prefixes(
    conn: &Connection,
    country: Option<&str>,
    isp: Option<&str>,
    cloud: Option<&str>,
    limit: usize,
) -> Result<Vec<PrefixRow>> {
    let country_filter = country.unwrap_or("");
    let isp_filter = isp.unwrap_or("");
    let cloud_filter = cloud.unwrap_or("");

    let mut stmt = conn.prepare(&format!(
        "SELECT prefix, country, province, city, isp, cloud_provider, weight \
         FROM geoip WHERE {} LIMIT ?",
        if country_filter.is_empty() && isp_filter.is_empty() && cloud_filter.is_empty() {
            "1=1".to_string()
        } else {
            let mut conditions = Vec::new();
            if !country_filter.is_empty() {
                conditions.push(format!("country LIKE '%{}%'", country_filter.replace('\'', "''")));
            }
            if !isp_filter.is_empty() {
                conditions.push(format!("isp LIKE '%{}%'", isp_filter.replace('\'', "''")));
            }
            if !cloud_filter.is_empty() {
                conditions.push(format!("cloud_provider LIKE '%{}%'", cloud_filter.replace('\'', "''")));
            }
            conditions.join(" AND ")
        }
    ))?;

    let rows: Vec<PrefixRow> = stmt
        .query_map((limit,), |row| {
            Ok(PrefixRow {
                prefix: row.get(0)?,
                country: row.get(1)?,
                province: row.get(2)?,
                city: row.get(3)?,
                isp: row.get(4)?,
                cloud_provider: row.get(5)?,
                weight: row.get(6)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(rows)
}

/// 列出未解决的冲突
pub fn list_conflicts(conn: &Connection) -> Result<Vec<(i64, String, String, String)>> {
    let mut stmt = conn.prepare(
        "SELECT id, prefix, field, sources FROM panel_conflicts WHERE resolved = 0",
    )?;
    let rows = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// 插入或更新编辑记录
pub fn upsert_edit(
    conn: &Connection,
    prefix: &str,
    field: &str,
    value: &str,
    weight: i64,
) -> Result<()> {
    conn.execute(
        "INSERT INTO panel_edits (prefix, field, value, weight) VALUES (?1, ?2, ?3, ?4) \
         ON CONFLICT(prefix, field) DO UPDATE SET value = excluded.value, weight = excluded.weight",
        (prefix, field, value, weight),
    )?;
    Ok(())
}

/// 列出编辑记录（按 id 降序）
pub fn list_edits(conn: &Connection, limit: usize) -> Result<Vec<(i64, String, String, String, i64)>> {
    let mut stmt = conn.prepare(
        "SELECT id, prefix, field, value, weight FROM panel_edits ORDER BY id DESC LIMIT ?"
    )?;
    let rows = stmt
        .query_map((limit,), |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// 删除编辑记录
pub fn delete_edit(conn: &Connection, id: i64) -> Result<bool> {
    let affected = conn.execute("DELETE FROM panel_edits WHERE id = ?", [id])?;
    Ok(affected > 0)
}

/// 解决冲突（标记为已解决）
pub fn resolve_conflict(conn: &Connection, id: i64) -> Result<bool> {
    let affected = conn.execute(
        "UPDATE panel_conflicts SET resolved = 1 WHERE id = ?",
        [id],
    )?;
    Ok(affected > 0)
}

/// 列出审计日志
pub fn list_audit(conn: &Connection, limit: usize) -> Result<Vec<(i64, String, String, i64)>> {
    let mut stmt = conn.prepare(
        "SELECT id, action, detail, ts FROM panel_audit ORDER BY id DESC LIMIT ?"
    )?;
    let rows = stmt
        .query_map((limit,), |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// 列出 cron 任务
pub fn list_cron(conn: &Connection) -> Result<Vec<(i64, String, String, i64, i64)>> {
    let mut stmt = conn.prepare(
        "SELECT id, name, schedule, enabled, last_run FROM panel_cron"
    )?;
    let rows = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// 插入或更新 cron 任务
pub fn upsert_cron(conn: &Connection, name: &str, schedule: &str, enabled: bool) -> Result<()> {
    conn.execute(
        "INSERT INTO panel_cron (name, schedule, enabled) VALUES (?1, ?2, ?3) \
         ON CONFLICT(name) DO UPDATE SET schedule = excluded.schedule, enabled = excluded.enabled",
        (name, schedule, if enabled { 1i64 } else { 0i64 }),
    )?;
    Ok(())
}

/// 设置数据源状态
pub fn set_source(
    conn: &Connection,
    name: &str,
    enabled: Option<bool>,
    weight: Option<i64>,
) -> Result<()> {
    let mut query = "UPDATE panel_sources SET ".to_string();
    let mut sets = Vec::new();
    let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

    if let Some(e) = enabled {
        sets.push("enabled = ?".to_string());
        params.push(Box::new(if e { 1i64 } else { 0i64 }));
    }
    if let Some(w) = weight {
        sets.push("weight = ?".to_string());
        params.push(Box::new(w));
    }
    query.push_str(&sets.join(", "));
    if sets.is_empty() {
        return Ok(());
    }
    query.push_str(" WHERE name = ?");
    params.push(Box::new(name));

    conn.execute(&query, rusqlite::params_from_iter(params.into_iter()))?;
    Ok(())
}

/// 启动 GeoIP 更新脚本（后台运行）
pub fn spawn_geoip_update(root: &Path) -> Result<()> {
    let script = root.join("scripts/geoip_update.sh");
    if !script.exists() {
        // 在无脚本时，尝试运行占位操作
        return Ok(());
    }

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let mut cmd = std::process::Command::new("sh");
        cmd.arg(&script);
        let child = cmd.spawn()?;
        log::info!("spawned geoip_update.sh with pid {}", child.id());
        Ok(())
    }
    #[cfg(not(unix))]
    {
        Err(anyhow!("spawn_geoip_update: Unix only"))
    }
}

/// 获取 covering 表中的指定字段值
/// 字段名经过白名单校验防止 SQL 注入
pub fn get_covering_field(
    conn: &Connection,
    source: &str,
    prefix: &str,
    field: &str,
) -> Result<Option<String>> {
    // 白名单字段 - 防止 SQL 注入
    let allowed_fields = [
        "country", "province", "city", "district", "isp", "asn", "as_org",
        "cloud_provider", "cloud_region", "cloud_service", "hosting",
        "division_code", "dc", "bits", "weight", "source", "commit_unix",
    ];
    if !allowed_fields.contains(&field) {
        return Err(anyhow!("invalid field: {}", field));
    }

    Ok(conn.query_row(
        &format!("SELECT {} FROM covering WHERE source = ? AND prefix = ? LIMIT 1", field),
        [source, prefix],
        |row| row.get::<_, String>(0),
    )
    .optional()?)
}

/// 列出可用操作名称
pub fn list_ops() -> Vec<String> {
    vec![
        "filter_prefixes",
        "list_conflicts",
        "upsert_edit",
        "list_edits",
        "delete_edit",
        "resolve_conflict",
        "list_audit",
        "list_cron",
        "upsert_cron",
        "set_source",
        "spawn_geoip_update",
        "get_covering_field",
    ].iter().map(|s| s.to_string()).collect()
}