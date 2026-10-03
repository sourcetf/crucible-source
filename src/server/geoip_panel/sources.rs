//! GeoIP source metadata (`SOURCES.json` mirror in panel DB).

use anyhow::{Context, Result};
use rusqlite::Connection;
use std::path::Path;

#[derive(Clone, Debug, Default)]
pub struct SourceRow {
    pub name: String,
    pub weight: i64,
    pub enabled: bool,
    pub url: String,
    pub last_commit: String,
    pub last_unix: i64,
}

/// SOURCES.json 体积上限（真实文件仅几 KB）。见 [`load_sources_json`] 的说明。
const MAX_SOURCES_JSON: u64 = 8 * 1024 * 1024;

/// 读 SOURCES.json 原文。
///
/// 上限不是为了对抗攻击者，而是防「无界读」把一次面板请求变成大内存分配：
/// 这个文件是离线管线产物，写坏/被替换成超大文件时，`read_to_string` 会按需
/// 分配整个文件大小（在 tokio worker 上）——本机 95% 磁盘、只有 2 条 worker，
/// 一次大分配就可能拖垮整站。与 `ssl_material::load_bytes` 同一策略（先查大小）。
pub fn load_sources_json(path: &Path) -> Result<String> {
    let md = std::fs::metadata(path)
        .with_context(|| format!("stat {}", path.display()))?;
    if md.len() > MAX_SOURCES_JSON {
        anyhow::bail!(
            "SOURCES.json too large ({} bytes, cap {}): {}",
            md.len(),
            MAX_SOURCES_JSON,
            path.display()
        );
    }
    Ok(std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?)
}

pub fn list_sources(conn: &Connection) -> Result<Vec<SourceRow>> {
    let mut stmt = conn.prepare(
        "SELECT name,
                COALESCE(weight, 50),
                COALESCE(enabled, 1),
                COALESCE(url, ''),
                COALESCE(last_commit, ''),
                COALESCE(last_unix, 0)
         FROM panel_sources
         ORDER BY name",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(SourceRow {
            name: row.get(0)?,
            weight: row.get(1)?,
            enabled: row.get::<_, i64>(2)? != 0,
            url: row.get(3)?,
            last_commit: row.get(4)?,
            last_unix: row.get(5)?,
        })
    })?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

pub fn record_source_refresh(
    conn: &Connection,
    name: &str,
    weight: i64,
    commit_unix: i64,
    last_commit: &str,
) -> Result<()> {
    conn.execute(
        "INSERT INTO panel_sources(name, weight, enabled, last_commit, last_unix)
         VALUES(?1, ?2, 1, ?3, ?4)
         ON CONFLICT(name) DO UPDATE SET
           weight=excluded.weight,
           last_commit=excluded.last_commit,
           last_unix=excluded.last_unix",
        rusqlite::params![name, weight, last_commit, commit_unix],
    )?;
    Ok(())
}
