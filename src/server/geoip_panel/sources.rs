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

pub fn load_sources_json(path: &Path) -> Result<String> {
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
