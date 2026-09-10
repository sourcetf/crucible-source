//! GeoIP 数据源配置（CERNET、RIR、云厂商等）。
use anyhow::Result;
use rusqlite::Connection;
use std::path::Path;

#[derive(Debug, Clone, Default)]
pub struct DataSource {
    pub name: String,
    pub weight: i64,
    pub enabled: bool,
    pub url: String,
    pub last_commit: String,
    pub last_unix: i64,
}

/// 从 panel_sources 表中列出所有数据源
#[derive(Debug, Clone, Default)]
pub struct SourceRow {
    pub name: String,
    pub weight: i64,
    pub enabled: i64,
    pub url: String,
    pub last_commit: String,
    pub last_unix: i64,
}

pub fn available_sources() -> Vec<DataSource> {
    vec![
        DataSource { name: "cernet".to_string(), url: "https://ip.cernet.cn".to_string(), sync_days: 1, active: true },
        DataSource { name: "ripe".to_string(), url: "https://ftp.ripe.net".to_string(), sync_days: 7, active: true },
        DataSource { name: "apnic".to_string(), url: "https://ftp.apnic.net".to_string(), sync_days: 7, active: true },
    ]
}

/// 从 panel 数据库列出数据源
pub fn list_sources(conn: &Connection) -> Result<Vec<SourceRow>> {
    // 确保表存在（可能还未初始化）
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS panel_sources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            weight INTEGER DEFAULT 50,
            enabled INTEGER DEFAULT 1,
            url TEXT,
            last_commit TEXT,
            last_unix INTEGER DEFAULT 0
        )",
    )?;

    let mut stmt = conn.prepare(
        "SELECT name, weight, enabled, url, last_commit, last_unix FROM panel_sources ORDER BY id",
    )?;
    let rows = stmt
        .query_map([], |row| {
            Ok(SourceRow {
                name: row.get(0)?,
                weight: row.get(1)?,
                enabled: row.get(2)?,
                url: row.get(3)?,
                last_commit: row.get(4)?,
                last_unix: row.get(5)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// 从 SOURCES.json 文件加载元数据
pub fn load_sources_json(path: &Path) -> Result<String> {
    let content = std::fs::read_to_string(path)?;
    Ok(content.trim().to_string())
}
