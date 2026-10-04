//! SQLite GeoIP database — §23 schema (geoip + ipv4/ipv6 + e_* epochs).

use anyhow::{Context, Result};
use rusqlite::Connection;
use std::path::Path;

/// 与 DNS 库（`dns/mod.rs` 的 5s）同口径：离线更新脚本（geoip_update.sh /
/// geoip_merge.py）会并发写同一个库，面板 lookup/edit 撞上写锁时若不等待，
/// 会立刻 SQLITE_BUSY —— merge_pipeline 里 `if let Ok(panel)` 会把整块手工覆盖
/// 静默跳过（打开失败也不落日志），表现为「覆盖列表有、lookup 不生效」。
const BUSY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

const MIGRATE_COLS: &[(&str, &str)] = &[
    ("prefix", "TEXT"),
    ("bits", "INTEGER DEFAULT 0"),
    ("weight", "INTEGER DEFAULT 0"),
    ("asn", "TEXT"),
    ("as_org", "TEXT"),
    ("dc", "TEXT"),
    ("net_org", "TEXT"),
    ("cloud_provider", "TEXT"),
    ("cloud_region", "TEXT"),
    ("cloud_service", "TEXT"),
    ("hosting", "TEXT"),
    ("division_code", "TEXT"),
    ("district", "TEXT"),
    ("province", "TEXT"),
    ("source", "TEXT"),
    ("start_i", "INTEGER"),
    ("end_i", "INTEGER"),
    ("e_country", "INTEGER DEFAULT 0"),
    ("e_province", "INTEGER DEFAULT 0"),
    ("e_city", "INTEGER DEFAULT 0"),
    ("e_district", "INTEGER DEFAULT 0"),
    ("e_isp", "INTEGER DEFAULT 0"),
    ("e_asn", "INTEGER DEFAULT 0"),
    ("e_as_org", "INTEGER DEFAULT 0"),
    ("e_net_org", "INTEGER DEFAULT 0"),
    ("e_cloud_provider", "INTEGER DEFAULT 0"),
    ("e_cloud_region", "INTEGER DEFAULT 0"),
    ("e_cloud_service", "INTEGER DEFAULT 0"),
    ("e_hosting", "INTEGER DEFAULT 0"),
    ("commit_unix", "INTEGER DEFAULT 0"),
];

fn create_range_table(conn: &Connection, name: &str) -> Result<()> {
    conn.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS {name} (
            start TEXT NOT NULL,
            end TEXT NOT NULL,
            bits INTEGER DEFAULT 0,
            weight INTEGER DEFAULT 0,
            country TEXT,
            province TEXT,
            region TEXT,
            city TEXT,
            district TEXT,
            isp TEXT,
            asn TEXT,
            as_org TEXT,
            net_org TEXT,
            cloud_provider TEXT,
            cloud_region TEXT,
            cloud_service TEXT,
            hosting TEXT,
            division_code TEXT,
            prefix TEXT,
            source TEXT,
            e_country INTEGER DEFAULT 0,
            e_province INTEGER DEFAULT 0,
            e_city INTEGER DEFAULT 0,
            e_district INTEGER DEFAULT 0,
            e_isp INTEGER DEFAULT 0,
            e_asn INTEGER DEFAULT 0,
            e_as_org INTEGER DEFAULT 0,
            e_net_org INTEGER DEFAULT 0,
            e_cloud_provider INTEGER DEFAULT 0,
            e_cloud_region INTEGER DEFAULT 0,
            e_cloud_service INTEGER DEFAULT 0,
            e_hosting INTEGER DEFAULT 0,
            commit_unix INTEGER DEFAULT 0,
            start_i INTEGER,
            end_i INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_{name}_start ON {name}(start);
        CREATE INDEX IF NOT EXISTS idx_{name}_range ON {name}(start, end);"
    ))?;
    // 老库的 ipv4/ipv6 建表时还没有数值范围列，CREATE TABLE IF NOT EXISTS 不会补列。
    // 列语义见 iputil::range_numeric_key（Python 侧 geoip_common.range_numeric_key 同义）。
    for col in ["start_i", "end_i"] {
        let _ = conn.execute(&format!("ALTER TABLE {name} ADD COLUMN {col} INTEGER"), []);
    }
    conn.execute_batch(&format!(
        "CREATE INDEX IF NOT EXISTS idx_{name}_numeric ON {name}(start_i, end_i);"
    ))?;
    Ok(())
}

pub fn open(path: &Path) -> Result<Connection> {
    let conn = Connection::open(path).with_context(|| format!("open {}", path.display()))?;
    conn.busy_timeout(BUSY_TIMEOUT)
        .context("set sqlite busy_timeout")?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS geoip (
            ip_start TEXT NOT NULL,
            ip_end TEXT NOT NULL,
            country TEXT,
            region TEXT,
            province TEXT,
            city TEXT,
            district TEXT,
            isp TEXT,
            dc TEXT,
            asn TEXT,
            as_org TEXT,
            cloud_provider TEXT,
            cloud_region TEXT,
            cloud_service TEXT,
            hosting TEXT,
            division_code TEXT,
            prefix TEXT,
            bits INTEGER DEFAULT 0,
            weight INTEGER DEFAULT 0,
            source TEXT,
            e_country INTEGER DEFAULT 0,
            e_province INTEGER DEFAULT 0,
            e_city INTEGER DEFAULT 0,
            e_district INTEGER DEFAULT 0,
            e_isp INTEGER DEFAULT 0,
            e_asn INTEGER DEFAULT 0,
            e_as_org INTEGER DEFAULT 0,
            e_cloud_provider INTEGER DEFAULT 0,
            e_cloud_region INTEGER DEFAULT 0,
            e_cloud_service INTEGER DEFAULT 0,
            e_hosting INTEGER DEFAULT 0,
            commit_unix INTEGER DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_geoip_start ON geoip(ip_start);
        CREATE INDEX IF NOT EXISTS idx_geoip_range ON geoip(ip_start, ip_end);",
    )?;
    for (col, typ) in MIGRATE_COLS {
        let _ = conn.execute(&format!("ALTER TABLE geoip ADD COLUMN {col} {typ}"), []);
    }
    // §23.8/G13：数值范围索引。covering.rs 的 `load_from_geoip` 用
    // `start_i <= ? AND end_i >= ?` 预过滤，没有这个索引会退化成全表扫描。
    // Python 侧（geoip_common.py）会建同名索引，但由 Rust 首次建库/迁移出来的
    // 库此前没有 —— 与 ipv4/ipv6 两张 range 表的口径不一致。
    conn.execute_batch(
        "CREATE INDEX IF NOT EXISTS idx_geoip_numeric ON geoip(start_i, end_i);",
    )?;
    create_range_table(&conn, "ipv4")?;
    create_range_table(&conn, "ipv6")?;
    Ok(conn)
}

/// Panel metadata DB (hand edits, conflicts, audit, sources, cron).
pub fn open_panel(path: &Path) -> Result<Connection> {
    let conn = Connection::open(path).with_context(|| format!("open panel {}", path.display()))?;
    conn.busy_timeout(BUSY_TIMEOUT)
        .context("set sqlite busy_timeout")?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS panel_edits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            prefix TEXT NOT NULL,
            field TEXT NOT NULL,
            value TEXT NOT NULL,
            weight INTEGER DEFAULT 200,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS panel_conflicts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            prefix TEXT NOT NULL,
            field TEXT NOT NULL,
            sources TEXT NOT NULL,
            resolved INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS panel_sources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            weight INTEGER DEFAULT 50,
            enabled INTEGER DEFAULT 1,
            url TEXT,
            last_commit TEXT,
            last_unix INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS panel_cron (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            schedule TEXT NOT NULL,
            enabled INTEGER DEFAULT 1,
            last_run INTEGER DEFAULT 0,
            last_status TEXT
        );
        CREATE TABLE IF NOT EXISTS panel_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            detail TEXT,
            ts INTEGER DEFAULT (strftime('%s','now')),
            created_at TEXT DEFAULT (datetime('now'))
        );",
    )?;
    // Migrate older DBs that lack UNIQUE/ts columns.
    let _ = conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_panel_cron_name ON panel_cron(name)",
        [],
    );
    let _ = conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_panel_edits_pf ON panel_edits(prefix, field)",
        [],
    );
    let _ = conn.execute("ALTER TABLE panel_audit ADD COLUMN ts INTEGER DEFAULT 0", []);
    Ok(conn)
}
