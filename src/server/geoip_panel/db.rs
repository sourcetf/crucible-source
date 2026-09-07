//! SQLite GeoIP database — §23 schema (geoip + ipv4/ipv6 + e_* epochs).

use anyhow::{Context, Result};
use rusqlite::Connection;
use std::path::Path;

const MIGRATE_COLS: &[(&str, &str)] = &[
    ("prefix", "TEXT"),
    ("bits", "INTEGER DEFAULT 0"),
    ("weight", "INTEGER DEFAULT 0"),
    ("asn", "TEXT"),
    ("as_org", "TEXT"),
    ("cloud_provider", "TEXT"),
    ("cloud_region", "TEXT"),
    ("cloud_service", "TEXT"),
    ("hosting", "TEXT"),
    ("division_code", "TEXT"),
    ("district", "TEXT"),
    ("province", "TEXT"),
    ("source", "TEXT"),
    ("e_country", "INTEGER DEFAULT 0"),
    ("e_province", "INTEGER DEFAULT 0"),
    ("e_city", "INTEGER DEFAULT 0"),
    ("e_district", "INTEGER DEFAULT 0"),
    ("e_isp", "INTEGER DEFAULT 0"),
    ("e_asn", "INTEGER DEFAULT 0"),
    ("e_as_org", "INTEGER DEFAULT 0"),
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
            e_cloud_provider INTEGER DEFAULT 0,
            e_cloud_region INTEGER DEFAULT 0,
            e_cloud_service INTEGER DEFAULT 0,
            e_hosting INTEGER DEFAULT 0,
            commit_unix INTEGER DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_{name}_start ON {name}(start);
        CREATE INDEX IF NOT EXISTS idx_{name}_range ON {name}(start, end);"
    ))?;
    Ok(())
}

pub fn open(path: &Path) -> Result<Connection> {
    let conn = Connection::open(path).with_context(|| format!("open {}", path.display()))?;
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
    create_range_table(&conn, "ipv4")?;
    create_range_table(&conn, "ipv6")?;
    Ok(conn)
}

/// Panel metadata DB (hand edits, conflicts, audit, sources, cron).
pub fn open_panel(path: &Path) -> Result<Connection> {
    let conn = Connection::open(path).with_context(|| format!("open panel {}", path.display()))?;
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
