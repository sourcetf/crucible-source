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

/// 尽力而为的 DDL：失败只记 debug，不阻断打开。
///
/// 为什么不能 `?`：这些语句是「建表/建索引/补列」的**迁移**动作，只在库可写时才需要
/// 真正执行。查询侧（`db.rs` 的职责是「打开、索引、只读查询」）在库**只读**时（文件
/// chmod 0444、只读挂载、或按 §23.11/G14 在 staging→原子切换后把 `current/geoip.sqlite`
/// 置只读）应当照常可查——表与索引早已存在，DDL 只是因为拿不到写锁而报
/// `attempt to write a readonly database`。旧实现把它 `?` 上去 ⇒ `db::open` 直接失败 ⇒
/// **每一次 lookup 都返回 error、面板整块不可用**（实测：只读文件上 open 报 Error code 8）。
/// 若 schema 真的缺失，后续真正的查询会给出准确错误，不会被这里吞掉。
fn ddl_best_effort(conn: &Connection, sql: &str, what: &str) {
    if let Err(e) = conn.execute_batch(sql) {
        log::debug!("geoip db DDL skipped ({what}): {e:#}");
    }
}

fn create_range_table(conn: &Connection, name: &str) -> Result<()> {
    ddl_best_effort(
        conn,
        &format!(
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
        ),
        "create range table",
    );
    // 老库的 ipv4/ipv6 建表时还没有数值范围列，CREATE TABLE IF NOT EXISTS 不会补列。
    // 列语义见 iputil::range_numeric_key（Python 侧 geoip_common.range_numeric_key 同义）。
    for col in ["start_i", "end_i"] {
        let _ = conn.execute(&format!("ALTER TABLE {name} ADD COLUMN {col} INTEGER"), []);
    }
    ddl_best_effort(
        conn,
        &format!("CREATE INDEX IF NOT EXISTS idx_{name}_numeric ON {name}(start_i, end_i);"),
        "range numeric index",
    );
    Ok(())
}

pub fn open(path: &Path) -> Result<Connection> {
    let conn = Connection::open(path).with_context(|| format!("open {}", path.display()))?;
    conn.busy_timeout(BUSY_TIMEOUT)
        .context("set sqlite busy_timeout")?;
    ddl_best_effort(
        &conn,
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
        "create geoip table",
    );
    for (col, typ) in MIGRATE_COLS {
        let _ = conn.execute(&format!("ALTER TABLE geoip ADD COLUMN {col} {typ}"), []);
    }
    // §23.8/G13：数值范围索引。covering.rs 的 `load_from_geoip` 用
    // `start_i <= ? AND end_i >= ?` 预过滤，没有这个索引会退化成全表扫描。
    // Python 侧（geoip_common.py）会建同名索引，但由 Rust 首次建库/迁移出来的
    // 库此前没有 —— 与 ipv4/ipv6 两张 range 表的口径不一致。
    ddl_best_effort(
        &conn,
        "CREATE INDEX IF NOT EXISTS idx_geoip_numeric ON geoip(start_i, end_i);",
        "geoip numeric index",
    );
    create_range_table(&conn, "ipv4")?;
    create_range_table(&conn, "ipv6")?;
    Ok(conn)
}

/// Panel metadata DB (hand edits, conflicts, audit, sources, cron).
pub fn open_panel(path: &Path) -> Result<Connection> {
    let conn = Connection::open(path).with_context(|| format!("open panel {}", path.display()))?;
    conn.busy_timeout(BUSY_TIMEOUT)
        .context("set sqlite busy_timeout")?;
    // 同样尽力而为：读侧（covering::merge_pipeline 的 lookup 热路径）只需要读 panel_edits，
    // 不该因为库只读就打不开、把手工覆盖整块静默跳过（见 ddl_best_effort 说明）。
    ddl_best_effort(
        &conn,
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
        "create panel tables",
    );
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

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("crucible_geoip_db_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// 回归：库文件只读（chmod 0444）且**待迁移**（缺 `idx_geoip_numeric`，旧管线库就是
    /// 这样）时，`open()` 必须仍能打开并查询。
    ///
    /// 修复前 `open()` 里的迁移 DDL 用 `?` 上抛：只读文件上 `CREATE INDEX` 触发
    /// `attempt to write a readonly database` ⇒ `db::open` 直接失败 ⇒ 每次 lookup 都返回
    /// `{"status":"error"}`（尽管纯读完全可行）。DDL 改为 best-effort 后恢复为 `status:ok`
    /// （只是那个索引建不出来，仅影响性能）。真机对照：旧二进制同库返回 error，新二进制 ok。
    #[test]
    fn open_survives_readonly_db_needing_index() {
        let dir = tmp_dir("ro");
        let path = dir.join("geoip.sqlite");
        {
            let conn = open(&path).unwrap();
            conn.execute(
                "INSERT INTO geoip(ip_start, ip_end, country) VALUES('10.0.0.0','10.255.255.255','US')",
                [],
            )
            .unwrap();
            // 模拟旧管线建出的库：缺数值范围索引（迁移 DDL 会真的尝试写）。
            conn.execute_batch("DROP INDEX IF EXISTS idx_geoip_numeric")
                .unwrap();
        }
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_readonly(true);
        std::fs::set_permissions(&path, perms).unwrap();
        let conn = open(&path).expect("read-only DB needing index migration must still open");
        let n: i64 = conn
            .query_row("SELECT count(*) FROM geoip", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1, "read-only DB must remain queryable");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
