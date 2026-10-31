#!/usr/bin/env python3
"""Shared GeoIP offline helpers (schema, covering merge, layer import)."""
from __future__ import annotations

import ipaddress
import json
import os
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# 路径覆盖：离线更新链（geoip_update.sh）可以用环境变量把整条链指到非生产目录，
# 便于 staging / 测试 / 原子切换验证（生产默认值逐字节不变）。Rust 侧对应的
# 覆盖变量是 CRUCIBLE_GEOIP_PANEL_DB / CRUCIBLE_GEOIP_PANEL。
DEFAULT_DB = os.environ.get("CRUCIBLE_GEOIP_DB") or "data/geoip/current/geoip.sqlite"
SOURCES_JSON = os.environ.get("CRUCIBLE_GEOIP_SOURCES") or "data/geoip/current/SOURCES.json"
PANEL_DB = os.environ.get("CRUCIBLE_GEOIP_PANEL_DB") or "data/geoip/panel.sqlite"
PANEL_TOML = (
    os.environ.get("CRUCIBLE_GEOIP_PANEL")
    or os.environ.get("CRUCIBLE_GEOIP_PANEL_TOML")
    or "data/geoip/panel.toml"
)

# G-10/G-17：Rust `covering::DEFAULT_PATH_PRIORITY_GAIN` 必须与此一致。
DEFAULT_PATH_PRIORITY_GAIN = 10


def data_root() -> Path:
    """数据根目录：`CRUCIBLE_GEOIP_DATA_ROOT` 覆盖，默认 `data/geoip`（相对 CWD）。

    离线脚本里大量 `data/geoip/sources/...`、`data/geoip/current/...` 的硬编码
    在 staging/测试目录下会指回生产路径。更新链导出该变量后，这里统一解析，
    避免每个脚本各自猜 CWD。
    """
    return Path(os.environ.get("CRUCIBLE_GEOIP_DATA_ROOT") or "data/geoip")


def sources_dir() -> Path:
    return data_root() / "sources"


def current_dir() -> Path:
    return data_root() / "current"


def logs_dir() -> Path:
    return data_root() / "logs"

# Rust 侧用 i64 saturating 运算；Python 整数无界，必须显式模拟，否则极端权重下
# 两侧的 (weight + bits*gain, epoch, bits) 评分会分叉（golden 向量把这条钉死）。
_I64_MAX = (1 << 63) - 1
_I64_MIN = -(1 << 63)


def _sat_i64(v: int) -> int:
    if v > _I64_MAX:
        return _I64_MAX
    if v < _I64_MIN:
        return _I64_MIN
    return v


def _sat_add(a: int, b: int) -> int:
    return _sat_i64(a + b)


def _sat_mul(a: int, b: int) -> int:
    return _sat_i64(a * b)


def load_panel_settings(panel_path: str | Path | None = None) -> dict[str, Any]:
    """读 `data/geoip/panel.toml`（面板设置，优先级高于 config.toml `[geoip]`）。

    与 Rust `geoip_panel::toml_store` 同一文件；离线脚本只需要路径增益等少数键。
    文件缺失/不可读/非法时回落默认值（离线脚本不应因为一份坏面板配置而整体失败）。
    """
    import os

    if panel_path is None:
        panel_path = (
            os.environ.get("CRUCIBLE_GEOIP_PANEL")
            or os.environ.get("CRUCIBLE_GEOIP_PANEL_TOML")
            or PANEL_TOML
        )
    path = Path(panel_path)
    if not path.is_file():
        return {}
    try:
        import tomllib

        with path.open("rb") as f:
            data = tomllib.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def load_server_geoip_gain(config_path: str | Path | None = None) -> int:
    """读 `config.toml [geoip] path_priority_gain`（优先级低于 panel.toml）。

    运行期 Rust 的优先级是 `panel.toml > config.toml [geoip] > 默认 10`。离线
    Python 若只看 panel.toml，就会出现「config.toml 写了 50、运行期用 50、离线
    校验仍按 10」的口径分叉（G-10）。配置文件路径与 `webserver --config` 一致：
    `CRUCIBLE_CONFIG` 环境变量，缺省为当前目录的 `config.toml`。
    """
    import os

    if config_path is None:
        config_path = os.environ.get("CRUCIBLE_CONFIG") or "config.toml"
    path = Path(config_path)
    if not path.is_file():
        return DEFAULT_PATH_PRIORITY_GAIN
    try:
        import tomllib

        with path.open("rb") as f:
            data = tomllib.load(f)
        geoip = data.get("geoip") if isinstance(data, dict) else None
        raw = geoip.get("path_priority_gain") if isinstance(geoip, dict) else None
        return int(raw) if raw is not None else DEFAULT_PATH_PRIORITY_GAIN
    except Exception:
        return DEFAULT_PATH_PRIORITY_GAIN


def load_path_priority_gain(panel_path: str | Path | None = None) -> int:
    """当前生效的路径优先级增益：`panel.toml > config.toml [geoip] > 默认 10`。

    与 Rust `Config::load → apply_geoip_panel_settings` 同一优先级；`merge_covering`
    不传 `path_priority_gain` 时用本函数，保证离线合并与运行期选同一行。
    """
    raw = load_panel_settings(panel_path).get("path_priority_gain")
    if raw is not None:
        try:
            return int(raw)
        except (TypeError, ValueError):
            pass
    return load_server_geoip_gain()

EPOCH_FIELDS = (
    "country",
    "province",
    "region",
    "city",
    "district",
    "isp",
    "asn",
    "as_org",
    "net_org",
    "cloud_provider",
    "cloud_region",
    "cloud_service",
    "hosting",
    "dc",
    "division_code",
)

SEED_RANGES: list[tuple[str, str, dict[str, str]]] = [
    ("1.2.4.8", "1.2.4.8", {"country": "CN", "province": "北京", "region": "BJ", "city": "Beijing", "isp": "DemoISP", "asn": "4134", "as_org": "CHINANET-BACKBONE", "dc": ""}),
    ("192.0.2.0", "192.0.2.255", {"country": "US", "region": "CA", "city": "Los Angeles", "isp": "ExampleNet", "dc": "LAX1"}),
    ("198.51.100.0", "198.51.100.255", {"country": "DE", "region": "BE", "city": "Berlin", "isp": "SampleCo", "dc": "FRA2"}),
    ("203.0.113.0", "203.0.113.255", {"country": "JP", "region": "13", "city": "Tokyo", "isp": "TestASN", "dc": "NRT1"}),
]


@dataclass
class MergedFields:
    country: str = ""
    province: str = ""
    region: str = ""
    city: str = ""
    district: str = ""
    isp: str = ""
    dc: str = ""
    asn: str = ""
    as_org: str = ""
    # §2.5：net_org = 网段注册公司（inetnum 持有者），≠ as_org（AS 持有者）。
    net_org: str = ""
    cloud_provider: str = ""
    cloud_region: str = ""
    cloud_service: str = ""
    hosting: str = ""
    division_code: str = ""
    prefix: str = ""
    bits: int = 0
    weight: int = 0
    commit_unix: int = 0
    prefixes_merged: int = 0
    extra: dict[str, str] = field(default_factory=dict)


def _clean_ip_text(v: object) -> str:
    """去掉 NUL 填充与空白（历史写入用过定长 char 列）。"""
    return str(v or "").strip().rstrip("\x00").strip()


def range_numeric_key(ip_text: str) -> int | None:
    """ipv4/ipv6 range 表 `start_i`/`end_i` 的数值键；解析失败返回 None。

    必须与 Rust `iputil::range_numeric_key` **逐位一致**，否则新导入的行查不到。
    IPv4：地址的 u32 值。IPv6：128 位装不进 SQLite 的 i64，取高 64 位并按
    `hi ^ 2^63` 映射进有符号 i64 —— 该映射保序，故 `start_i <= key <= end_i`
    是「落在区间内」的必要条件（能走索引），精确的 128 位判定在 Rust 侧完成。
    """
    try:
        addr = ipaddress.ip_address(_clean_ip_text(ip_text))
    except ValueError:
        return None
    # 必须按**地址族**分支，不能按数值大小（`::`、`::1` 数值很小但属于 IPv6）。
    if addr.version == 4:
        return int(addr)
    x = (int(addr) >> 64) ^ (1 << 63)
    return x - (1 << 64) if x >= (1 << 63) else x


def _create_range_table(conn: sqlite3.Connection, name: str) -> None:
    conn.execute(
        f"""CREATE TABLE IF NOT EXISTS {name} (
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
            e_region INTEGER DEFAULT 0,
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
            e_dc INTEGER DEFAULT 0,
            e_division_code INTEGER DEFAULT 0,
            commit_unix INTEGER DEFAULT 0,
            start_i INTEGER,
            end_i INTEGER
        )"""
    )
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{name}_start ON {name}(start)")
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{name}_range ON {name}(start, end)")
    # 老库建表时没有数值范围列；CREATE TABLE IF NOT EXISTS 不补列，需显式 ALTER。
    for col in ("start_i", "end_i"):
        try:
            conn.execute(f"ALTER TABLE {name} ADD COLUMN {col} INTEGER")
        except sqlite3.OperationalError:
            pass
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{name}_numeric ON {name}(start_i, end_i)")


def _backfill_range_numeric(conn: sqlite3.Connection, name: str) -> int:
    """回填 range 表的 start_i/end_i（幂等：只填空值），返回行数。"""
    try:
        rows = conn.execute(
            f"SELECT rowid, start, end FROM {name} WHERE start_i IS NULL OR end_i IS NULL"
        ).fetchall()
    except sqlite3.OperationalError:
        return 0
    upd = []
    for rowid, s, e in rows:
        si = range_numeric_key(s)
        ei = range_numeric_key(e)
        if si is None or ei is None:
            continue
        upd.append((si, ei, rowid))
    if upd:
        conn.executemany(f"UPDATE {name} SET start_i = ?, end_i = ? WHERE rowid = ?", upd)
    return len(upd)


def _backfill_numeric(conn: sqlite3.Connection) -> int:
    """把 start_i/end_i 空值补成真实整数，返回补的行数。

    幂等：只处理空值，已填的（含 upsert_range 新写的）不动。
    """
    cur = conn.execute(
        "SELECT rowid, ip_start, ip_end FROM geoip WHERE start_i IS NULL OR end_i IS NULL"
    )
    rows = cur.fetchall()
    if not rows:
        return 0
    upd: list[tuple[int, int, int]] = []
    for rowid, s, e in rows:
        # 用 range_numeric_key 而不是 int(ip_address)：主表理论上只存 v4，但历史
        # 导入/手工 SQL 可能塞进 v6 行；`int(v6)` 超出 SQLite INTEGER（i64）范围，
        # 绑定时会抛 OverflowError 把整个 init_schema 打断。range_numeric_key 对
        # v6 走「高 64 位保序映射」，与 Rust 查询侧同一把标尺。
        si = range_numeric_key(s)
        ei = range_numeric_key(e)
        if si is None or ei is None:
            continue
        upd.append((si, ei, rowid))
    if upd:
        conn.executemany("UPDATE geoip SET start_i = ?, end_i = ? WHERE rowid = ?", upd)
        conn.commit()
    return len(upd)


def init_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """CREATE TABLE IF NOT EXISTS geoip (
            ip_start TEXT NOT NULL,
            ip_end TEXT NOT NULL,
            bits INTEGER DEFAULT 0,
            weight INTEGER DEFAULT 0,
            prefix TEXT,
            country TEXT, region TEXT, city TEXT, isp TEXT, dc TEXT,
            province TEXT, district TEXT,
            asn TEXT, as_org TEXT,
            cloud_provider TEXT, cloud_region TEXT, cloud_service TEXT,
            hosting TEXT, division_code TEXT, source TEXT,
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
        )"""
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_geoip_start ON geoip(ip_start)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_geoip_range ON geoip(ip_start, ip_end)")
    for col, typ in (
        ("province", "TEXT"),
        ("district", "TEXT"),
        ("asn", "TEXT"),
        ("as_org", "TEXT"),
        ("net_org", "TEXT"),
        ("cloud_provider", "TEXT"),
        ("cloud_region", "TEXT"),
        ("cloud_service", "TEXT"),
        ("hosting", "TEXT"),
        ("division_code", "TEXT"),
        ("source", "TEXT"),
        ("e_country", "INTEGER DEFAULT 0"),
        ("e_province", "INTEGER DEFAULT 0"),
        ("e_region", "INTEGER DEFAULT 0"),
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
        ("e_dc", "INTEGER DEFAULT 0"),
        ("e_division_code", "INTEGER DEFAULT 0"),
        ("commit_unix", "INTEGER DEFAULT 0"),
        ("bits", "INTEGER DEFAULT 0"),
        ("weight", "INTEGER DEFAULT 0"),
        ("prefix", "TEXT"),
    ):
        try:
            conn.execute(f"ALTER TABLE geoip ADD COLUMN {col} {typ}")
        except sqlite3.OperationalError:
            pass
    for col, typ in (("start_i", "INTEGER"), ("end_i", "INTEGER")):
        try:
            conn.execute(f"ALTER TABLE geoip ADD COLUMN {col} {typ}")
        except sqlite3.OperationalError:
            pass
    conn.execute("CREATE INDEX IF NOT EXISTS idx_geoip_numeric ON geoip(start_i, end_i)")
    # 存量回填（幂等：只填空值）。**必须在 Python 里算**：SQLite 的
    # `CAST('1.2.4.0' AS INTEGER)` 只会取前导数字得到 1（不是 16909312），
    # 用它回填等于把整库的数值范围列写成错的。
    _backfill_numeric(conn)
    _create_range_table(conn, "ipv4")
    _create_range_table(conn, "ipv6")
    _backfill_range_numeric(conn, "ipv4")
    _backfill_range_numeric(conn, "ipv6")
    # §2.6：anycast 表——bgptools/anycast-prefixes 与 RIPE anycast 提取写入这里，
    # 查询侧（Rust anycast.rs）读表判定 + 国家票 30% 共识抑制。
    #
    # 必须建 (start,end) 唯一索引：`upsert_anycast` 用的是
    # `INSERT … ON CONFLICT(start, end) DO UPDATE`，而 SQLite 的 UPSERT 只有在
    # (start,end) 上存在 UNIQUE/PK 约束时才合法。旧 schema 只建了普通索引，于是
    # 每次写入都抛 `ON CONFLICT clause does not match any PRIMARY KEY or UNIQUE
    # constraint` —— anycast 表永远为空（RIPE anycast 提取/面板追加全部静默失效）。
    conn.execute(
        """CREATE TABLE IF NOT EXISTS anycast (
            start TEXT NOT NULL,
            end TEXT NOT NULL,
            bits INTEGER DEFAULT 0,
            prefix TEXT,
            source TEXT,
            commit_unix INTEGER DEFAULT 0
        )"""
    )
    for col in ("start_i", "end_i"):
        try:
            conn.execute(f"ALTER TABLE anycast ADD COLUMN {col} INTEGER")
        except sqlite3.OperationalError:
            pass
    # 老库可能已有重复段（普通索引不阻止重复）；先按 (start,end) 去重再做唯一索引。
    conn.execute(
        """DELETE FROM anycast WHERE rowid NOT IN (
               SELECT MIN(rowid) FROM anycast GROUP BY start, end
           )"""
    )
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_anycast_unique ON anycast(start, end)"
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_anycast_range ON anycast(start, end)")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_anycast_numeric ON anycast(start_i, end_i)"
    )
    for rowid, s, e in conn.execute(
        "SELECT rowid, start, end FROM anycast WHERE start_i IS NULL OR end_i IS NULL"
    ).fetchall():
        si = range_numeric_key(s)
        ei = range_numeric_key(e)
        if si is not None and ei is not None:
            conn.execute(
                "UPDATE anycast SET start_i = ?, end_i = ? WHERE rowid = ?",
                (si, ei, rowid),
            )


def upsert_anycast(
    conn: sqlite3.Connection,
    start: str,
    end: str,
    *,
    source: str = "anycast",
    commit_unix: int | None = None,
) -> None:
    """§2.6：写入 anycast 表（幂等：同段重复写以最后一条为准）。"""
    bits = 0
    prefix = f"{start}-{end}"
    try:
        nets = list(
            ipaddress.summarize_address_range(
                ipaddress.ip_address(start), ipaddress.ip_address(end)
            )
        )
        if len(nets) == 1:
            prefix = str(nets[0])
            bits = int(prefix.split("/")[1])
    except ValueError:
        pass
    cu = int(commit_unix if commit_unix is not None else time.time())
    si = range_numeric_key(start)
    ei = range_numeric_key(end)
    conn.execute(
        """INSERT INTO anycast(start, end, bits, prefix, source, commit_unix, start_i, end_i)
           VALUES(?,?,?,?,?,?,?,?)
           ON CONFLICT(start, end) DO UPDATE SET
             bits=excluded.bits, prefix=excluded.prefix,
             source=excluded.source, commit_unix=excluded.commit_unix,
             start_i=excluded.start_i, end_i=excluded.end_i""",
        (start, end, bits, prefix, source, cu, si, ei),
    )


def set_meta_flag(name: str, value: Any = 1) -> None:
    """§3.2：黑名单元标记（ip2region_blacklisted=1 等）落 SOURCES.json 顶层。"""
    path = Path(SOURCES_JSON)
    path.parent.mkdir(parents=True, exist_ok=True)
    meta: dict[str, Any] = {}
    if path.is_file():
        try:
            meta = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            meta = {}
    meta[name] = value
    path.write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def init_panel_schema(conn: sqlite3.Connection) -> None:
    """Panel metadata DB — mirrors Rust `geoip_panel::db::open_panel`.

    Tables: panel_edits, panel_conflicts, panel_sources, panel_cron, panel_audit.
    """
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS panel_edits (
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
        );
        """
    )
    try:
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_panel_cron_name ON panel_cron(name)"
        )
    except sqlite3.OperationalError:
        pass
    try:
        conn.execute("ALTER TABLE panel_audit ADD COLUMN ts INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass


def seed_panel_demo(conn: sqlite3.Connection, *, commit_unix: int | None = None) -> None:
    """Insert demo sources / conflict / cron / audit rows when empty."""
    cu = int(commit_unix if commit_unix is not None else time.time())
    n = conn.execute("SELECT COUNT(*) FROM panel_sources").fetchone()[0]
    if n == 0:
        for name, weight in (
            ("demo-seed", 80),
            ("rir-geofeed", 60),
            ("qqwry", 40),
        ):
            conn.execute(
                """INSERT OR IGNORE INTO panel_sources(name, weight, enabled, url, last_commit, last_unix)
                   VALUES(?,?,1,?,?,?)""",
                (name, weight, "", "demo", cu),
            )
    n = conn.execute("SELECT COUNT(*) FROM panel_conflicts").fetchone()[0]
    if n == 0:
        conn.execute(
            """INSERT INTO panel_conflicts(prefix, field, sources, resolved)
               VALUES(?,?,?,0)""",
            ("8.8.8.0/24", "isp", "demo-seed|rir-geofeed"),
        )
    n = conn.execute("SELECT COUNT(*) FROM panel_cron").fetchone()[0]
    if n == 0:
        conn.execute(
            """INSERT OR IGNORE INTO panel_cron(name, schedule, enabled, last_run, last_status)
               VALUES(?,?,1,0,?)""",
            ("geoip_update", "0 3 * * *", "never"),
        )
    conn.execute(
        "INSERT INTO panel_audit(action, detail, ts) VALUES(?,?,?)",
        ("seed", "geoip_seed_demo panel bootstrap", cu),
    )


def ip_to_int(ip: str) -> int:
    return int(ipaddress.ip_address(ip))


def _covering_select(conn: sqlite3.Connection, table: str, key: int) -> list[sqlite3.Row]:
    """单表 covering 查询（列语义与 Rust `covering.rs` 的 SELECT 逐列一致）。"""
    if table == "geoip":
        cols = """ip_start, ip_end, COALESCE(bits,0) AS bits,
                  COALESCE(weight,0) AS weight, COALESCE(commit_unix,0) AS commit_unix,
                  COALESCE(country,'') AS country,
                  COALESCE(province, region, '') AS province,
                  COALESCE(region,'') AS region, COALESCE(city,'') AS city,
                  COALESCE(district,'') AS district, COALESCE(isp,'') AS isp,
                  COALESCE(dc,'') AS dc, COALESCE(asn,'') AS asn,
                  COALESCE(as_org,'') AS as_org, COALESCE(net_org,'') AS net_org,
                  COALESCE(cloud_provider,'') AS cloud_provider,
                  COALESCE(cloud_region,'') AS cloud_region,
                  COALESCE(cloud_service,'') AS cloud_service,
                  COALESCE(hosting,'') AS hosting,
                  COALESCE(division_code,'') AS division_code,
                  COALESCE(prefix, ip_start || '-' || ip_end) AS prefix,
                  COALESCE(e_country,0) AS e_country, COALESCE(e_province,0) AS e_province,
                  COALESCE(e_region,0) AS e_region, COALESCE(e_city,0) AS e_city,
                  COALESCE(e_district,0) AS e_district, COALESCE(e_isp,0) AS e_isp,
                  COALESCE(e_asn,0) AS e_asn, COALESCE(e_as_org,0) AS e_as_org,
                  COALESCE(e_net_org,0) AS e_net_org,
                  COALESCE(e_cloud_provider,0) AS e_cloud_provider,
                  COALESCE(e_cloud_region,0) AS e_cloud_region,
                  COALESCE(e_cloud_service,0) AS e_cloud_service,
                  COALESCE(e_hosting,0) AS e_hosting,
                  COALESCE(e_dc,0) AS e_dc,
                  COALESCE(e_division_code,0) AS e_division_code"""
        sql = f"""SELECT {cols} FROM geoip
                  WHERE start_i IS NULL OR (start_i <= ? AND end_i >= ?)
                  ORDER BY COALESCE(commit_unix, 0) ASC, COALESCE(weight, 0) ASC,
                           COALESCE(bits, 0) ASC, rowid ASC"""
        return list(conn.execute(sql, (key, key)).fetchall())
    # ipv4/ipv6 range 表：列名 start/end，无 dc 文本列。为与 Rust 的 range SELECT
    # 对齐，dc 返回 ''；province 走 COALESCE(province, region, '')。
    cols = """start AS ip_start, end AS ip_end, COALESCE(bits,0) AS bits,
              COALESCE(weight,0) AS weight, COALESCE(commit_unix,0) AS commit_unix,
              COALESCE(country,'') AS country,
              COALESCE(province, region, '') AS province,
              COALESCE(region,'') AS region, COALESCE(city,'') AS city,
              COALESCE(district,'') AS district, COALESCE(isp,'') AS isp,
              '' AS dc, COALESCE(asn,'') AS asn,
              COALESCE(as_org,'') AS as_org, COALESCE(net_org,'') AS net_org,
              COALESCE(cloud_provider,'') AS cloud_provider,
              COALESCE(cloud_region,'') AS cloud_region,
              COALESCE(cloud_service,'') AS cloud_service,
              COALESCE(hosting,'') AS hosting,
              COALESCE(division_code,'') AS division_code,
              COALESCE(prefix, start || '-' || end) AS prefix,
              COALESCE(e_country,0) AS e_country, COALESCE(e_province,0) AS e_province,
              COALESCE(e_region,0) AS e_region, COALESCE(e_city,0) AS e_city,
              COALESCE(e_district,0) AS e_district, COALESCE(e_isp,0) AS e_isp,
              COALESCE(e_asn,0) AS e_asn, COALESCE(e_as_org,0) AS e_as_org,
              COALESCE(e_net_org,0) AS e_net_org,
              COALESCE(e_cloud_provider,0) AS e_cloud_provider,
              COALESCE(e_cloud_region,0) AS e_cloud_region,
              COALESCE(e_cloud_service,0) AS e_cloud_service,
              COALESCE(e_hosting,0) AS e_hosting,
              COALESCE(e_dc,0) AS e_dc,
              COALESCE(e_division_code,0) AS e_division_code"""
    sql = f"""SELECT {cols} FROM {table}
              WHERE start_i IS NULL OR (start_i <= ? AND end_i >= ?)
              ORDER BY COALESCE(commit_unix, 0) ASC, COALESCE(weight, 0) ASC,
                       COALESCE(bits, 0) ASC, rowid ASC"""
    return list(conn.execute(sql, (key, key)).fetchall())


def load_covering(conn: sqlite3.Connection, ip: str) -> list[sqlite3.Row]:
    conn.row_factory = sqlite3.Row
    # §23.8：必须用数值范围列（start_i/end_i）。按 TEXT 比较点分四段是**错的**——
    # 字符串字典序 ≠ 数值序，两个方向都会漏：
    #   1.2.4.8 落在 1.2.4.0/24 内，但 '1.2.4.255' >= '1.2.4.8' 为假（'2' < '8'）；
    #   9.0.0.1 与 10.0.0.0 之间同理（'9' > '1'）。
    # 同一修复 Rust 侧早已做（covering.rs: load_from_geoip 用 start_i <= ?1 AND end_i >= ?1）。
    #
    # G-10/U-17：v4-mapped（`::ffff:a.b.c.d`）必须先折回 v4 再取数值键。Rust
    # `covering::load_covering_prefixes` 在入口 unmap，Python 此前没做 ⇒ 双栈
    # listener 上的同一客户端在离线校验里查不到 v4 段。
    try:
        # 与 Rust `iputil::parse_ip`（s.trim().parse()）同口径：允许首尾空白。
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return []
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    # 地址族分流必须与 Rust 一致：v4 → geoip 主表 + ipv4 range 表；
    # v6 → ipv6 range 表（geoip 主表只存 v4）。旧 Python 只查 geoip：离线校验
    # 看不到写入 ipv4/ipv6 表的行（demo/镜像/ASN 双栈），与运行期结果分叉。
    if isinstance(addr, ipaddress.IPv4Address):
        return _covering_select(conn, "geoip", int(addr)) + _covering_select(conn, "ipv4", int(addr))
    key = range_numeric_key(str(addr))
    return [] if key is None else _covering_select(conn, "ipv6", key)


# §3.3 查询期过滤（与 Rust `covering::country_vote_ok` / `cn_city_polluted` 同一
# 判定；离线合并也必须是同一口径，否则 ZZ 行会被 Python 选成国家）。
_SPECIAL_COUNTRY_CODES = frozenset({"ZZ", "XX", "A1", "A2"})
_FOREIGN_CITY_WORDS = (
    "美国", "日本", "英国", "德国", "法国", "韩国", "俄罗斯", "加拿大",
    "澳大利亚", "新加坡", "印度", "荷兰",
)


def country_vote_ok(cc: str) -> bool:
    """特殊国家码（ZZ/XX/A1/A2）不参与地理结论。"""
    return cc.strip().upper() not in _SPECIAL_COUNTRY_CODES


def cn_city_polluted(row_country: str, city: str) -> bool:
    """country=CN 但城市写外国名 → QQWry 污染票。"""
    if row_country.upper() != "CN":
        return False
    return any(word in city for word in _FOREIGN_CITY_WORDS)


def merge_covering(
    rows: list[sqlite3.Row], path_priority_gain: int | None = None
) -> MergedFields:
    """按字段合并覆盖行（§23.5 covering merge）。

    G-10：评分与 Rust `covering::merge_covering_fields_with_gain` **逐位一致**：
    `(weight + bits * gain, epoch, bits)`；同分后行胜；空值不覆盖非空。
    `gain` 缺省取 `data/geoip/panel.toml` 的 `path_priority_gain`（默认 10）。
    """
    out = MergedFields()
    if not rows:
        return out
    out.prefixes_merged = len(rows)
    gain = (
        int(path_priority_gain)
        if path_priority_gain is not None
        else load_path_priority_gain()
    )

    def pick(field: str) -> str:
        best = ""
        best_score: tuple[int, int, int] | None = None
        e_col = f"e_{field}"
        for r in rows:
            keys = r.keys()
            # 与 Rust 一致：**不 trim**（值原样参与输出；Rust 只判空，不裁剪）。
            val = (r[field] or "") if field in keys else ""
            row_country = (r["country"] or "") if "country" in keys else ""
            # 与 Rust `sanitize` 一致：特殊国家码不参与地理结论；CN 行里的外国
            # 城市名是 QQWry 污染票，同样丢弃（空值随后被跳过）。
            if field == "country" and not country_vote_ok(val):
                val = ""
            if field == "city" and cn_city_polluted(row_country, val):
                val = ""
            if not val:
                continue
            epoch = 0
            # 与 Rust `merge_covering_fields_with_gain` 一致：region/dc/division_code
            # 没有传字段 epoch（固定 0，回落 commit_unix）。此前 Python 会读
            # e_region/e_dc/e_division_code，库里这些列一旦非零，离线/运行期就会
            # 选出不同的省/DC/行政区。
            if field not in ("region", "dc", "division_code") and e_col in keys:
                epoch = int(r[e_col] or 0)
            cu = int(r["commit_unix"] or 0) if "commit_unix" in keys else 0
            if epoch <= 0:
                epoch = cu
            w = int(r["weight"] or 0) if "weight" in keys else 0
            bits = int(r["bits"] or 0) if "bits" in keys else 0
            # 与 Rust `field_score` 相同：saturating i64 加法/乘法。
            effective_weight = _sat_add(w, _sat_mul(bits, gain))
            score = (effective_weight, epoch, bits)
            if best_score is None or score >= best_score:
                best = val
                best_score = score
        return best

    out.country = pick("country")
    out.province = pick("province")
    out.region = pick("region")
    out.city = pick("city")
    out.district = pick("district")
    out.isp = pick("isp")
    out.dc = pick("dc")
    out.asn = pick("asn")
    out.as_org = pick("as_org")
    out.net_org = pick("net_org")
    out.cloud_provider = pick("cloud_provider")
    out.cloud_region = pick("cloud_region")
    out.cloud_service = pick("cloud_service")
    out.hosting = pick("hosting")
    out.division_code = pick("division_code")
    # 命中前缀 / bits：与 Rust `merge_covering_fields` 一致 —— 取最大 bits
    # （同 bits 后行胜）；weight/commit 取所有行的最大值。旧实现取 SQL 末行，
    # Rust 取最长前缀，同一个 IP 两侧会报出不同的 prefix/bits。
    for r in rows:
        keys = r.keys()
        rb = int(r["bits"] or 0) if "bits" in keys else 0
        if not out.prefix or rb >= out.bits:
            if "prefix" in keys:
                out.prefix = r["prefix"] or f"{r['ip_start']}-{r['ip_end']}"
            else:
                out.prefix = f"{r['ip_start']}-{r['ip_end']}"
            out.bits = rb
        out.weight = max(out.weight, int(r["weight"] or 0) if "weight" in keys else 0)
        out.commit_unix = max(
            out.commit_unix, int(r["commit_unix"] or 0) if "commit_unix" in keys else 0
        )
    return out


# §23.5.6：anycast 内置种子（与 Rust `anycast::ANYCAST_V4` 逐条一致）。表内行优先，
# 无表/无命中时回落这批。离线校验必须与运行期同判定，否则冲突 IP 的城市抑制两侧不同。
_ANYCAST_SEED_V4 = (
    ("1.1.1.0", 24),
    ("8.8.8.0", 24),
    ("9.9.9.0", 24),
    ("208.67.222.0", 24),
)


def detect_country_conflict(rows: list[sqlite3.Row]) -> tuple[str, bool]:
    """国家票（§23.5.6）：与 Rust `conflict::detect_country_conflict` 逐位一致。

    投票 = 每个国家的 `Σ max(weight,1)`（特殊码 ZZ/XX/A1/A2 不投），commit 取 max；
    胜者按 `(票数 desc, commit desc, 国家码 asc)` 排序 —— 最后一键是确定性收尾
    （Rust 的 votes 是 HashMap，无序会导致平票胜者随进程漂移）。次高 ≥ 胜者 30% 判冲突。
    """
    votes: dict[str, list[int]] = {}
    for r in rows:
        keys = r.keys()
        cc = (r["country"] or "") if "country" in keys else ""
        if not cc or not country_vote_ok(cc):
            continue
        w = int(r["weight"] or 0) if "weight" in keys else 0
        cu = int(r["commit_unix"] or 0) if "commit_unix" in keys else 0
        e = votes.setdefault(cc, [0, 0])
        e[0] += max(w, 1)
        e[1] = max(e[1], cu)
    if not votes:
        return ("", False)
    ranked = sorted(
        ((c, w, cu) for c, (w, cu) in votes.items()),
        key=lambda t: (-t[1], -t[2], t[0]),
    )
    winner = ranked[0][0]
    if len(ranked) < 2:
        return (winner, False)
    conflict = ranked[1][1] * 100 >= ranked[0][1] * 30
    return (winner, conflict)


def anycast_hit(conn: sqlite3.Connection, addr: ipaddress._BaseAddress) -> bool:
    """`addr` 是否落在 anycast 表或内置种子里（与 Rust `anycast::is_anycast_conn` 同口径）。

    表内起止是 TEXT：按地址族数值比较，v4-mapped 折回 v4；表缺失/无命中时回落内置
    v4 种子。Rust 侧表扫描失败也会回落种子，这里用 try/except 覆盖「无 anycast 表」。
    """
    try:
        rows = conn.execute("SELECT start, end FROM anycast").fetchall()
    except sqlite3.OperationalError:
        rows = []
    for row in rows:
        try:
            a = ipaddress.ip_address(str(row[0]).strip())
            b = ipaddress.ip_address(str(row[1]).strip())
        except (ValueError, TypeError):
            continue
        if isinstance(a, ipaddress.IPv6Address) and a.ipv4_mapped is not None:
            a = a.ipv4_mapped
        if isinstance(b, ipaddress.IPv6Address) and b.ipv4_mapped is not None:
            b = b.ipv4_mapped
        if isinstance(a, ipaddress.IPv4Address) != isinstance(addr, ipaddress.IPv4Address):
            continue
        if int(a) <= int(addr) <= int(b):
            return True
    if isinstance(addr, ipaddress.IPv4Address):
        for base, bits in _ANYCAST_SEED_V4:
            if addr in ipaddress.ip_network(f"{base}/{bits}", strict=False):
                return True
    return False


def format_label(m: MergedFields) -> str:
    if m.cloud_provider:
        head = m.cloud_provider
        region_or_city = m.cloud_region or m.city
        if region_or_city:
            head = f"{head} {region_or_city}"
        parts = [head]
        if m.isp:
            parts.append(m.isp)
        if m.asn:
            parts.append(f"AS{m.asn} {m.as_org}".strip())
        return " / ".join(p for p in parts if p)
    geo = [p for p in (m.province, m.city, m.district, m.isp) if p]
    parts: list[str] = []
    if geo:
        parts.append(" ".join(geo))
    if m.hosting:
        parts.append(m.hosting)
    if m.asn:
        parts.append(f"AS{m.asn} {m.as_org}".strip())
    elif m.net_org:
        parts.append(m.net_org)
    if m.net_org and m.net_org != m.as_org and m.asn:
        parts.append(f"reg={m.net_org}")
    return " / ".join(p for p in parts if p)


def lookup_merged(conn: sqlite3.Connection, ip: str) -> MergedFields | None:
    """离线合并 = Rust `covering::merge_pipeline` 的确定性核心（G-10 口径一致）。

    此前只做 `merge_covering`，漏了运行期的 §23.5.6 抑制：国家票胜者覆盖
    `merged.country`，且「国家冲突（次高 ≥30%）或 anycast」时清空
    province/city/district。于是同一个冲突 IP，离线校验（本函数）会保留城市，而
    面板 `/api/geoip/lookup`（`merge_pipeline`）抑制掉 —— 「同数据两端选出的字段
    一致」不成立。这里补齐这两层；面板 `panel_edits` 是数据层、不在离线库语义内
    （Rust 侧也只有面板端点会叠加），故此处不回放。
    """
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    rows = load_covering(conn, ip)
    if not rows:
        return None
    merged = merge_covering(rows)
    country, conflict = detect_country_conflict(rows)
    if country:
        merged.country = country
    if conflict or anycast_hit(conn, addr):
        merged.province = ""
        merged.city = ""
        merged.district = ""
    return merged


_RANGE_INSERT_SQL = """INSERT INTO geoip (
    ip_start, ip_end, bits, weight, prefix,
    country, province, region, city, district, isp, dc,
    asn, as_org, net_org, cloud_provider, cloud_region, cloud_service,
    hosting, division_code, source,
    e_country, e_province, e_city, e_district, e_isp,
    e_asn, e_as_org, e_net_org, e_cloud_provider, e_cloud_region,
    e_cloud_service, e_hosting, commit_unix,
    start_i, end_i
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
          ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"""

# §23 双 schema：v6 行走 `ipv6` 表（列名 start/end，无 dc 文本列；Rust
# `covering::load_from_range_table` 对 index 10 固定返回 ''）。v4 继续走主表
# `geoip`（Rust `load_from_geoip`）。旧 `upsert_range` 不区分地址族，v6 也被塞进
# geoip 主表 —— 运行期 `load_from_geoip` 对 v6 直接 return empty，等价于「导入成功
# 但永远查不到」。ASN/BGP 双栈导入必须按族分流。
_IPV6_INSERT_SQL = """INSERT INTO ipv6 (
    start, end, bits, weight,
    country, province, region, city, district, isp,
    asn, as_org, net_org, cloud_provider, cloud_region, cloud_service,
    hosting, division_code, prefix, source,
    e_country, e_province, e_region, e_city, e_district, e_isp,
    e_asn, e_as_org, e_net_org, e_cloud_provider, e_cloud_region,
    e_cloud_service, e_hosting, e_dc, e_division_code, commit_unix,
    start_i, end_i
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
          ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"""


def _as_text(v: object) -> str:
    """把任意 JSON 值安全转成 TEXT 绑定值（源形状漂移兜底）。

    上游 JSON 的字段类型会漂移（实测某云厂商层把 `hosting`/`tags` 写成数组）。
    直接把 list/dict 绑进 sqlite3 会抛 `ProgrammingError: type 'list' is not
    supported`，整批 merge 在最深处失败。这里把 list 用逗号连接、dict 用 JSON
    文本、标量 str()，保证「一个怪字段」不会杀掉整条更新链。
    """
    if v is None:
        return ""
    if isinstance(v, str):
        return v
    if isinstance(v, (list, tuple)):
        return ", ".join(_as_text(x) for x in v if x is not None)
    if isinstance(v, dict):
        return json.dumps(v, ensure_ascii=False, sort_keys=True)
    return str(v)


def _to_int(v: object, default: int = 0) -> int:
    try:
        return int(v)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def _range_insert_params(
    start: str,
    end: str,
    fields: dict[str, Any],
    weight: int,
    source: str,
    commit_unix: int | None,
) -> tuple:
    """把一行 range 记录归一成 `_RANGE_INSERT_SQL` 的参数元组。

    抽出来是为了让 `upsert_range`（单行）与 `upsert_range_many`（批量，ASN/BGP
    导入上百万行时用）共享**同一套**列顺序/epoch/数值键逻辑 —— 两份实现漂移正是
    「34 个占位符对 36 个参数」那类静默失败的温床。所有文本字段都经 `_as_text`：
    上游 JSON 的 list/dict 值不能直接绑定（否则整批 merge 在 sqlite3 绑参处失败）。
    """
    start = _as_text(start).strip()
    end = _as_text(end).strip()
    bits = 32
    prefix = f"{start}/32"
    try:
        nets = list(
            ipaddress.summarize_address_range(
                ipaddress.ip_address(start), ipaddress.ip_address(end)
            )
        )
        if len(nets) == 1:
            prefix = str(nets[0])
            bits = int(prefix.split("/")[1])
        elif len(nets) > 1:
            # 区间不能表示成单个 CIDR：仍按地址族给一个不会误导的长度。
            bits = 128 if nets[0].version == 6 else 32
            prefix = f"{start}-{end}"
    except ValueError:
        pass
    cu = _to_int(
        commit_unix if commit_unix is not None else fields.get("commit_unix"),
        int(time.time()),
    )
    # §23.8 性能：数值范围列 + 索引——TEXT BETWEEN 无法用索引且比较错误。
    # 必须用 range_numeric_key（v4=u32、v6=高 64 位保序映射）：直接 int(v6) 会
    # 超出 SQLite i64，绑定时抛 OverflowError（IPv6 ASN/BGP 导入曾因此整段失败）。
    si = range_numeric_key(start)
    ei = range_numeric_key(end)
    if si is None:
        si = -1
    if ei is None:
        ei = -1
    text = {f: _as_text(fields.get(f, "")) for f in (
        "country", "region", "province", "city", "district", "isp", "dc",
        "asn", "as_org", "net_org", "cloud_provider", "cloud_region",
        "cloud_service", "hosting", "division_code", "source",
    )}
    epochs = {}
    for f in EPOCH_FIELDS:
        val = text.get(f, "")
        epochs[f"e_{f}"] = cu if val else _to_int(fields.get(f"e_{f}"), 0)

    return (
        start,
        end,
        bits,
        weight,
        prefix,
        text["country"],
        text["province"] or text["region"],
        text["region"],
        text["city"],
        text["district"],
        text["isp"],
        text["dc"],
        text["asn"],
        text["as_org"],
        text["net_org"],
        text["cloud_provider"],
        text["cloud_region"],
        text["cloud_service"],
        text["hosting"],
        text["division_code"],
        source or text["source"],
        epochs["e_country"],
        epochs["e_province"],
        epochs["e_city"],
        epochs["e_district"],
        epochs["e_isp"],
        epochs["e_asn"],
        epochs["e_as_org"],
        epochs["e_net_org"],
        epochs["e_cloud_provider"],
        epochs["e_cloud_region"],
        epochs["e_cloud_service"],
        epochs["e_hosting"],
        cu,
        si,
        ei,
    )


def _is_v6_addr(text: str) -> bool:
    try:
        return ipaddress.ip_address(str(text).strip()).version == 6
    except ValueError:
        return False


def _ipv6_insert_params(p: tuple) -> tuple:
    """把 v4 参数元组映射成 `ipv6` range 表列序（见 `_IPV6_INSERT_SQL`）。

    v4 元组布局：start,end,bits,weight,prefix,country,province,region,city,
    district,isp,dc,asn,as_org,net_org,cloud_{provider,region,service},hosting,
    division_code,source,e_country,e_province,e_city,e_district,e_isp,e_asn,
    e_as_org,e_net_org,e_cloud_{provider,region,service},e_hosting,commit,start_i,end_i。
    ipv6 表没有 `dc`/`e_dc` 查询语义（Rust 固定 ''），这里写 0/空。
    """
    return (
        p[0], p[1], p[2], p[3],          # start,end,bits,weight
        p[5], p[6], p[7], p[8], p[9], p[10],  # country,province,region,city,district,isp
        p[12], p[13], p[14],             # asn,as_org,net_org
        p[15], p[16], p[17],             # cloud_provider/region/service
        p[18], p[19],                    # hosting,division_code
        p[4], p[20],                     # prefix,source
        p[21], p[22], 0, p[23], p[24], p[25],          # e_country..e_isp (+e_region=0)
        p[26], p[27], p[28],             # e_asn,e_as_org,e_net_org
        p[29], p[30], p[31],             # e_cloud_*
        p[32], 0, 0,                     # e_hosting, e_dc=0, e_division_code=0
        p[33], p[34], p[35],             # commit_unix,start_i,end_i
    )


def upsert_range(
    conn: sqlite3.Connection,
    start: str,
    end: str,
    fields: dict[str, Any],
    *,
    weight: int = 50,
    source: str = "",
    commit_unix: int | None = None,
) -> None:
    # 末尾的 start_i/end_i 是数值范围列（init_schema 的 ALTER + idx_geoip_numeric）。
    # 绑定元组一直带着 si/ei，列清单却漏了它们 —— 34 个占位符对 36 个参数，
    # upsert_range 每次都抛 ProgrammingError，所有走它的 enrich/seed 全部静默失败。
    p = _range_insert_params(start, end, fields, weight, source, commit_unix)
    if _is_v6_addr(start):
        conn.execute(_IPV6_INSERT_SQL, _ipv6_insert_params(p))
    else:
        conn.execute(_RANGE_INSERT_SQL, p)


def upsert_range_many(
    conn: sqlite3.Connection,
    rows,
    *,
    batch_size: int = 2000,
) -> int:
    """批量写入 range 行（ASN/BGP 等百万行导入用）。

    `rows` 是 `(start, end, fields, weight, source, commit_unix)` 的可迭代对象；
    返回写入行数。v4 写主表 `geoip`、v6 写 `ipv6` range 表（与 Rust 查询侧
    按地址族分流的口径一致）。单行 `execute` 的 Python/SQLite 调用开销在百万级
    数据上会占掉大部分运行时间，批量 `executemany` 后同一条 SQL 仍走
    `_range_insert_params`，保证列顺序与单行写入完全一致。
    """
    n = 0
    v4_batch: list[tuple] = []
    v6_batch: list[tuple] = []

    def flush_v4() -> None:
        nonlocal n
        if v4_batch:
            conn.executemany(_RANGE_INSERT_SQL, v4_batch)
            n += len(v4_batch)
            v4_batch.clear()

    def flush_v6() -> None:
        nonlocal n
        if v6_batch:
            conn.executemany(_IPV6_INSERT_SQL, v6_batch)
            n += len(v6_batch)
            v6_batch.clear()

    for start, end, fields, weight, source, cu in rows:
        p = _range_insert_params(start, end, fields, weight, source, cu)
        if _is_v6_addr(start):
            v6_batch.append(_ipv6_insert_params(p))
            if len(v6_batch) >= batch_size:
                flush_v6()
        else:
            v4_batch.append(p)
            if len(v4_batch) >= batch_size:
                flush_v4()
    flush_v4()
    flush_v6()
    return n


def write_sources_meta(path: Path, meta: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    existing: dict[str, Any] = {}
    if path.is_file():
        existing = json.loads(path.read_text(encoding="utf-8"))
    existing.update(meta)
    path.write_text(json.dumps(existing, indent=2, sort_keys=True) + "\n", encoding="utf-8")
