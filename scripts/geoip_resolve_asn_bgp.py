#!/usr/bin/env python3
"""§2.4 ASN/BGP 多源解析（权重 850/820/810，均高于 china-operator）：

数据源（全部公开、可复现）：
  * `origin-asn`（sapics/ip-location-db，Route Views + RIPE RIS 的 BGP origin
    ASN 聚合，IPv4/IPv6 各一份）——真实 BGP 前缀，**更具体前缀**按 bits*gain
    参与运行期合并（weight 850）。
  * `iptoasn.com` combined（BGP 派生，IPv4+IPv6 同一文件，weight 820）。
  * `geolite2-asn`（sapics 镜像的 MaxMind GeoLite2 ASN CSV，IPv4/IPv6，weight 810）。

选择策略（确定且可复现）：
  1. 同一 (start,end) 多源给出不同 ASN（MOAS / 多源冲突）→ 运行期按
     `(weight + bits*gain, epoch, bits)` 选；三源权重 850 > 820 > 810，因此
     BGP origin 优先；完全同分时行序由 SQLite rowid 固定（本脚本按
     start,end,weight DESC,source,asn 排序写入，顺序可复现）。
  2. 更具体前缀（bits 更大）在权重相同时按 `bits*path_priority_gain` 胜出；
     BGP /24 不会被更宽的 /8 覆盖。
  3. 所有同前缀冲突写入 `panel_conflicts`（sources 字段为排序后的 ASN 列表），
     重复运行按 (prefix,field,sources,resolved=0) 去重，不会越跑越多。
  4. IPv4/IPv6 双栈：v6 的 start_i/end_i 用 `range_numeric_key`（高 64 位保序
     映射）写入，避免 `int(v6)` 超出 SQLite i64。

`--fixture` 可绕过网络，读统一 CSV（source,start,end,asn,as_org），用于冲突/
双栈/更具体前缀的确定性回归（见 scripts/geoip_asn_conflict_test.py）。

历史 bug（本文件修复）：
  * 旧实现调用 `json.loads` 但从未 `import json` → `asn_urls()` 永远抛
    NameError，被 `except Exception` 吞掉后 URLS=[]，脚本打印
    `rows=0 moas_conflicts=0` 并**静默成功**（U-09 全流程实测数据为零）。
  * 旧实现只取 ipv4 CSV、单行 INSERT、无 IPv6；本版三源双栈。
"""
from __future__ import annotations

import argparse
import csv
import gzip
import io
import ipaddress
import sqlite3
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from geoip_common import DEFAULT_DB, init_panel_schema, init_schema, upsert_range_many  # noqa: E402

UA = {"User-Agent": "crucible-geoip/1.0 (+https://localhost)"}
TIMEOUT = 180

# source label → (weight, urls)。label 会写进 geoip.source，也是重跑时的清理键。
SOURCES: dict[str, dict] = {
    "asn-bgp": {
        "weight": 850,
        "urls": [
            "https://raw.githubusercontent.com/sapics/ip-location-db/main/"
            "origin-asn/origin-asn-ipv4.csv",
            "https://raw.githubusercontent.com/sapics/ip-location-db/main/"
            "origin-asn/origin-asn-ipv6.csv",
        ],
    },
    "asn-iptoasn": {
        "weight": 820,
        "urls": ["https://iptoasn.com/data/ip2asn-combined.tsv.gz"],
    },
    "asn-geolite2": {
        "weight": 810,
        "urls": [
            "https://raw.githubusercontent.com/sapics/ip-location-db/main/"
            "geolite2-asn/geolite2-asn-ipv4.csv",
            "https://raw.githubusercontent.com/sapics/ip-location-db/main/"
            "geolite2-asn/geolite2-asn-ipv6.csv",
        ],
    },
}
# 旧数据清理范围：这些 source 的行由本脚本整体刷新。
OWN_SOURCES = tuple(SOURCES)


def _norm_range(start: str, end: str) -> tuple[str, str] | None:
    """规范化起止地址；非法/跨族返回 None。"""
    try:
        a = ipaddress.ip_address(start.strip())
        b = ipaddress.ip_address(end.strip())
    except ValueError:
        return None
    if a.version != b.version or int(a) > int(b):
        return None
    return str(a), str(b)


def _norm_asn(asn: str) -> str | None:
    a = str(asn).strip()
    if not a.isdigit() or a == "0":
        return None
    return str(int(a))


def _iter_origin_csv(stream: io.TextIOBase, source: str):
    """sapics origin-asn / geolite2-asn：start,end,asn,org（CSV，org 可带逗号引号）。"""
    weight = SOURCES[source]["weight"]
    for row in csv.reader(stream):
        if len(row) < 3:
            continue
        rng = _norm_range(row[0], row[1])
        asn = _norm_asn(row[2])
        if rng is None or asn is None:
            continue
        org = row[3].strip() if len(row) > 3 else ""
        yield (source, rng[0], rng[1], asn, org, weight)


def _iter_iptoasn_tsv(stream: io.TextIOBase, source: str):
    """iptoasn.com combined：start,end,asn,cc,org（TSV；asn=0 表示未路由）。"""
    weight = SOURCES[source]["weight"]
    for line in stream:
        parts = line.rstrip("\n").split("\t")
        if len(parts) < 3:
            continue
        rng = _norm_range(parts[0], parts[1])
        asn = _norm_asn(parts[2])
        if rng is None or asn is None:
            continue
        org = parts[4].strip() if len(parts) > 4 else ""
        yield (source, rng[0], rng[1], asn, org, weight)


def _iter_fixture(path: Path):
    """统一 fixture：source,start,end,asn,as_org（source 必须是 OWN_SOURCES 之一）。"""
    with path.open(encoding="utf-8") as f:
        for row in csv.reader(f):
            if not row or row[0].startswith("#"):
                continue
            if len(row) < 5:
                raise SystemExit(f"bad fixture row (need source,start,end,asn,org): {row!r}")
            source = row[0].strip()
            if source not in SOURCES:
                raise SystemExit(f"bad fixture source {source!r}; want {OWN_SOURCES}")
            rng = _norm_range(row[1], row[2])
            asn = _norm_asn(row[3])
            if rng is None or asn is None:
                raise SystemExit(f"bad fixture range/asn: {row!r}")
            yield (source, rng[0], rng[1], asn, row[4].strip(), SOURCES[source]["weight"])


def _open_url(url: str):
    req = urllib.request.Request(url, headers=UA)
    resp = urllib.request.urlopen(req, timeout=TIMEOUT)
    if url.endswith(".gz"):
        return io.TextIOWrapper(gzip.GzipFile(fileobj=resp), encoding="utf-8", errors="replace")
    return io.TextIOWrapper(resp, encoding="utf-8", errors="replace")


def _stream_source(source: str, limit: int | None):
    """逐个 URL 流式产出记录；单 URL 失败只告警，不影响其它 URL。"""
    for url in SOURCES[source]["urls"]:
        try:
            with _open_url(url) as f:
                it = (
                    _iter_iptoasn_tsv(f, source)
                    if source == "asn-iptoasn"
                    else _iter_origin_csv(f, source)
                )
                for i, rec in enumerate(it):
                    yield rec
                    if limit is not None and i + 1 >= limit:
                        break
        except Exception as exc:  # noqa: BLE001 —— 单源失败不应杀掉整条链
            print(f"warn: {source} {url}: {exc}", file=sys.stderr)


def _ensure_stage(conn: sqlite3.Connection) -> None:
    conn.execute(
        """CREATE TEMP TABLE IF NOT EXISTS asn_stage (
               start TEXT NOT NULL,
               end TEXT NOT NULL,
               asn TEXT NOT NULL,
               as_org TEXT DEFAULT '',
               source TEXT NOT NULL,
               weight INTEGER NOT NULL,
               PRIMARY KEY (start, end, source, asn)
           )"""
    )


def _stage_insert(conn: sqlite3.Connection, records, batch_size: int = 5000) -> int:
    _ensure_stage(conn)
    sql = """INSERT OR IGNORE INTO asn_stage(start, end, asn, as_org, source, weight)
             VALUES (?, ?, ?, ?, ?, ?)"""
    n = 0
    batch: list[tuple] = []
    for _source, start, end, asn, org, weight in records:
        batch.append((start, end, asn, org, _source, weight))
        if len(batch) >= batch_size:
            conn.executemany(sql, batch)
            n += len(batch)
            batch.clear()
    if batch:
        conn.executemany(sql, batch)
        n += len(batch)
    return n


def ingest_staged(conn: sqlite3.Connection, *, replace_sources: tuple[str, ...]) -> dict:
    """对已写入 `asn_stage` 的行做去重/落库/冲突登记（不负责读取数据源）。"""
    staged = int(
        conn.execute("SELECT COUNT(*) FROM asn_stage").fetchone()[0]
    )
    # 只清理**本次成功读取**的 source：某个源临时失败时保留它的旧数据，而不是
    # 把上一轮的好数据一起删掉（「部分源失败 → 该源数据消失」是比旧数据更糟的状态）。
    replace = tuple(s for s in replace_sources if s in OWN_SOURCES)
    if replace:
        # v4 行在 geoip 主表、v6 行在 ipv6 range 表；两处都要清理，否则重跑会
        # 留下上一轮的 v6 重复行（v4 的 ipv4 表也顺手清，保持幂等）。
        for table in ("geoip", "ipv4", "ipv6"):
            conn.executemany(
                f"DELETE FROM {table} WHERE source = ?", [(s,) for s in replace]
            )
    # 同一 (start,end,asn) 只保留最佳源（weight 高者，其次 source/as_org 字典序）；
    # 按 start,end 排序后逐组处理，内存里只保留当前组（不会随总行数增长）。
    cur = conn.execute(
        """SELECT start, end, asn, as_org, source, weight FROM asn_stage
           ORDER BY start, end, weight DESC, source ASC, asn ASC, as_org ASC"""
    )
    conflicts: dict[tuple[str, str], set[str]] = {}
    current: tuple[str, str] | None = None
    best: dict[str, tuple[str, str, int]] = {}
    inserted = 0
    ranges = 0

    def flush(key: tuple[str, str] | None, group: dict[str, tuple[str, str, int]]) -> int:
        if key is None or not group:
            return 0
        # 冲突登记必须用**整组** ASN：旧写法只在看到第 2 行时把当前 ASN 加进去，
        # 会漏掉第一个 ASN（sources 变成 "64501|64502"，少了胜者 64500）。
        if len(group) > 1:
            conflicts.setdefault(key, set()).update(group.keys())
        rows = [
            (key[0], key[1], {"asn": asn, "as_org": org}, weight, source, None)
            for asn, (org, source, weight) in sorted(group.items())
        ]
        upsert_range_many(conn, rows)
        return len(rows)

    for start, end, asn, as_org, source, weight in cur.fetchall():
        key = (start, end)
        if key != current:
            inserted += flush(current, best)
            if current is not None:
                ranges += 1
            current = key
            best = {}
        # ORDER BY weight DESC / source ASC / asn ASC：同 ASN 的首行就是最佳行。
        best.setdefault(asn, (as_org or "", source, int(weight)))
    inserted += flush(current, best)
    if current is not None:
        ranges += 1

    # 同 (start,end) 多 ASN（MOAS / 跨源冲突）→ 人工审核；去重避免重跑膨胀。
    for (start, end), asns in sorted(conflicts.items()):
        sig = "|".join(sorted(asns, key=lambda x: int(x)))
        prefix = f"{start}-{end}"
        conn.execute(
            """INSERT INTO panel_conflicts(prefix, field, sources, resolved)
               SELECT ?, 'asn', ?, 0
               WHERE NOT EXISTS (
                   SELECT 1 FROM panel_conflicts
                   WHERE prefix = ? AND field = 'asn' AND sources = ? AND resolved = 0
               )""",
            (prefix, sig, prefix, sig),
        )
    conn.commit()
    return {
        "staged": staged,
        "inserted": inserted,
        "ranges": ranges,
        "conflicts": len(conflicts),
        "replace_sources": replace,
    }


def ingest(conn: sqlite3.Connection, records, *, replace_sources: tuple[str, ...]) -> dict:
    """单测/小数据入口：写 staging 后调用 ingest_staged。"""
    _ensure_stage(conn)
    # 同一连接上多次 ingest（单测/重跑）必须清掉上一轮 staging，否则旧行会混进来。
    conn.execute("DELETE FROM asn_stage")
    _stage_insert(conn, records)
    return ingest_staged(conn, replace_sources=replace_sources)


def main() -> int:
    ap = argparse.ArgumentParser(description="GeoIP ASN/BGP multi-source resolver")
    ap.add_argument("--db", default=DEFAULT_DB)
    ap.add_argument("--fixture", help="统一 CSV（source,start,end,asn,as_org）绕过网络")
    ap.add_argument(
        "--source",
        action="append",
        choices=OWN_SOURCES,
        help="只跑指定源（可重复；默认全部）",
    )
    ap.add_argument("--limit", type=int, help="每个源/每个 URL 最多读取 N 行（冒烟用）")
    args = ap.parse_args()

    sources = tuple(args.source or OWN_SOURCES)
    cu = int(time.time())
    path = Path(args.db)
    path.parent.mkdir(parents=True, exist_ok=True)
    started = time.time()
    conn = sqlite3.connect(str(path))
    conn.execute("PRAGMA busy_timeout = 30000")
    try:
        init_schema(conn)
        init_panel_schema(conn)
        loaded: list[str] = []
        if args.fixture:
            _stage_insert(conn, _iter_fixture(Path(args.fixture)))
            loaded = sorted(
                {row[0] for row in conn.execute("SELECT DISTINCT source FROM asn_stage")}
            )
        else:
            _ensure_stage(conn)
            for source in sources:
                n = _stage_insert(conn, _stream_source(source, args.limit))
                if n > 0:
                    loaded.append(source)
                else:
                    print(f"warn: source {source} produced 0 rows", file=sys.stderr)
        if not loaded:
            print("geoip_resolve_asn_bgp: no records from any source", file=sys.stderr)
            return 2
        stats = ingest_staged(conn, replace_sources=tuple(loaded))
        conn.execute(
            "INSERT INTO panel_audit(action, detail, ts) VALUES('asn_resolve', ?, ?)",
            (
                "sources={} staged={} inserted={} ranges={} conflicts={}".format(
                    ",".join(loaded),
                    stats["staged"],
                    stats["inserted"],
                    stats["ranges"],
                    stats["conflicts"],
                ),
                cu,
            ),
        )
        conn.commit()
    finally:
        conn.close()
    print(
        "geoip_resolve_asn_bgp: "
        f"sources={','.join(loaded)} staged={stats['staged']} "
        f"inserted={stats['inserted']} ranges={stats['ranges']} "
        f"conflicts={stats['conflicts']} db={path} "
        f"elapsed={time.time() - started:.1f}s"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
