#!/usr/bin/env python3
"""§3 黑名单清洗：从 geoip.sqlite 清除 Ip2Region / DB-IP 系污染 + 手工 CIDR 黑段。

动作（与标准一致）：
- Ip2Region 系：删 xdb 产物、写 BLACKLISTED.txt、按历史权重戳（480/780/815/818）
  清空字段（当年约 365 万处）；meta ip2region_blacklisted=1
- DB-IP 系：删 mmdb、按权重戳（740/730/500）purge 字段（约 2400 万）+ 删 ASN 行
  （约 9.3 万）；meta dbip_blacklisted=1
- 手工 CIDR 黑名单（blacklist.json）整行删除
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import sqlite3
from pathlib import Path

from geoip_common import DEFAULT_DB, init_schema, set_meta_flag
from geoip_blacklist import SOURCE_BLACKLIST

GEO_FIELDS = [
    "country", "province", "region", "city", "district", "isp",
    "asn", "as_org", "net_org",
    "cloud_provider", "cloud_region", "cloud_service",
    "hosting", "division_code",
]


def purge_source_blacklist(conn: sqlite3.Connection, current_dir: Path) -> dict:
    stats: dict[str, int] = {}
    for entry in SOURCE_BLACKLIST:
        cleared = 0
        deleted = 0
        # 字段清空 + 对应 epoch 归零（防陈旧时间戳复活空字段）。
        sets = ", ".join(f"{f}=''" for f in GEO_FIELDS)
        sets += ", " + ", ".join(f"e_{f}=0" for f in GEO_FIELDS)
        for pattern in entry["source_patterns"]:
            weight_list = ",".join(str(w) for w in entry["weights"])
            # 按源名 + 历史权重戳清空字段（保留行骨架，空值不覆盖非空语义仍成立）。
            cur = conn.execute(
                f"""UPDATE geoip SET {sets}
                    WHERE source LIKE ? AND weight IN ({weight_list})""",
                (pattern,),
            )
            cleared += cur.rowcount if cur.rowcount > 0 else 0
            # ASN 行整行删除（dbip-asn：ASN 行约 9.3 万）。
            cur = conn.execute(
                f"""DELETE FROM geoip
                    WHERE source LIKE ? AND weight IN ({weight_list})
                      AND asn != ''""",
                (pattern,),
            )
            deleted += cur.rowcount if cur.rowcount > 0 else 0
        stats[entry["id"]] = cleared + deleted
        # 产物删除（xdb / mmdb）
        for pat in entry.get("artifacts", []):
            for f in current_dir.rglob(pat):
                try:
                    f.unlink()
                except OSError:
                    pass
        set_meta_flag(entry["meta_flag"], 1)
    # BLACKLISTED.txt 标记
    (current_dir / "BLACKLISTED.txt").write_text(
        "blacklisted: ip2region(all), dbip(city/asn)\n", encoding="utf-8"
    )
    return stats


def in_blacklist(ip_start: str, ip_end: str, entries: list[str]) -> bool:
    try:
        s = ipaddress.ip_address(ip_start)
        e = ipaddress.ip_address(ip_end)
    except ValueError:
        return False
    for item in entries:
        try:
            net = ipaddress.ip_network(item, strict=False)
        except ValueError:
            continue
        if s in net and e in net:
            return True
    return False


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=DEFAULT_DB)
    ap.add_argument("--root", default="data/geoip/current")
    ap.add_argument("--blacklist", default="data/geoip/blacklist.json")
    ap.add_argument("--skip-source-purge", action="store_true",
                    help="只清 CIDR 黑名单（源库 purge 幂等但耗时）")
    args = ap.parse_args()
    bl_path = Path(args.blacklist)
    entries: list[str] = []
    if bl_path.is_file():
        entries = json.loads(bl_path.read_text(encoding="utf-8")).get("entries", [])
    current_dir = Path(args.root)
    conn = sqlite3.connect(args.db)
    removed = 0
    try:
        init_schema(conn)
        # 1) 源库黑名单（Ip2Region / DB-IP）
        if not args.skip_source_purge:
            stats = purge_source_blacklist(conn, current_dir)
            for k, v in stats.items():
                print(f"geoip_purge_blacklisted: {k} purged/cleared {v}")
        # 2) 手工 CIDR 黑名单整行删除
        rows = conn.execute("SELECT rowid, ip_start, ip_end FROM geoip").fetchall()
        for rowid, start, end in rows:
            if in_blacklist(start, end, entries):
                conn.execute("DELETE FROM geoip WHERE rowid=?", (rowid,))
                removed += 1
        conn.commit()
    finally:
        conn.close()
    print(f"geoip_purge_blacklisted: removed {removed} cidr-matched rows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
