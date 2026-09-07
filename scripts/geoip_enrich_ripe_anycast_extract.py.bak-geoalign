#!/usr/bin/env python3
"""§2.6 ripe_anycast_extract：RIPE whois dump 中 netname 含 ANYCAST/Anycast 的段
→ anycast 表。数据源 data/geoip/sources/ripe.db（geoip_enrich_netorg 已下载）。"""
from __future__ import annotations

import re
import sqlite3
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from geoip_common import DEFAULT_DB, init_schema, upsert_anycast  # noqa: E402

DUMP = Path("data/geoip/sources/ripe.db")
ANYCAST_RE = re.compile(r"anycast", re.I)
RANGE_RE = re.compile(r"^(\d+\.\d+\.\d+\.\d+)\s*-\s*(\d+\.\d+\.\d+\.\d+)$")


def main() -> int:
    if not DUMP.is_file():
        print("geoip_enrich_ripe_anycast_extract: no ripe.db; skip")
        return 0
    cu = int(time.time())
    conn = sqlite3.connect(DEFAULT_DB)
    n = 0
    try:
        init_schema(conn)
        cur_obj: dict = {}
        with DUMP.open(encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.rstrip("\n")
                if not line:
                    if cur_obj.get("type") == "inetnum" and cur_obj.get("anycast"):
                        m = RANGE_RE.match(cur_obj.get("range", ""))
                        if m:
                            upsert_anycast(conn, m.group(1), m.group(2),
                                           source="ripe-anycast", commit_unix=cu)
                            n += 1
                    cur_obj = {}
                    continue
                if line.startswith("%"):
                    continue
                key, _, val = line.partition(":")
                key = key.strip().lower()
                val = val.strip()
                if key == "inetnum":
                    cur_obj["type"] = "inetnum"
                    cur_obj["range"] = val
                elif key == "netname" and ANYCAST_RE.search(val):
                    cur_obj["anycast"] = True
        conn.commit()
    finally:
        conn.close()
    print(f"geoip_enrich_ripe_anycast_extract: {n} anycast ranges")
    return 0


if __name__ == "__main__":
    sys.exit(main())
