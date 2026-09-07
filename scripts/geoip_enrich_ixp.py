#!/usr/bin/env python3
"""§2.8 IXP 交换中心种子（主流通用段）→ isp=IXP:<name>。
PeeringDB 需 API key，这里内置知名 IXP 段；面板可继续手改覆盖。"""
from __future__ import annotations

import sqlite3
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from geoip_common import DEFAULT_DB, init_schema, upsert_range  # noqa: E402

IXPS = [
    ("80.249.208.0", "80.249.223.255", "AMS-IX"),
    ("80.81.192.0", "80.81.195.255", "DE-CIX Frankfurt"),
    ("195.66.224.0", "195.66.239.255", "LINX LON1"),
    ("206.126.236.0", "206.126.239.255", "Six Seattle"),
    ("198.32.160.0", "198.32.167.255", "NYIIX"),
    ("218.104.110.0", "218.104.110.255", "CN-IX 区间示例"),
]


def main() -> int:
    cu = int(time.time())
    conn = sqlite3.connect(DEFAULT_DB)
    n = 0
    try:
        init_schema(conn)
        for start, end, name in IXPS:
            upsert_range(
                conn, start, end,
                {"isp": f"IXP:{name}", "as_org": name, "net_org": name},
                weight=840, source="ixp", commit_unix=cu,
            )
            n += 1
        conn.commit()
    finally:
        conn.close()
    print(f"geoip_enrich_ixp: {n} ixp seeds")
    return 0


if __name__ == "__main__":
    sys.exit(main())
