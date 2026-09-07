#!/usr/bin/env python3
"""§2.8 IANA/特殊用途段（RFC 5736/5737/3849/7534/8770 等）→ country=ZZ。
查询侧（Rust covering）忽略 ZZ/XX/A1/A2 —— 特殊段不参与地理结论。"""
from __future__ import annotations

import sqlite3
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from geoip_common import DEFAULT_DB, init_schema, upsert_range  # noqa: E402

SPECIAL_V4 = [
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
    "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
]


def main() -> int:
    cu = int(time.time())
    conn = sqlite3.connect(DEFAULT_DB)
    n = 0
    try:
        init_schema(conn)
        for cidr in SPECIAL_V4:
            import ipaddress
            net = ipaddress.ip_network(cidr, strict=False)
            upsert_range(
                conn, str(net.network_address), str(net.broadcast_address),
                {"country": "ZZ", "source": "iana-special"},
                weight=980, source="iana-special", commit_unix=cu,
            )
            n += 1
        conn.commit()
    finally:
        conn.close()
    print(f"geoip_enrich_iana_special: {n} special ranges -> ZZ")
    return 0


if __name__ == "__main__":
    sys.exit(main())
