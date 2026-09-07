#!/usr/bin/env python3
"""§2.8 google_rdns：对 Google 段（8.8.8.0/24 等）做 PTR 探测，取地域线索。
上限 cap 次查询（默认 200），避免运行时失控；仅补 city 为空的行。"""
from __future__ import annotations

import socket
import sqlite3
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from geoip_common import DEFAULT_DB, init_schema  # noqa: E402

CAP = 200
PROBE_NETS = ["8.8.8.0/24", "34.0.0.0/9"]


def main() -> int:
    import ipaddress
    cu = int(time.time())
    conn = sqlite3.connect(DEFAULT_DB)
    probed = 0
    hit = 0
    try:
        init_schema(conn)
        for cidr in PROBE_NETS:
            if probed >= CAP:
                break
            net = ipaddress.ip_network(cidr, strict=False)
            for ip in net.hosts():
                if probed >= CAP:
                    break
                probed += 1
                try:
                    name, _, _ = socket.gethostbyaddr(str(ip))
                except (socket.herror, socket.gaierror, OSError):
                    continue
                # ptr 常见格式：<region>-<hash>.xxx.google.com
                parts = name.split(".")
                tag = next((p for p in parts if p and "-" in p and len(p) <= 20), "")
                if not tag:
                    continue
                cur = conn.execute(
                    "SELECT city FROM geoip WHERE ip_start<=? AND ip_end>=? AND city!='' LIMIT 1",
                    (str(ip), str(ip)),
                ).fetchone()
                if cur:
                    continue
                conn.execute(
                    """UPDATE geoip SET dc=?, e_dc=?, commit_unix=?
                       WHERE ip_start<=? AND ip_end>=? AND source LIKE '%google%'""",
                    (tag, cu, cu, str(ip), str(ip)),
                )
                hit += 1
        conn.commit()
    finally:
        conn.close()
    print(f"geoip_enrich_google_rdns: probed={probed} tagged={hit}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
