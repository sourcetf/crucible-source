#!/usr/bin/env python3
"""CNNIC whois enrich stub."""
from __future__ import annotations

import sqlite3
from pathlib import Path

from geoip_common import DEFAULT_DB, init_schema, upsert_range


def main() -> int:
    conn = sqlite3.connect(Path(DEFAULT_DB))
    try:
        init_schema(conn)
        upsert_range(conn, "1.2.4.8", "1.2.4.8", {"country": "CN", "region": "BJ", "source": "cnnic-whois-demo"}, weight=500)
        conn.commit()
    finally:
        conn.close()
    print("geoip_enrich_cnnic_whois: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
