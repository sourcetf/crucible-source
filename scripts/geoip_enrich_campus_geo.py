#!/usr/bin/env python3
"""Campus geo enrich stub."""
from __future__ import annotations

import sqlite3
from pathlib import Path

from geoip_common import DEFAULT_DB, init_schema, upsert_range


def main() -> int:
    conn = sqlite3.connect(Path(DEFAULT_DB))
    try:
        init_schema(conn)
        upsert_range(
            conn,
            "203.0.113.0",
            "203.0.113.255",
            {"country": "CN", "region": "浙江省", "city": "杭州市", "isp": "CERNET", "source": "campus-geo"},
            weight=750,
        )
        conn.commit()
    finally:
        conn.close()
    print("geoip_enrich_campus_geo: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
