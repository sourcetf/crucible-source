#!/usr/bin/env python3
"""Geofeed CSV import (offline demo + optional URL fetch)."""
from __future__ import annotations

import argparse
import csv
import io
import sqlite3
from pathlib import Path

from geoip_common import DEFAULT_DB, SOURCES_JSON, init_schema, upsert_range, write_sources_meta

try:
    from geoip_http import fetch
except ImportError:
    fetch = None  # type: ignore


DEMO_CSV = """start,end,country,region,city,isp
203.0.113.20/32,203.0.113.20/32,JP,13,Tokyo,GeofeedDemo
"""


def parse_row(row: dict[str, str]) -> tuple[str, str, dict[str, str]] | None:
    start = row.get("start", "").split("/")[0]
    end = row.get("end", start).split("/")[0]
    if not start:
        return None
    return start, end, {
        "country": row.get("country", ""),
        "region": row.get("region", ""),
        "city": row.get("city", ""),
        "isp": row.get("isp", ""),
        "source": "geofeed",
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=DEFAULT_DB)
    ap.add_argument("--url", default="", help="optional geofeed CSV URL")
    ap.add_argument("--weight", type=int, default=800)
    args = ap.parse_args()

    text = DEMO_CSV
    if args.url and fetch:
        text = fetch(args.url, use_tor=False).decode("utf-8", errors="replace")

    path = Path(args.db)
    conn = sqlite3.connect(path)
    n = 0
    try:
        init_schema(conn)
        reader = csv.DictReader(io.StringIO(text))
        for row in reader:
            parsed = parse_row(row)
            if not parsed:
                continue
            start, end, fields = parsed
            upsert_range(conn, start, end, fields, weight=args.weight, source="geofeed")
            n += 1
        conn.commit()
    finally:
        conn.close()
    write_sources_meta(Path(SOURCES_JSON), {"geofeed": {"rows": n, "url": args.url or "demo"}})
    print(f"geoip_enrich_geofeed: imported {n} rows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
