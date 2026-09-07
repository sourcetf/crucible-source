#!/usr/bin/env python3
"""Offline GeoIP panel helper (list sources / quick lookup)."""
from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path

from geoip_common import DEFAULT_DB, SOURCES_JSON, format_label, init_schema, lookup_merged


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("command", choices=["lookup", "sources", "stats"])
    ap.add_argument("ip", nargs="?", default="")
    ap.add_argument("--db", default=DEFAULT_DB)
    args = ap.parse_args()

    if args.command == "sources":
        p = Path(SOURCES_JSON)
        print(p.read_text(encoding="utf-8") if p.is_file() else "{}")
        return 0

    conn = sqlite3.connect(args.db)
    try:
        init_schema(conn)
        if args.command == "stats":
            n = conn.execute("SELECT COUNT(*) FROM geoip").fetchone()[0]
            print(json.dumps({"rows": n, "db": args.db}))
            return 0
        merged = lookup_merged(conn, args.ip)
    finally:
        conn.close()
    if not merged:
        print(json.dumps({"status": "miss", "ip": args.ip}))
        return 1
    print(json.dumps({"status": "ok", "ip": args.ip, "label": format_label(merged)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
