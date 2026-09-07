#!/usr/bin/env python3
"""Offline GeoIP lookup CLI (debug / validation; production uses Rust panel)."""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

from geoip_common import DEFAULT_DB, format_label, init_schema, lookup_merged


def main() -> int:
    ap = argparse.ArgumentParser(description="Offline GeoIP lookup")
    ap.add_argument("ip", nargs="?", help="IPv4/IPv6 address")
    ap.add_argument("--db", default=DEFAULT_DB)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    if not args.ip:
        ap.print_help()
        return 1

    db_path = Path(args.db)
    if not db_path.is_file():
        print(f"database missing: {db_path}", file=sys.stderr)
        return 2

    conn = sqlite3.connect(db_path)
    try:
        init_schema(conn)
        merged = lookup_merged(conn, args.ip)
    finally:
        conn.close()

    if merged is None:
        out = {"ip": args.ip, "status": "miss"}
    else:
        label = format_label(merged)
        out = {
            "ip": args.ip,
            "status": "ok",
            "country": merged.country or None,
            "province": merged.region or None,
            "city": merged.city or None,
            "isp": merged.isp or None,
            "asn": merged.asn or None,
            "as_org": merged.as_org or None,
            "cloud_provider": merged.cloud_provider or None,
            "cloud_region": merged.cloud_region or None,
            "hosting": merged.dc or None,
            "bits": merged.bits,
            "prefixes_merged": merged.prefixes_merged,
            "label": label or None,
        }

    if args.json:
        print(json.dumps(out, ensure_ascii=False, indent=2))
    else:
        print(out.get("label") or out.get("status"))
    return 0 if out.get("status") == "ok" else 3


if __name__ == "__main__":
    raise SystemExit(main())
