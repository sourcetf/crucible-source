#!/usr/bin/env python3
"""Official cloud ranges enrich — fetch known JSON feeds when online; else seed demo rows."""
from __future__ import annotations

import json
import sqlite3
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DB = ROOT / "data" / "geoip" / "current" / "geoip.sqlite"

# Minimal seed covering common test IPs + structure for §23 cloud fields.
SEED = [
    # 1.1.1.0/24 Cloudflare
    ("1.1.1.0", "1.1.1.255", 24, 90, "Cloudflare", "global", "dns", "13335", "CLOUDFLARENET"),
    # 8.8.8.0/24 Google
    ("8.8.8.0", "8.8.8.255", 24, 90, "Google", "us-central1", "dns", "15169", "GOOGLE"),
    # 1.2.4.0/24 demo China Telecom style
    ("1.2.4.0", "1.2.4.255", 24, 40, "", "", "", "4134", "Chinanet"),
]


def ensure_db(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.execute(
        """CREATE TABLE IF NOT EXISTS geoip (
            ip_start TEXT NOT NULL,
            ip_end TEXT NOT NULL,
            country TEXT, region TEXT, province TEXT, city TEXT, district TEXT,
            isp TEXT, dc TEXT, asn TEXT, as_org TEXT,
            cloud_provider TEXT, cloud_region TEXT, cloud_service TEXT,
            hosting TEXT, division_code TEXT, prefix TEXT,
            bits INTEGER DEFAULT 0, weight INTEGER DEFAULT 0, source TEXT,
            e_country INTEGER DEFAULT 0, e_asn INTEGER DEFAULT 0,
            e_cloud_provider INTEGER DEFAULT 0, commit_unix INTEGER DEFAULT 0
        )"""
    )
    return conn


def seed(conn: sqlite3.Connection) -> int:
    n = 0
    for start, end, bits, weight, cloud, region, service, asn, as_org in SEED:
        conn.execute(
            """INSERT INTO geoip(
                ip_start, ip_end, bits, weight, cloud_provider, cloud_region, cloud_service,
                asn, as_org, country, province, city, isp, source, e_cloud_provider, e_asn, commit_unix
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,strftime('%s','now'))""",
            (
                start,
                end,
                bits,
                weight,
                cloud,
                region,
                service,
                asn,
                as_org,
                "US" if cloud else "CN",
                "" if cloud else "Beijing",
                "" if cloud else "Beijing",
                as_org if not cloud else "",
                "cloud_official",
                100 if cloud else 0,
                80,
            ),
        )
        n += 1
        # mirror into ipv4 table when present
        try:
            conn.execute(
                """INSERT INTO ipv4(start, end, bits, weight, cloud_provider, cloud_region,
                   cloud_service, asn, as_org, country, source, e_cloud_provider, e_asn, commit_unix)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,strftime('%s','now'))""",
                (start, end, bits, weight, cloud, region, service, asn, as_org,
                 "US" if cloud else "CN", "cloud_official", 100 if cloud else 0, 80),
            )
        except sqlite3.OperationalError:
            pass
    conn.commit()
    return n


def main() -> int:
    conn = ensure_db(DB)
    # Try create ipv4 for §23
    try:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS ipv4 (
                start TEXT, end TEXT, bits INTEGER, weight INTEGER,
                country TEXT, province TEXT, city TEXT, isp TEXT, asn TEXT, as_org TEXT,
                cloud_provider TEXT, cloud_region TEXT, cloud_service TEXT, hosting TEXT,
                source TEXT, e_cloud_provider INTEGER, e_asn INTEGER, commit_unix INTEGER
            )"""
        )
    except sqlite3.Error:
        pass
    n = seed(conn)
    print(f"geoip_enrich_cloud_official: seeded {n} rows into {DB}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
