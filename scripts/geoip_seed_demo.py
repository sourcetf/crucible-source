#!/usr/bin/env python3
"""Create offline demo GeoIP DB with §23 schema + sample IPv4 ranges.

Writes `data/geoip/current/geoip.sqlite` (geoip + ipv4/ipv6 tables) so
`geoip_lookup` works without network / raw layer downloads.
"""
from __future__ import annotations

import argparse
import sqlite3
import sys
import time
from pathlib import Path

# Allow `python scripts/geoip_seed_demo.py` from repo root.
_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

from geoip_common import (  # noqa: E402
    DEFAULT_DB,
    PANEL_DB,
    SOURCES_JSON,
    init_panel_schema,
    init_schema,
    seed_panel_demo,
    upsert_range,
    write_sources_meta,
)

DEMO_RANGES: list[tuple[str, str, dict]] = [
    (
        "1.2.4.0",
        "1.2.4.255",
        {
            "country": "CN",
            "province": "北京",
            "region": "BJ",
            "city": "Beijing",
            "district": "海淀区",
            "isp": "CNNIC",
            "asn": "24151",
            "as_org": "CNNIC-DNS",
            "division_code": "110108",
            "source": "demo-seed",
        },
    ),
    (
        "8.8.8.0",
        "8.8.8.255",
        {
            "country": "US",
            "province": "California",
            "region": "CA",
            "city": "Mountain View",
            "isp": "Google",
            "asn": "15169",
            "as_org": "GOOGLE",
            "cloud_provider": "Google Cloud",
            "cloud_region": "us-west1",
            "cloud_service": "dns",
            "source": "demo-seed",
        },
    ),
    (
        "1.1.1.0",
        "1.1.1.255",
        {
            "country": "AU",
            "province": "Queensland",
            "region": "QLD",
            "city": "Brisbane",
            "isp": "Cloudflare",
            "asn": "13335",
            "as_org": "CLOUDFLARENET",
            "cloud_provider": "Cloudflare",
            "cloud_region": "anycast",
            "cloud_service": "cdn",
            "source": "demo-seed",
        },
    ),
    (
        "192.0.2.0",
        "192.0.2.255",
        {
            "country": "US",
            "province": "California",
            "region": "CA",
            "city": "Los Angeles",
            "isp": "ExampleNet",
            "asn": "64500",
            "as_org": "TEST-NET-1",
            "hosting": "LAX1-IDC",
            "source": "demo-seed",
        },
    ),
    (
        "198.51.100.0",
        "198.51.100.255",
        {
            "country": "DE",
            "province": "Berlin",
            "region": "BE",
            "city": "Berlin",
            "isp": "SampleCo",
            "asn": "64501",
            "as_org": "TEST-NET-2",
            "cloud_provider": "DemoCloud",
            "cloud_region": "eu-central-1",
            "cloud_service": "compute",
            "source": "demo-seed",
        },
    ),
    (
        "203.0.113.0",
        "203.0.113.255",
        {
            "country": "JP",
            "province": "Tokyo",
            "region": "13",
            "city": "Tokyo",
            "district": "Chiyoda",
            "isp": "TestASN",
            "asn": "64502",
            "as_org": "TEST-NET-3",
            "hosting": "NRT-DC1",
            "division_code": "13101",
            "source": "demo-seed",
        },
    ),
    (
        "101.226.0.0",
        "101.226.255.255",
        {
            "country": "CN",
            "province": "上海",
            "region": "SH",
            "city": "Shanghai",
            "district": "浦东新区",
            "isp": "中国电信",
            "asn": "4812",
            "as_org": "CHINANET-SH",
            "division_code": "310115",
            "hosting": "",
            "source": "demo-seed",
        },
    ),
    # Tencent-ish cloud sample for label formatting smoke (cloud_provider path).
    (
        "119.28.0.0",
        "119.28.255.255",
        {
            "country": "US",
            "province": "California",
            "region": "CA",
            "city": "San Jose",
            "isp": "Tencent",
            "asn": "132203",
            "as_org": "Tencent",
            "cloud_provider": "腾讯云",
            "cloud_region": "us-sanjose-1",
            "cloud_service": "cvm",
            "source": "demo-seed",
        },
    ),
]


def seed_ipv4_row(conn: sqlite3.Connection, start: str, end: str, fields: dict, cu: int) -> None:
    bits = 24
    prefix = f"{start}/{bits}"
    conn.execute(
        """INSERT INTO ipv4 (
            start, end, bits, weight, country, province, region, city, district, isp,
            asn, as_org, cloud_provider, cloud_region, cloud_service, hosting,
            division_code, prefix, source,
            e_country, e_province, e_city, e_district, e_isp,
            e_asn, e_as_org, e_cloud_provider, e_cloud_region, e_cloud_service, e_hosting,
            commit_unix
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            start,
            end,
            bits,
            80,
            fields.get("country", ""),
            fields.get("province", ""),
            fields.get("region", ""),
            fields.get("city", ""),
            fields.get("district", ""),
            fields.get("isp", ""),
            fields.get("asn", ""),
            fields.get("as_org", ""),
            fields.get("cloud_provider", ""),
            fields.get("cloud_region", ""),
            fields.get("cloud_service", ""),
            fields.get("hosting", ""),
            fields.get("division_code", ""),
            prefix,
            fields.get("source", "demo-seed"),
            cu,
            cu,
            cu,
            cu,
            cu,
            cu,
            cu,
            cu if fields.get("cloud_provider") else 0,
            cu if fields.get("cloud_region") else 0,
            cu if fields.get("cloud_service") else 0,
            cu if fields.get("hosting") else 0,
            cu,
        ),
    )


def main() -> int:
    ap = argparse.ArgumentParser(description="Seed offline demo geoip.sqlite (§23 schema)")
    ap.add_argument("--db", default=DEFAULT_DB)
    ap.add_argument("--force", action="store_true", help="wipe existing rows before seed")
    args = ap.parse_args()

    db_path = Path(args.db)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    init_schema(conn)
    cu = int(time.time())

    if args.force:
        conn.execute("DELETE FROM geoip")
        conn.execute("DELETE FROM ipv4")
        conn.execute("DELETE FROM ipv6")

    # Skip re-seed if already populated (idempotent offline path).
    n = conn.execute("SELECT COUNT(*) FROM geoip").fetchone()[0]
    if n > 0 and not args.force:
        print(f"geoip_seed_demo: {db_path} already has {n} geoip rows; skip (use --force)")
        conn.close()
        # Still ensure panel + SOURCES exist for Admin smoke.
        sources_path = Path(SOURCES_JSON)
        if not sources_path.is_file():
            write_sources_meta(
                sources_path,
                {
                    "demo_seed": {
                        "script": "geoip_seed_demo.py",
                        "note": "existing db; meta backfilled",
                    }
                },
            )
        panel_path = Path(PANEL_DB)
        panel_path.parent.mkdir(parents=True, exist_ok=True)
        panel = sqlite3.connect(str(panel_path))
        init_panel_schema(panel)
        seed_panel_demo(panel)
        panel.commit()
        panel.close()
        print(f"geoip_seed_demo: ensured panel={panel_path} sources={sources_path}")
        return 0

    for start, end, fields in DEMO_RANGES:
        upsert_range(conn, start, end, fields, weight=80, source="demo-seed", commit_unix=cu)
        seed_ipv4_row(conn, start, end, fields, cu)

    # Minimal ipv6 demo row (documentation / schema smoke) with full §23 fields.
    conn.execute(
        """INSERT INTO ipv6 (
            start, end, bits, weight, country, province, region, city, district, isp,
            asn, as_org, cloud_provider, cloud_region, cloud_service, hosting,
            division_code, prefix, source, commit_unix,
            e_country, e_province, e_city, e_district, e_isp,
            e_asn, e_as_org, e_cloud_provider, e_cloud_region, e_cloud_service, e_hosting
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            "2001:db8::",
            "2001:db8::ffff",
            112,
            50,
            "US",
            "Documentation",
            "DOC",
            "Documentation",
            "",
            "TEST-IPV6",
            "64511",
            "DOC-NET",
            "",
            "",
            "",
            "DOC-IDC",
            "",
            "2001:db8::/112",
            "demo-seed",
            cu,
            cu,
            cu,
            cu,
            0,
            cu,
            cu,
            cu,
            0,
            0,
            0,
            cu,
        ),
    )

    conn.commit()
    sources_path = Path(SOURCES_JSON)
    if db_path.parent.name == "current":
        sources_path = db_path.parent / "SOURCES.json"
    write_sources_meta(
        sources_path,
        {
            "demo_seed": {
                "script": "geoip_seed_demo.py",
                "commit_unix": cu,
                "ranges": len(DEMO_RANGES),
                "note": "offline §23 schema sample (ASN + cloud fields)",
            }
        },
    )
    conn.close()

    # Panel metadata DB (conflicts / sources / audit / cron) for Admin API.
    panel_path = Path(PANEL_DB)
    panel_path.parent.mkdir(parents=True, exist_ok=True)
    panel = sqlite3.connect(str(panel_path))
    init_panel_schema(panel)
    seed_panel_demo(panel, commit_unix=cu)
    panel.commit()
    panel.close()

    print(
        f"geoip_seed_demo: wrote {db_path} ({len(DEMO_RANGES)} ipv4 ranges + ipv6 sample); "
        f"panel={panel_path}; sources={sources_path}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
