#!/usr/bin/env python3
"""§2.7 RIR 发现的运营商 geofeed（权重 990）：扫 RIR whois dump 中的
geofeed:/remarks: Geofeed https://… URL → RFC8805 CSV 解析入库。
曾发现约 5322 个 URL；逐 URL 失败容忍（上限 GEOIP_GEOFEED_FAILS 默认 200）。"""
from __future__ import annotations

import ipaddress
import os
import re
import sqlite3
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from geoip_common import DEFAULT_DB, init_schema, upsert_range  # noqa: E402

WEIGHT = 990
DUMPS = [Path("data/geoip/sources/ripe.db"), Path("data/geoip/sources/apnic.db"),
         Path("data/geoip/sources/afrinic.db"), Path("data/geoip/sources/lacnic.db")]
GEOFEED_RE = re.compile(r"(https?://[^\s\"',]+geofeed[^\s\"',]*\.csv)", re.I)


def main() -> int:
    urls: set[str] = set()
    for dump in DUMPS:
        if not dump.is_file():
            continue
        with dump.open(encoding="utf-8", errors="replace") as f:
            for line in f:
                if "geofeed" in line.lower() and "http" in line.lower():
                    m = GEOFEED_RE.search(line)
                    if m:
                        urls.add(m.group(1))
    print(f"geoip_enrich_rir_geofeed: discovered {len(urls)} geofeed urls")
    cu = int(time.time())
    conn = sqlite3.connect(DEFAULT_DB)
    ok = fails = 0
    max_fails = int(os.environ.get("GEOIP_GEOFEED_FAILS", "200"))
    n = 0
    try:
        init_schema(conn)
        for url in sorted(urls):
            if fails > max_fails:
                break
            try:
                text = fetch_csv(url)
            except Exception:
                fails += 1
                continue
            count = 0
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(",")
                if len(parts) < 3:
                    continue
                prefix = parts[0]
                country = parts[1]
                region = parts[2] if len(parts) > 2 else ""
                city = parts[3] if len(parts) > 3 else ""
                try:
                    net = ipaddress.ip_network(prefix, strict=False)
                except ValueError:
                    continue
                if net.version != 4:
                    continue
                if country.upper() in ("ZZ", "XX", "A1", "A2", ""):
                    continue
                upsert_range(
                    conn, str(net.network_address), str(net.broadcast_address),
                    {"country": country.upper(), "region": region, "city": city},
                    weight=WEIGHT, source="rir-geofeed", commit_unix=cu,
                )
                count += 1
            n += count
            ok += 1
        conn.commit()
    finally:
        conn.close()
    print(f"geoip_enrich_rir_geofeed: ok={ok} fails={fails} rows={n}")
    return 0


def fetch_csv(url: str) -> str:
    import urllib.request
    req = urllib.request.Request(url, headers={"User-Agent": "crucible-geoip/1.0"})
    with urllib.request.urlopen(req, timeout=45) as r:
        return r.read().decode("utf-8", errors="replace")


if __name__ == "__main__":
    sys.exit(main())
