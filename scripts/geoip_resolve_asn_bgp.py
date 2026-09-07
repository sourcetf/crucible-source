#!/usr/bin/env python3
"""§2.4 ASN/BGP（权重 820，高于 china-operator）：
sapics/ip-location-db ip-to-asn CSV（IPtoASN 合成）→ asn/as_org；
同一区间多 ASN（MOAS）→ 进 panel_conflicts 人工审核。
as_org → ISP 启发式仅在 isp 空时使用；asn 为 null/乱标不硬编。"""
from __future__ import annotations

import ipaddress
import sqlite3
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from geoip_common import DEFAULT_DB, init_panel_schema, init_schema, upsert_range  # noqa: E402

WEIGHT = 820
def asn_urls() -> list[str]:
    try:
        api = "https://api.github.com/repos/sapics/ip-location-db/contents/iptoasn-asn"
        listing = json.loads(urllib.request.urlopen(urllib.request.Request(api, headers={"User-Agent": "crucible-geoip/1.0"}), timeout=30).read())
        return [e["download_url"] for e in listing if e.get("name", "").endswith("-ipv4.csv")]
    except Exception as exc:
        print(f"warn: sapics listing: {exc}", file=sys.stderr)
        return []


URLS = asn_urls()


def main() -> int:
    cu = int(time.time())
    conn = sqlite3.connect(DEFAULT_DB)
    n = moas = 0
    try:
        init_schema(conn)
        init_panel_schema(conn)
        for url in URLS:
            req = urllib.request.Request(url, headers={"User-Agent": "crucible-geoip/1.0"})
            try:
                with urllib.request.urlopen(req, timeout=120) as r:
                    text = r.read().decode("utf-8", errors="replace")
            except Exception as exc:
                print(f"warn: {url}: {exc}", file=sys.stderr)
                continue
            moas_seen: dict[tuple[str, str], set[str]] = {}
            batch = []
            for line in text.splitlines():
                parts = line.strip().split(",")
                if len(parts) < 3:
                    continue
                try:
                    start = str(ipaddress.IPv4Address(parts[0]))
                    end = str(ipaddress.IPv4Address(parts[1]))
                except ValueError:
                    continue
                asn = parts[2].strip()
                as_org = parts[3].strip() if len(parts) > 3 else ""
                if not asn or not asn.isdigit() or asn == "0":
                    continue  # null/乱标不硬编
                key = (start, end)
                moas_seen.setdefault(key, set()).add(asn)
                batch.append((start, end, asn, as_org))
            for start, end, asn, as_org in batch:
                upsert_range(
                    conn, start, end, {"asn": asn, "as_org": as_org},
                    weight=WEIGHT, source="asn-bgp", commit_unix=cu,
                )
                n += 1
            for (start, end), asns in moas_seen.items():
                if len(asns) > 1:  # MOAS → 人工 conflict
                    conn.execute(
                        """INSERT INTO panel_conflicts(prefix, field, sources, resolved)
                           VALUES(?,?,?,0)""",
                        (f"{start}-{end}", "asn", "|".join(sorted(asns))),
                    )
                    moas += 1
            conn.commit()
            break  # 第一个成功源即可
    finally:
        conn.close()
    print(f"geoip_resolve_asn_bgp: rows={n} moas_conflicts={moas}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
