#!/usr/bin/env python3
"""§2.3 GeoCN.mmdb摄取（国内主力，权重 820）：data/geoip/sources/GeoCN.jsonl
（由 scripts/geoip-mmdb2jsonl/mmdb2jsonl 生成）→ upsert_range；
同时重建 adcode_names.json（§2.8 places：division_code → 省/市/区名）。
"""
from __future__ import annotations

import json
import sqlite3
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from geoip_common import DEFAULT_DB, init_schema, upsert_range  # noqa: E402

JSONL = Path("data/geoip/sources/GeoCN.jsonl")
ADCODE_OUT = Path("data/geoip/current/adcode_names.json")
WEIGHT = 820


def main() -> int:
    if not JSONL.is_file():
        print("geoip_enrich_geocn: missing GeoCN.jsonl (run mmdb2jsonl first)")
        return 1
    cu = int(time.time())
    adcode: dict[str, dict[str, str]] = {}
    conn = sqlite3.connect(DEFAULT_DB)
    n = 0
    try:
        init_schema(conn)
        with JSONL.open(encoding="utf-8") as f:
            for line in f:
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                data = rec.get("data") or {}
                start = rec.get("ip_start")
                end = rec.get("ip_end")
                if not start or not end:
                    continue
                # 只导 v4（v6 表后续接入）
                if ":" in start:
                    continue
                code = data.get("division_code") or data.get("adcode") or ""
                province = data.get("province") or ""
                city = data.get("city") or ""
                district = data.get("district") or data.get("county") or ""
                fields = {
                    "country": "CN",
                    "province": province,
                    "city": city,
                    "district": district,
                    "isp": data.get("isp") or "",
                    "division_code": str(code) if code else "",
                }
                upsert_range(conn, start, end, fields, weight=WEIGHT,
                             source="geocn", commit_unix=cu)
                if code:
                    key = str(code)
                    cur = adcode.setdefault(key, {})
                    if province and not cur.get("province"):
                        cur["province"] = province
                    if city and not cur.get("city"):
                        cur["city"] = city
                    if district and not cur.get("district"):
                        cur["district"] = district
                n += 1
                if n % 200000 == 0:
                    conn.commit()
        conn.commit()
        ADCODE_OUT.write_text(json.dumps(adcode, ensure_ascii=False, indent=0),
                              encoding="utf-8")
    finally:
        conn.close()
    print(f"geoip_enrich_geocn: upserted {n} ranges; adcode_names {len(adcode)} codes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
