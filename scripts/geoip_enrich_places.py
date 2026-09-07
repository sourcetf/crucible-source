#!/usr/bin/env python3
"""§2.8 places：用 division_code（adcode_names.json）重建省/市/区名。
仅回填「有 division_code 但名字为空」的行（空值不覆盖非空）。"""
from __future__ import annotations

import json
import sqlite3
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from geoip_common import DEFAULT_DB, init_schema  # noqa: E402

ADCODE = Path("data/geoip/current/adcode_names.json")


def main() -> int:
    if not ADCODE.is_file():
        print("geoip_enrich_places: no adcode_names.json; skip (先跑 geoip_enrich_geocn)")
        return 0
    table = json.loads(ADCODE.read_text(encoding="utf-8"))
    cu = int(time.time())
    conn = sqlite3.connect(DEFAULT_DB)
    n = 0
    try:
        init_schema(conn)
        rows = conn.execute(
            """SELECT rowid, division_code, province, city, district FROM geoip
               WHERE division_code != '' AND (province = '' OR city = '' OR district = '')"""
        ).fetchall()
        for rowid, code, prov, city, district in rows:
            meta = table.get(code)
            if not meta:
                continue
            new_p = prov or meta.get("province", "")
            new_c = city or meta.get("city", "")
            new_d = district or meta.get("district", "")
            if (new_p, new_c, new_d) == (prov, city, district):
                continue
            conn.execute(
                """UPDATE geoip SET province=?, city=?, district=?,
                     e_province=CASE WHEN province='' THEN ? ELSE e_province END,
                     e_city=CASE WHEN city='' THEN ? ELSE e_city END,
                     e_district=CASE WHEN district='' THEN ? ELSE e_district END,
                     commit_unix=? WHERE rowid=?""",
                (new_p, new_c, new_d, cu, cu, cu, cu, rowid),
            )
            n += 1
            if n % 50000 == 0:
                conn.commit()
        conn.commit()
    finally:
        conn.close()
    print(f"geoip_enrich_places: backfilled {n} rows from adcode_names")
    return 0


if __name__ == "__main__":
    sys.exit(main())
