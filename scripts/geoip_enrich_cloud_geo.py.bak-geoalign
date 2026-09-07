#!/usr/bin/env python3
"""§2.1/§2.8 cloud_geo：云 region → 地理（city/country）拼接。
腾讯上游曾出现 region=global——对已有 cloud 行按 region 表回填城市；
仅在 city 为空时补（空值不覆盖非空）。"""
from __future__ import annotations

import sqlite3
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from geoip_common import DEFAULT_DB, init_schema  # noqa: E402

# AWS/GCP/Azure 主 region → (country, province, city)
REGION_GEO = {
    "us-east-1": ("US", "弗吉尼亚州", "阿什本"),
    "us-east-2": ("US", "俄亥俄州", "哥伦布"),
    "us-west-1": ("US", "加利福尼亚州", "圣何塞"),
    "us-west-2": ("US", "俄勒冈州", "波特兰"),
    "eu-west-1": ("IE", "都柏林", "都柏林"),
    "eu-central-1": ("DE", "黑森州", "法兰克福"),
    "ap-northeast-1": ("JP", "东京都", "东京"),
    "ap-southeast-1": ("SG", "", "新加坡"),
    "ap-southeast-2": ("AU", "新南威尔士州", "悉尼"),
    "ap-northeast-2": ("KR", "", "首尔"),
    "ap-south-1": ("IN", "马哈拉施特拉邦", "孟买"),
    "cn-north-1": ("CN", "北京", "北京"),
    "cn-northwest-1": ("CN", "宁夏回族自治区", "中卫"),
    "asia-east1": ("TW", "彰化县", "彰化"),
    "asia-east2": ("HK", "", "香港"),
    "asia-northeast1": ("JP", "东京都", "东京"),
    "asia-south1": ("IN", "马哈拉施特拉邦", "孟买"),
    "asia-southeast1": ("SG", "", "新加坡"),
    "europe-west1": ("BE", "", "圣赫斯兰"),
    "europe-west3": ("DE", "黑森州", "法兰克福"),
}


def main() -> int:
    cu = int(time.time())
    conn = sqlite3.connect(DEFAULT_DB)
    n = 0
    try:
        init_schema(conn)
        rows = conn.execute(
            """SELECT rowid, cloud_region FROM geoip
               WHERE cloud_region != '' AND (city = '' OR country = '')
                 AND source LIKE '%cloud%' OR (cloud_region != '' AND city = '')"""
        ).fetchall()
        for rowid, region in rows:
            geo = REGION_GEO.get((region or "").strip().lower())
            if not geo:
                continue
            country, province, city = geo
            conn.execute(
                """UPDATE geoip SET country=?, province=?, city=?,
                     e_city=?, commit_unix=? WHERE rowid=? AND (city='' OR country='')""",
                (country, province, city, cu, cu, rowid),
            )
            n += 1
        conn.commit()
    finally:
        conn.close()
    print(f"geoip_enrich_cloud_geo: backfilled {n} cloud rows with region geo")
    return 0


if __name__ == "__main__":
    sys.exit(main())
