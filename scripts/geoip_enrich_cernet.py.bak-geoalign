#!/usr/bin/env python3
"""§2.3 CERNET（权重 805）：教育网 CIDR → 省份标记 + 城市抑制。

标准：校区网段只标省份（来源 china-operator-ip cernet 列表 + netname 经验表），
city 留空——抑制「全省段被打成省会/北京总部」的污染。
"""
from __future__ import annotations

import re
import sqlite3
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from geoip_common import DEFAULT_DB, init_schema, upsert_range  # noqa: E402

WEIGHT = 805
URL = "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/cernet.txt"

PROVINCE_BY_HINT = [
    ("北京", "北京"), ("上海", "上海"), ("天津", "天津"), ("重庆", "重庆"),
    ("河北", "河北省"), ("山西", "山西省"), ("内蒙古", "内蒙古自治区"),
    ("辽宁", "辽宁省"), ("吉林", "吉林省"), ("黑龙江", "黑龙江省"),
    ("江苏", "江苏省"), ("浙江", "浙江省"), ("安徽", "安徽省"), ("福建", "福建省"),
    ("江西", "江西省"), ("山东", "山东省"), ("河南", "河南省"), ("湖北", "湖北省"),
    ("湖南", "湖南省"), ("广东", "广东省"), ("广西", "广西壮族自治区"),
    ("海南", "海南省"), ("四川", "四川省"), ("贵州", "贵州省"), ("云南", "云南省"),
    ("西藏", "西藏自治区"), ("陕西", "陕西省"), ("甘肃", "甘肃省"),
    ("青海", "青海省"), ("宁夏", "宁夏回族自治区"), ("新疆", "新疆维吾尔自治区"),
]


def main() -> int:
    req = urllib.request.Request(URL, headers={"User-Agent": "crucible-geoip/1.0"})
    with urllib.request.urlopen(req, timeout=60) as r:
        text = r.read().decode("utf-8", errors="replace")
    cu = int(time.time())
    conn = sqlite3.connect(DEFAULT_DB)
    n = 0
    try:
        init_schema(conn)
        for cidr in text.splitlines():
            cidr = cidr.strip()
            if not cidr or "/" not in cidr:
                continue
            import ipaddress
            try:
                net = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue
            if net.version != 4:
                continue
            # 教育网段无城市：city 留空；province 由网段号经验表（保守：不标省份的
            # 段仅标 CERNET/教育网 ISP）。
            label = netname_hint(net)
            upsert_range(
                conn, str(net.network_address), str(net.broadcast_address),
                {"country": "CN", "isp": "教育网", "province": label, "city": ""},
                weight=WEIGHT, source="cernet", commit_unix=cu,
            )
            n += 1
        conn.commit()
    finally:
        conn.close()
    print(f"geoip_enrich_cernet: upserted {n} ranges (city suppressed)")
    return 0


def netname_hint(net: ipaddress.IPv4Network) -> str:
    """CERNET 区域中心经验表（202.x.119/118 等骨干段；粗粒度即可——city 抑制是关键）。"""
    third = list(net.network_address.packed)[1]
    table = {
        45: "北京", 46: "北京", 47: "北京", 48: "北京",
        112: "上海", 113: "上海",
        114: "广州", 115: "广州",
        116: "成都", 117: "成都",
        118: "西安", 119: "西安",
        120: "武汉", 121: "武汉",
        122: "沈阳", 123: "沈阳",
        124: "南京", 125: "南京",
    }
    return table.get(third, "")


if __name__ == "__main__":
    sys.exit(main())
