#!/usr/bin/env python3
"""§3 黑名单：被用户认定「数据库有问题」的源库注册表 + 手工 CIDR 列表。

源库黑名单（硬拒绝，永不下载/合并；merge/update/ASN enrich 全路径拦截）：
- Ip2Region 系：lionsoul2014/ip2region（06-ip2region，历史权重 780 CN / 480 world）、
  hel2o ip2region_n.xdb（815）、ip2region_v4_geocn.xdb（818）
- DB-IP 系：dbip-city-*.mmdb（740 / 降权 500）、dbip-asn-*.mmdb（730）

用法：
  python3 geoip_blacklist.py --list                 # 列出全部注册表 + CIDR
  python3 geoip_blacklist.py --add 203.0.113.0/24   # 追加手工 CIDR 黑名单
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

DEFAULT = Path("data/geoip/blacklist.json")

# §3.1/§3.2 源库黑名单：source 名匹配（SQL LIKE 模式）+ 历史权重戳（purge 用）。
SOURCE_BLACKLIST: list[dict] = [
    {
        "id": "ip2region",
        "source_patterns": ["%ip2region%", "06-ip2region%"],
        "weights": [480, 780, 815, 818],
        "artifacts": ["*.xdb"],
        "meta_flag": "ip2region_blacklisted",
    },
    {
        "id": "dbip",
        "source_patterns": ["%dbip%", "dbip-%"],
        "weights": [740, 730, 500],
        "artifacts": ["*.mmdb"],
        "meta_flag": "dbip_blacklisted",
    },
]

# URL 级硬拒绝（fetch 脚本同步引用同样的关键词）。
BLACKLIST_URL_PATTERNS = (r"ip2region", r"db-ip\.com|dbip")


def source_blocked(source_name: str) -> bool:
    """源名是否命中源库黑名单（merge/enrich 全路径拦截用）。"""
    low = (source_name or "").lower()
    return any(low.find(p.strip("%")) >= 0 for entry in SOURCE_BLACKLIST
               for p in entry["source_patterns"])


def url_blocked(url: str) -> bool:
    import re
    return any(re.search(p, url, re.I) for p in BLACKLIST_URL_PATTERNS)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--add", action="append", default=[], help="CIDR or IP to blacklist")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--file", default=str(DEFAULT))
    args = ap.parse_args()
    path = Path(args.file)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {"entries": []}
    if path.is_file():
        data = json.loads(path.read_text(encoding="utf-8"))
    if args.add:
        for item in args.add:
            if item not in data["entries"]:
                data["entries"].append(item)
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        print(f"blacklist: {len(data['entries'])} cidr entries")
    elif args.list or not args.add:
        print(json.dumps({"source_blacklist": [
            {"id": e["id"], "weights": e["weights"], "meta_flag": e["meta_flag"]}
            for e in SOURCE_BLACKLIST
        ], **data}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
