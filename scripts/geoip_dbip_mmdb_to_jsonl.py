#!/usr/bin/env python3
"""DB-IP City/ASN Lite (mmdb) → GeoIP layer JSONL 转换器（离线验证/对照用）。

背景：生产 fetch 链接（`geoip_fetch_layers.py`）把 DB-IP 系列为源库黑名单
（`geoip_blacklist.py`，历史污染名单），**本脚本不会**绕过该黑名单去联网抓取；
它只读取操作者已下载到本地的 `.mmdb` 文件，把它转成 `geoip_update.sh` 能吃下的
标准层格式（`current/<NN-dir>/*.jsonl`），用于 U-08 数据质量对照与可复现流水线
验证。生产是否启用该层由操作者决定（层目录名前缀决定权重，见 geoip_merge.py）。

mmdb 记录 → 字段映射：
  * City Lite：country=country.iso_code；province=subdivisions[0]；city=city；
    district=subdivisions[1]（若有）。DB-IP 只有英文地名（中文仅国家/大洲名），
    因此产出的 CN 城市是 ASCII 小地名 —— 这正是 §23.3「DB-IP 曾把国内标成英文
    乡镇名需抑制」的数据源限制，需 GeoCN/QQWry 等 CJK 层补齐。
  * ASN Lite：asn=autonomous_system_number；as_org=autonomous_system_organization。
  * commit_unix 取 mmdb metadata.build_epoch，供合并侧 epoch 对照。

用法：
  python3 scripts/geoip_dbip_mmdb_to_jsonl.py \
      --mmdb dbip-city-lite-2026-10.mmdb \
      --layer-dir data/geoip/current/20-city-dbip --name dbip-city.jsonl
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import sys
import time
from pathlib import Path

try:
    import maxminddb
except ImportError:  # pragma: no cover - 依赖提示
    print("error: 需要 maxminddb（python3 -m pip install --user maxminddb）", file=sys.stderr)
    raise SystemExit(2)


def _name(rec: dict, key: str, lang_pref: tuple[str, ...] = ("zh-CN", "en")) -> str:
    node = rec.get(key)
    if not isinstance(node, dict):
        return ""
    names = node.get("names")
    if not isinstance(names, dict):
        return ""
    for lang in lang_pref:
        v = names.get(lang)
        if isinstance(v, str) and v.strip():
            return v.strip()
    for v in names.values():
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def _subdivision(rec: dict, idx: int) -> str:
    subs = rec.get("subdivisions")
    if not isinstance(subs, list) or len(subs) <= idx:
        return ""
    return _name(subs[idx], "names") if isinstance(subs[idx], dict) else ""


def _city_fields(rec: dict) -> dict:
    return {
        "country": _name(rec, "country", ("iso_code", "zh-CN", "en")) or "",
        "province": _subdivision(rec, 0),
        "city": _name(rec, "city"),
        "district": _subdivision(rec, 1),
    }


def _asn_fields(rec: dict) -> dict:
    asn = rec.get("autonomous_system_number")
    org = rec.get("autonomous_system_organization")
    return {
        "asn": str(asn) if isinstance(asn, int) and asn > 0 else "",
        "as_org": org.strip() if isinstance(org, str) else "",
    }


def convert(mmdb_path: Path, out_path: Path, *, max_rows: int = 0) -> dict:
    reader = maxminddb.open_database(str(mmdb_path))
    meta = reader.metadata()
    db_type = (meta.database_type or "").lower()
    is_asn = "asn" in db_type
    commit_unix = int(meta.build_epoch or time.time())
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = out_path.with_suffix(out_path.suffix + ".tmp")
    rows = 0
    by_country: dict[str, int] = {}
    started = time.time()
    with tmp.open("w", encoding="utf-8") as f:
        try:
            for network, rec in reader:
                if not isinstance(rec, dict):
                    continue
                if is_asn:
                    fields = _asn_fields(rec)
                    if not fields["asn"]:
                        continue
                else:
                    fields = _city_fields(rec)
                    if not fields["country"]:
                        continue
                # 只写非空字段，减小层体积（merge 侧对缺字段按空处理）。
                fields = {k: v for k, v in fields.items() if v}
                fields["ip_start"] = str(network.network_address)
                fields["ip_end"] = str(network.broadcast_address)
                fields["commit_unix"] = commit_unix
                f.write(json.dumps(fields, ensure_ascii=False, separators=(",", ":")) + "\n")
                rows += 1
                if not is_asn and rows <= 3000000:
                    cc = fields.get("country", "")
                    by_country[cc] = by_country.get(cc, 0) + 1
                if max_rows and rows >= max_rows:
                    break
        finally:
            reader.close()
    os.replace(tmp, out_path)
    return {
        "db_type": meta.database_type,
        "build_epoch": commit_unix,
        "rows": rows,
        "out": str(out_path),
        "bytes": out_path.stat().st_size,
        "elapsed": round(time.time() - started, 2),
        "top_countries": sorted(by_country.items(), key=lambda x: -x[1])[:10],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="DB-IP mmdb → GeoIP layer JSONL")
    ap.add_argument("--mmdb", required=True, help="本地 dbip-*.mmdb 文件")
    ap.add_argument("--out", help="输出 jsonl 路径（默认 <layer-dir>/<name>）")
    ap.add_argument("--layer-dir", help="层目录（如 data/geoip/current/20-city-dbip）")
    ap.add_argument("--name", default="dbip.jsonl", help="输出文件名")
    ap.add_argument("--max-rows", type=int, default=0, help="最多转换 N 行（冒烟用）")
    args = ap.parse_args()
    if not args.out:
        if not args.layer_dir:
            ap.error("需要 --out 或 --layer-dir")
        args.out = str(Path(args.layer_dir) / args.name)
    stats = convert(Path(args.mmdb), Path(args.out), max_rows=args.max_rows)
    print(json.dumps(stats, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
