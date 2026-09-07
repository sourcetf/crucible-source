#!/usr/bin/env python3
"""Offline GeoIP merge — init schema, seed, import layer dirs, write SOURCES.json."""
from __future__ import annotations

import argparse
import json
import sqlite3
import time
from pathlib import Path

from geoip_common import SEED_RANGES, init_schema, upsert_range, write_sources_meta

# §5 信任权重（最终保留侧）：目录名前两位 → 权重。
LAYER_WEIGHTS = {
    "01": 900,   # cloud：rezmoss/cloud-provider-ip-addresses 等聚合
    "02": 990,   # cloud official：官方 geofeed / OCI public_ip_ranges（压倒性最高）
    "03": 990,   # RFC8805 geofeed 层（如走层路径导入）
    "05": 300,   # hosting：ipapi.is 免费 Sample（弱 IDC 兜底）
    "08": 990,   # RIR 发现的运营商 geofeed（层路径时）
    "10": 400,   # china-operator-ip：中国运营商 CIDR（噪声，低权）
    "20": 520,   # 全球城市骨架：GeoLite2-City (sapics)
    "30": 600,   # RIR delegated：国家基线 + unannounced 标记
    "40": 820,   # ASN/org：IPtoASN / GeoLite2-ASN
}


def import_layer_dir(
    conn: sqlite3.Connection,
    layer_dir: Path,
    weight: int,
    source: str,
    commit_unix: int,
) -> int:
    n = 0
    for path in sorted(layer_dir.glob("*.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            start = row.get("ip_start") or row.get("start")
            end = row.get("ip_end") or row.get("end") or start
            if not start:
                continue
            fields = {k: row.get(k, "") for k in (
                "country", "region", "province", "city", "district", "isp", "dc",
                "asn", "as_org", "cloud_provider", "cloud_region", "cloud_service",
                "hosting", "division_code",
            )}
            row_cu = int(row.get("commit_unix") or commit_unix)
            upsert_range(
                conn, start, end, fields, weight=weight, source=source, commit_unix=row_cu
            )
            n += 1
    return n


def seed_samples(conn: sqlite3.Connection, commit_unix: int) -> int:
    cur = conn.execute("SELECT COUNT(*) FROM geoip")
    if cur.fetchone()[0] > 0:
        return 0
    n = 0
    for start, end, fields in SEED_RANGES:
        upsert_range(
            conn, start, end, fields, weight=100, source="seed", commit_unix=commit_unix
        )
        n += 1
    return n


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="data/geoip/current/geoip.sqlite")
    ap.add_argument("--layers", default="data/geoip/current", help="scan 01-cloud … subdirs")
    ap.add_argument("--init-schema", action="store_true")
    ap.add_argument("--seed", action="store_true")
    ap.add_argument("--import-layers", action="store_true")
    ap.add_argument(
        "--commit-unix",
        type=int,
        default=0,
        help="upstream commit unix for epoch columns (default: now)",
    )
    args = ap.parse_args()
    path = Path(args.db)
    path.parent.mkdir(parents=True, exist_ok=True)
    fresh = not path.exists()
    commit_unix = args.commit_unix or int(time.time())

    conn = sqlite3.connect(path)
    try:
        if args.init_schema or fresh or args.seed or args.import_layers:
            init_schema(conn)
        inserted = seed_samples(conn, commit_unix) if args.seed else 0
        imported = 0
        if args.import_layers:
            layers_root = Path(args.layers)
            meta: dict[str, object] = {}
            for sub in sorted(layers_root.iterdir()):
                if not sub.is_dir() or not sub.name[:2].isdigit():
                    continue
                # §5 信任权重：目录前缀映射到标准权重表；未列出的回退 50+NN。
                weight = LAYER_WEIGHTS.get(sub.name[:2], 50 + int(sub.name[:2]))
                n = import_layer_dir(conn, sub, weight, sub.name, commit_unix)
                imported += n
                meta[sub.name] = {
                    "rows": n,
                    "weight": weight,
                    "commit_unix": commit_unix,
                }
            write_sources_meta(layers_root / "SOURCES.json", meta)
        conn.commit()
        if imported:
            print(f"imported {imported} rows into {path} (commit_unix={commit_unix})")
        elif inserted:
            print(f"seeded {inserted} demo ranges into {path} (commit_unix={commit_unix})")
        elif fresh or args.init_schema:
            print(f"initialized {path}")
        else:
            print(f"exists {path}")
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
