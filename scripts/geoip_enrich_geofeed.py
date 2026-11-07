#!/usr/bin/env python3
"""Geofeed CSV import (offline demo + optional URL fetch).

三种输入（择一，按优先级）：
  1. `--urls-file PATH`：自定义 geofeed 供给层（JSON，`{"urls":[...]}` 或纯数组）。
     由面板 `POST /api/geoip/geofeed/refresh` 写出、`geoip_update.sh --only=geofeed` 消费。
     每个 URL 按 **RFC8805**（`prefix,country,region,city[,postal]`，无表头）解析导入，
     source=`custom-geofeed`（权重默认 800，可 `--weight` 覆盖）。
  2. `--url URL`：单个 RFC8805/CSV geofeed。
  3. 都不给：内置 DEMO_CSV（离线演示）。

生产路径不调 Python（§23.1 铁律 2）；本脚本只由离线更新链调起。面板侧只落一份
**声明式数据**供给层，不向 Python 传命令。
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import sqlite3
from pathlib import Path

from geoip_common import DEFAULT_DB, SOURCES_JSON, init_schema, upsert_range, write_sources_meta

try:
    from geoip_http import fetch
except ImportError:
    fetch = None  # type: ignore


DEMO_CSV = """start,end,country,region,city,isp
203.0.113.20/32,203.0.113.20/32,JP,13,Tokyo,GeofeedDemo
"""

# Geofeed 里按国家码过滤的占位/特殊码（与 geoip_enrich_rir_geofeed.py 同口径）。
_SKIP_COUNTRY = ("ZZ", "XX", "A1", "A2", "")


def parse_row(row: dict[str, str]) -> tuple[str, str, dict[str, str]] | None:
    start = row.get("start", "").split("/")[0]
    end = row.get("end", start).split("/")[0]
    if not start:
        return None
    return start, end, {
        "country": row.get("country", ""),
        "region": row.get("region", ""),
        "city": row.get("city", ""),
        "isp": row.get("isp", ""),
        "source": "geofeed",
    }


def parse_rfc8805(text: str) -> list[tuple[str, str, dict[str, str]]]:
    """解析 RFC8805 geofeed（`prefix,country,region,city[,postal]`，无表头）。"""
    import ipaddress

    out: list[tuple[str, str, dict[str, str]]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(",")
        if len(parts) < 3:
            continue
        prefix, country = parts[0].strip(), parts[1].strip().upper()
        if not prefix or country in _SKIP_COUNTRY:
            continue
        try:
            net = ipaddress.ip_network(prefix, strict=False)
        except ValueError:
            continue
        if net.version != 4:
            # 本项目库/schema 以 v4 为主（merge 同理只导 v4 层）。
            continue
        region = parts[2].strip() if len(parts) > 2 else ""
        city = parts[3].strip() if len(parts) > 3 else ""
        out.append(
            (
                str(net.network_address),
                str(net.broadcast_address),
                {"country": country, "region": region, "city": city},
            )
        )
    return out


def load_urls_file(path: Path) -> list[str]:
    """读供给层 JSON：`{"urls":[...]}` 或 `[...]`；非法内容报错（不静默）。"""
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        data = data.get("urls", [])
    if not isinstance(data, list):
        raise ValueError(f"{path}: 期望 {{\"urls\":[...]}} 或数组")
    urls = [str(u).strip() for u in data if str(u).strip()]
    return urls


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=DEFAULT_DB)
    ap.add_argument("--url", default="", help="optional single geofeed CSV URL (RFC8805/demo CSV)")
    ap.add_argument("--urls-file", default="", help="JSON supply file with a list of geofeed URLs")
    ap.add_argument("--weight", type=int, default=800)
    args = ap.parse_args()

    path = Path(args.db)
    conn = sqlite3.connect(path)
    n = 0
    try:
        init_schema(conn)
        if args.urls_file:
            urls = load_urls_file(Path(args.urls_file))
            if not urls:
                print("geoip_enrich_geofeed: 供给层没有 URL")
            if fetch is None:
                raise RuntimeError("geoip_http.fetch 不可用，无法下载自定义 geofeed")
            ok = fails = 0
            for url in urls:
                try:
                    text = fetch(url, use_tor=False).decode("utf-8", errors="replace")
                except Exception as exc:  # noqa: BLE001 —— 单 URL 失败不中断其余
                    fails += 1
                    print(f"warn: geofeed {url}: {exc}")
                    continue
                rows = parse_rfc8805(text)
                for start, end, fields in rows:
                    upsert_range(conn, start, end, fields, weight=args.weight, source="custom-geofeed")
                    n += 1
                ok += 1
            conn.commit()
            write_sources_meta(
                Path(SOURCES_JSON),
                {"custom-geofeed": {"rows": n, "urls": len(urls), "ok": ok, "fails": fails}},
            )
            print(f"geoip_enrich_geofeed: custom geofeed imported {n} rows (ok={ok} fails={fails})")
            return 0

        text = DEMO_CSV
        if args.url and fetch:
            text = fetch(args.url, use_tor=False).decode("utf-8", errors="replace")

        reader = csv.DictReader(io.StringIO(text))
        for row in reader:
            parsed = parse_row(row or {})
            if not parsed:
                continue
            start, end, fields = parsed
            upsert_range(conn, start, end, fields, weight=args.weight, source="geofeed")
            n += 1
        conn.commit()
        write_sources_meta(Path(SOURCES_JSON), {"geofeed": {"rows": n, "url": args.url or "demo"}})
        print(f"geoip_enrich_geofeed: imported {n} rows")
        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(main())
