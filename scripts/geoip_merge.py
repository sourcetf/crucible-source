#!/usr/bin/env python3
"""Offline GeoIP merge — init schema, seed, import layer dirs, write SOURCES.json."""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import time
from pathlib import Path

from geoip_common import (
    DEFAULT_DB,
    SEED_RANGES,
    current_dir,
    init_schema,
    upsert_range,
    write_sources_meta,
)

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


def _load_panel_source_overrides():
    """读取面板设的「源权重 / 启用开关」，让它们**真的生效**。

    Wave-25 功能审查判定此处是**伪实现**：面板（`/api/geoip/sources`）能改 `panel_sources.weight`
    并双写 `panel.toml`、还能回显，但合并只用 `LAYER_WEIGHTS`（离线常量），全仓没有任何消费者，
    于是"改权重"对查询结果毫无影响。这里把面板值接成**合并期覆盖**（源权重天然是合并期语义）：
    `enabled=false` 的层整层跳过导入；`weight` 覆盖同名层的权重。

    取值顺序：`state/geoip/panel.toml [sources]` → `data/geoip/panel.toml [sources]` →
    `data/geoip/panel.sqlite` 的 `panel_sources` 表（name/weight/enabled）。任何一步失败都
    静默跳过（合并绝不能因为面板文件损坏而失败）。
    """
    out = {}
    import os, json
    try:
        import tomllib as _t
    except Exception:  # Python < 3.11
        _t = None
    cands = [
        os.environ.get("CRUCIBLE_GEOIP_PANEL_TOML"),
        "state/geoip/panel.toml",
        "/crucible/state/geoip/panel.toml",
        "data/geoip/panel.toml",
        "/crucible/data/geoip/panel.toml",
    ]
    for c in cands:
        if not c or not os.path.isfile(c) or _t is None:
            continue
        try:
            with open(c, "rb") as fh:
                doc = _t.load(fh)
            srcs = (doc or {}).get("sources") or {}
            for name, v in srcs.items():
                if isinstance(v, dict):
                    rec = {}
                    if "weight" in v:
                        rec["weight"] = int(v["weight"])
                    if "enabled" in v:
                        rec["enabled"] = bool(v["enabled"])
                    out[name] = rec
                elif isinstance(v, int):
                    out[name] = {"weight": int(v)}
        except Exception:
            pass
    for db in ["data/geoip/panel.sqlite", "/crucible/data/geoip/panel.sqlite"]:
        if not os.path.isfile(db):
            continue
        try:
            import sqlite3
            with sqlite3.connect(f"file:{db}?mode=ro", uri=True) as c:
                for name, weight, enabled in c.execute(
                    "SELECT name, weight, enabled FROM panel_sources"
                ):
                    rec = out.setdefault(name, {})
                    if weight is not None:
                        rec["weight"] = int(weight)
                    if enabled is not None:
                        rec["enabled"] = bool(enabled)
        except Exception:
            pass
    return out


PANEL_SOURCE_OVERRIDES = _load_panel_source_overrides()


def import_layer_dir(
    conn: sqlite3.Connection,
    layer_dir: Path,
    weight: int,
    source: str,
    commit_unix: int,
) -> int:
    n = 0
    for path in sorted(layer_dir.glob("*.jsonl")):
        # 逐行流式读取：真实层文件可达数百 MB（GeoLite2/ASN 层），
        # `read_text().splitlines()` 会同时分配原文 + 行列表，峰值内存翻几倍。
        with path.open(encoding="utf-8", errors="replace") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError as e:
                    print(
                        f"warn: {path}:{lineno}: bad JSON ({e.msg}), skipped",
                        file=sys.stderr,
                    )
                    continue
                if not isinstance(row, dict):
                    continue
                start = row.get("ip_start") or row.get("start")
                end = row.get("ip_end") or row.get("end") or start
                if not start:
                    continue
                fields = {k: row.get(k, "") for k in (
                    "country", "region", "province", "city", "district", "isp", "dc",
                    "asn", "as_org", "net_org",
                    "cloud_provider", "cloud_region", "cloud_service",
                    "hosting", "division_code",
                )}
                try:
                    row_cu = int(row.get("commit_unix") or commit_unix)
                except (TypeError, ValueError):
                    row_cu = commit_unix
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
    ap.add_argument("--db", default=DEFAULT_DB)
    ap.add_argument("--layers", default=str(current_dir()), help="scan 01-cloud … subdirs")
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
    # SQLite 默认 busy_timeout=0：抓到锁就立刻报 "database is locked"。
    # 更新与面板/其他进程并发时，等一会儿比直接失败强（真并发由单实例锁挡住）。
    conn.execute("PRAGMA busy_timeout = 30000")
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
                # 面板的「源权重 / 启用」优先（Wave-25：此前面板值无人消费 = 伪实现）。
                _ov = PANEL_SOURCE_OVERRIDES.get(sub.name, {})
                if _ov.get("enabled") is False:
                    meta[sub.name] = {"rows": 0, "weight": 0,
                                      "skipped": "panel: source disabled"}
                    continue
                weight = _ov.get("weight") or LAYER_WEIGHTS.get(
                    sub.name[:2], 50 + int(sub.name[:2])
                )
                if _ov:
                    meta_note = "panel"   # 供 finish 阶段标注该层权重来自面板
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
