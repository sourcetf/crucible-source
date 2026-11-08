#!/usr/bin/env python3
"""§2.6 ripe_anycast_extract：RIPE whois dump 中 netname 含 ANYCAST/Anycast 的段
→ anycast 表。数据源 data/geoip/sources/ripe.db（geoip_enrich_netorg 已下载），
`.db` 不可用时退回流式读同目录的 `ripe.db.gz`。"""
from __future__ import annotations

import gzip
import re
import sqlite3
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from geoip_common import DEFAULT_DB, init_schema, sources_dir, upsert_anycast  # noqa: E402

DUMP = sources_dir() / "ripe.db"
DUMP_GZ = sources_dir() / "ripe.db.gz"
ANYCAST_RE = re.compile(r"anycast", re.I)
RANGE_RE = re.compile(r"^(\d+\.\d+\.\d+\.\d+)\s*-\s*(\d+\.\d+\.\d+\.\d+)$")


def _open_dump():
    """优先未压缩的 ripe.db；否则流式读 ripe.db.gz。

    RIPE 全量 dump 解压后约 2GB。磁盘紧张时 geoip_enrich_netorg 解不出来，
    会留下一个 **0 字节** 的 ripe.db —— 老代码只判 `is_file()`，于是读到空文件，
    rc=0 且打印 "0 anycast ranges"，anycast 功能静默失效整条链都不报错。
    这里要求 ≥1MB，并在只有 .gz 时直接流式解压（不落盘、不占额外空间）。
    """
    for p in (DUMP, DUMP_GZ):
        try:
            if p.is_file() and p.stat().st_size > 1_000_000:
                return gzip.open(p, "rt", encoding="utf-8", errors="replace") if p.suffix == ".gz" \
                    else p.open(encoding="utf-8", errors="replace")
        except OSError:
            continue
    return None


def main() -> int:
    f = _open_dump()
    if f is None:
        print("geoip_enrich_ripe_anycast_extract: 无可用 ripe.db/ripe.db.gz（跳过）")
        return 0
    cu = int(time.time())
    conn = sqlite3.connect(DEFAULT_DB)
    n = 0
    try:
        init_schema(conn)
        cur_obj: dict = {}
        with f:
            for line in f:
                line = line.rstrip("\n")
                if not line:
                    if cur_obj.get("type") == "inetnum" and cur_obj.get("anycast"):
                        m = RANGE_RE.match(cur_obj.get("range", ""))
                        if m:
                            upsert_anycast(conn, m.group(1), m.group(2),
                                           source="ripe-anycast", commit_unix=cu)
                            n += 1
                    cur_obj = {}
                    continue
                if line.startswith("%"):
                    continue
                key, _, val = line.partition(":")
                key = key.strip().lower()
                val = val.strip()
                if key == "inetnum":
                    cur_obj["type"] = "inetnum"
                    cur_obj["range"] = val
                elif key == "netname" and ANYCAST_RE.search(val):
                    cur_obj["anycast"] = True
        conn.commit()
    finally:
        conn.close()
    print(f"geoip_enrich_ripe_anycast_extract: {n} anycast ranges")
    return 0


if __name__ == "__main__":
    sys.exit(main())
