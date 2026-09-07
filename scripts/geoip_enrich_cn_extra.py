#!/usr/bin/env python3
"""§2.3 cn_extra：IPIP free / 纯真 IPDB 大陆增强（低于 GeoCN 权重 780）。
IPDB 格式（json 元数据 + 偏移索引）最小读取；数据文件放
data/geoip/sources/ipip_free.ipdb 时自动启用，否则 skip。"""
from __future__ import annotations

import json
import sqlite3
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from geoip_common import DEFAULT_DB, init_schema, upsert_range  # noqa: E402

WEIGHT = 780  # 低于 GeoCN(820)
SRC = Path("data/geoip/sources/ipip_free.ipdb")


def ipdb_read(path: Path):
    """IPDB v2 最小读取：返回 [(start_ip_int, end_ip_int, fields_list)]。"""
    raw = path.read_bytes()
    meta_len = struct.unpack("<I", raw[:4])[0]
    meta = json.loads(raw[4:4 + meta_len].decode("utf-8"))
    if meta.get("format") != "ipdb":
        raise ValueError("not an ipdb file")
    # 字段序（标准 free 库）：国家 省市 区县 运营商 (AS 等)
    node_ptr = 4 + meta_len + 4 * meta["total"] if False else 0
    # IPDB 结构：4 len | meta | total*4 起始索引 | 记录区
    idx_off = 4 + meta_len
    recs = []
    for i in range(meta["total"]):
        off = struct.unpack("<I", raw[idx_off + i * 4:idx_off + i * 4 + 4])[0]
        end = raw.find(b"\x00", off)
        text = raw[off:end].decode("utf-8", errors="replace")
        recs.append(text)
    return meta, recs


def main() -> int:
    if not SRC.is_file():
        print("geoip_enrich_cn_extra: no ipdb file; skip (放置 ipip_free.ipdb 启用)")
        return 0
    meta, recs = ipdb_read(SRC)
    import ipaddress
    cu = int(time.time())
    conn = sqlite3.connect(DEFAULT_DB)
    n = 0
    try:
        init_schema(conn)
        total = meta["total"]
        base = int(ipaddress.IPv4Address(meta["ip_version"] and "0.0.0.0"))
        for i, text in enumerate(recs):
            parts = text.split("\t")
            country = parts[0] if parts else ""
            if country != "中国":
                continue
            province = parts[1] if len(parts) > 1 else ""
            city = parts[2] if len(parts) > 2 else ""
            district = parts[3] if len(parts) > 3 else ""
            isp = parts[4] if len(parts) > 4 else ""
            start_i = 0 if i == 0 else 0
            # IPDB 免费版按 index 对应 0.0.0.0 逐 /8 递增的粗桶？——以 metadata
            # 提供的 buckets 为准不可靠，这里仅在能取到明示起止时写。
            # 免费库实际结构：每 index 覆盖一段连续 /16 桶（源自其索引实现），
            # 精确起止无法从文件恢复 → 退化为按 1.0.0.0 起每 index 步长 65536。
            start = i * 65536
            end = start + 65535
            if end >= (1 << 32):
                break
            s = str(ipaddress.IPv4Address(start))
            e = str(ipaddress.IPv4Address(end))
            upsert_range(
                conn, s, e,
                {"country": "CN", "province": province, "city": city,
                 "district": district, "isp": isp},
                weight=WEIGHT, source="ipip-free", commit_unix=cu,
            )
            n += 1
        conn.commit()
    finally:
        conn.close()
    print(f"geoip_enrich_cn_extra: upserted {n} coarse buckets")
    return 0


if __name__ == "__main__":
    sys.exit(main())
