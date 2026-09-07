#!/usr/bin/env python3
"""§2.3 纯真 QQWry（权重 800）：真 .dat 解析 + 脏串清洗。

清洗规则（标准）：剥离 –北京–/【】 等装饰串；country=CN 但城市写「美国/日本…」
的污染票在查询侧丢弃（Rust covering），这里仅负责把 GBK 记录规范成
country/province/city/isp 结构。
数据源（依次尝试）：SukkaW/QQWry-Dat / 民间镜像 qqwry.exe。
"""
from __future__ import annotations

import re
import socket
import struct
import sqlite3
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from geoip_common import DEFAULT_DB, init_schema, upsert_range  # noqa: E402

WEIGHT = 800
SOURCES = [
    "https://github.com/SukkaW/QQWry-Dat/releases/latest/download/qqwry.dat",
    "https://qqwry.mirror.noc.one/qqwry.exe",
    "https://raw.githubusercontent.com/Felix2yu/QQWry-Dat/main/qqwry.dat",
]
DIRTY = re.compile(r"[–—\-]{1,2}[^–—\-]{1,12}[–—\-]{1,2}|【|】|\(.*?\)")

PROVINCE_HINTS = (
    "北京", "上海", "天津", "重庆", "河北", "山西", "内蒙古", "辽宁", "吉林",
    "黑龙江", "江苏", "浙江", "安徽", "福建", "江西", "山东", "河南", "湖北",
    "湖南", "广东", "广西", "海南", "四川", "贵州", "云南", "西藏", "陕西",
    "甘肃", "青海", "宁夏", "新疆", "香港", "澳门", "台湾",
)

ISP_HINTS = (
    "电信", "联通", "移动", "铁通", "教育网", "科技网", "长城宽带", "鹏博士",
    "广电", "电信通",
)


def fetch_dat() -> bytes | None:
    for url in SOURCES:
        try:
            import urllib.request
            req = urllib.request.Request(url, headers={"User-Agent": "crucible-geoip/1.0"})
            with urllib.request.urlopen(req, timeout=120) as r:
                data = r.read()
            if len(data) > 100000:
                print(f"qqwry: fetched {len(data)} bytes from {url}")
                return data
        except Exception as exc:
            print(f"warn: {url}: {exc}", file=sys.stderr)
    return None


class QQWry:
    """经典 QQWry .dat 格式（GBK，索引区 + 记录区，redirect 模式）。"""

    def __init__(self, data: bytes):
        self.data = data
        first, last = struct.unpack("<II", data[:8])
        self.first, self.last = first, last
        self.count = (last - first) // 7

    def _read_cstring(self, off: int) -> bytes:
        end = self.data.find(b"\x00", off)
        if end < 0:
            end = min(off + 512, len(self.data))
        return self.data[off:end]

    def _read_area(self, off: int) -> str:
        if off >= len(self.data) - 4:
            return ""
        mode = self.data[off]
        if mode in (1, 2):
            ptr = struct.unpack("<I", self.data[off + 1:off + 5])[0]
            if ptr >= len(self.data):
                return ""
            if mode == 2:
                return self._read_cstring(ptr).decode("gbk", errors="replace").strip()
            return self._read_cstring(ptr).decode("gbk", errors="replace").strip()
        return self._read_cstring(off).decode("gbk", errors="replace").strip()

    def record(self, idx: int) -> tuple[str, str, str, str]:
        rec_off = self.first + idx * 7
        ip_start = socket.inet_ntoa(self.data[rec_off:rec_off + 4])
        rec_ptr = struct.unpack("<I", self.data[rec_off + 4:rec_off + 8])[0]
        mode = self.data[rec_ptr]
        if mode == 1:
            country_ptr = struct.unpack("<I", self.data[rec_ptr + 1:rec_ptr + 5])[0]
            country = self._read_cstring(country_ptr).decode("gbk", errors="replace").strip()
            area_off = rec_ptr + 5
        elif mode == 2:
            country_ptr = struct.unpack("<I", self.data[rec_ptr + 1:rec_ptr + 5])[0]
            country = self._read_cstring(country_ptr).decode("gbk", errors="replace").strip()
            area_off = rec_ptr + 5
        else:
            country = self._read_cstring(rec_ptr).decode("gbk", errors="replace").strip()
            area_off = rec_ptr + len(self._read_cstring(rec_ptr)) + 1
        area = self._read_area(area_off)
        return ip_start, country, area, ""

    def ip_end_of(self, idx: int) -> str:
        if idx + 1 < self.count:
            rec_off = self.first + (idx + 1) * 7
            return socket.inet_ntoa(self.data[rec_off:rec_off + 4])
        # 最后一条：默认到 255.255.255.255 前一段末尾（保守截断到 223.255.255.255）
        return "223.255.255.255"


def clean(country: str, area: str) -> tuple[str, str, str, str]:
    country = DIRTY.sub("", country).strip()
    area = DIRTY.sub("", area).strip()
    isp = next((k for k in ISP_HINTS if k in country or k in area), "")
    province = next((p for p in PROVINCE_HINTS if p in country or p in area), "")
    city = ""
    if province and province in area and area != province:
        rest = area.replace(province, "", 1).strip()
        rest = re.sub(r"(市|地区|自治州|盟).*$", lambda m: m.group(0), rest)
        if rest and not any(k in rest for k in ISP_HINTS):
            city = rest[:12]
    elif country in PROVINCE_HINTS and area:
        city = area[:12]
    return country, province, city, isp


def main() -> int:
    data = fetch_dat()
    if not data:
        print("geoip_enrich_qqwry: no dat available; skip")
        return 1
    qq = QQWry(data)
    cu = int(time.time())
    conn = sqlite3.connect(DEFAULT_DB)
    n = 0
    try:
        init_schema(conn)
        for idx in range(qq.count):
            try:
                ip_start, country, area, _ = qq.record(idx)
            except (struct.error, IndexError):
                continue
            c, prov, city, isp = clean(country, area)
            if not c:
                continue
            ip_end = qq.ip_end_of(idx)
            try:
                import ipaddress
                if int(ipaddress.IPv4Address(ip_end)) < int(ipaddress.IPv4Address(ip_start)):
                    continue
            except ValueError:
                continue
            upsert_range(
                conn, ip_start, ip_end,
                {"country": c, "province": prov, "city": city, "isp": isp},
                weight=WEIGHT, source="qqwry", commit_unix=cu,
            )
            n += 1
            if n % 50000 == 0:
                conn.commit()
        conn.commit()
    finally:
        conn.close()
    print(f"geoip_enrich_qqwry: upserted {n} ranges (total index {qq.count})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
