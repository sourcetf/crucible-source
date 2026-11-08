#!/usr/bin/env python3
"""§2.3 纯真 QQWry（权重 800）：真 .dat 解析 + 脏串清洗。

文件格式（依 metowolf/qqwry.dat 仓库的 protocol.md，与 lumaqq《纯真IP数据库格式详解》一致）：
  - **全部整数小端**；文件分三段：[8 字节文件头][记录区][索引区]
  - 文件头：First Index Offset(4) + Last Index Offset(4)
  - 索引区：每条 7 字节 = [开始IP(4)][记录偏移(3)]
  - 记录区：每条 = [结束IP(4)][国家字段][地区字段]；字符串 GBK + \0 结尾。
    字段首字节为 0x01/0x02 时，其后 3 字节是偏移，指向另一处的 [国家][地区]。

旧实现有三处硬伤。它们一直没暴露，是因为三个数据源 URL 长期 404 —— 这条路
从来没在真数据上跑通过（实测换成可用源后：乱码率 100%）：
  1. 记录偏移按 **4 字节**读。格式是 3 字节，多读的那 1 字节正好是下一条索引项的
     开始 IP 高位 ⇒ 指针飞进几千万，解出来全是乱码；
  2. **没读结束IP**。记录区条目的前 4 字节就是结束IP，旧代码把它当成「无意义前缀」
     跳过，结束位置靠 `ip_end_of(idx)` 猜「下一条索引的开始IP − 1」；
  3. **IP 字节序搞反**。本源小端存储（按小端读 1589 个采样点全单调，按大端读 785 处
     逆序），旧代码用 `inet_ntoa` 直接按大端解释 ⇒ 每个 IP 都是字节颠倒的。
  改后实测（5000 条抽样 country 全部可用）：8.8.8.8 → 美国–加利福尼亚州–圣克拉拉–山景城
  | 谷歌公司；114.114.114.114 → 中国–江苏–南京 | 腾讯云；58.14.0.1 → 中国–山东–济南
  | 教育网/山东女子学院。

数据源（依次尝试）：metowolf/qqwry.dat 的 release 资产（每日更新）→ 民间镜像。
下载成功会缓存到 sources/qqwry.dat；全部源都拉不到时用缓存顶上。
"""
from __future__ import annotations

import ipaddress
import re
import socket
import struct
import sqlite3
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from geoip_common import DEFAULT_DB, init_schema, sources_dir, upsert_range  # noqa: E402

WEIGHT = 800
# 2026-11 实测：原来的三个源**全部 404/不可达**（SukkaW 与 Felix2yu 的仓库里
# 已没有 qqwry.dat，noc.one 镜像连不上）⇒ 这一档 weight 800 的国内源天天静默跳空。
# metowolf/qqwry.dat 的 release 资产可用（实测 200，27MB，每日更新），放第一位；
# 原来的三个留着当兜底（哪天复活就能自动接上）。
SOURCES = [
    "https://github.com/metowolf/qqwry.dat/releases/latest/download/qqwry.dat",
    "https://github.com/SukkaW/QQWry-Dat/releases/latest/download/qqwry.dat",
    "https://qqwry.mirror.noc.one/qqwry.exe",
    "https://raw.githubusercontent.com/Felix2yu/QQWry-Dat/main/qqwry.dat",
]
CACHE = sources_dir() / "qqwry.dat"
DIRTY = re.compile(r"[–—\-]{1,2}[^–—\-]{1,12}[–—\-]{1,2}|【|】|\(.*?\)")
SEP = re.compile(r"[–—\-]{1,2}|\s+")

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
_ISP_RE = re.compile("|".join(ISP_HINTS))


def fetch_dat() -> bytes | None:
    for url in SOURCES:
        try:
            import urllib.request
            req = urllib.request.Request(url, headers={"User-Agent": "crucible-geoip/1.0"})
            with urllib.request.urlopen(req, timeout=120) as r:
                data = r.read()
            if len(data) > 100000:
                print(f"qqwry: fetched {len(data)} bytes from {url}")
                # 缓存：下次所有源都挂掉时还能顶上（原子替换，别留半截文件）。
                try:
                    tmp = CACHE.with_name(CACHE.name + ".tmp")
                    tmp.write_bytes(data)
                    tmp.replace(CACHE)
                except OSError as exc:
                    print(f"warn: 写缓存 {CACHE} 失败: {exc}", file=sys.stderr)
                return data
        except Exception as exc:
            print(f"warn: {url}: {exc}", file=sys.stderr)
    try:
        if CACHE.is_file() and CACHE.stat().st_size > 100000:
            print(f"qqwry: 所有源不可用，改用缓存 {CACHE}（{CACHE.stat().st_size} bytes）")
            return CACHE.read_bytes()
    except OSError:
        pass
    return None


class QQWry:
    """按 protocol.md 解析 [文件头][记录区][索引区] 三段式 .dat。"""

    def __init__(self, data: bytes):
        if len(data) < 16:
            raise ValueError("文件过小")
        first, last = struct.unpack("<II", data[:8])
        if not (8 <= first < last <= len(data)) or (last - first) % 7:
            raise ValueError(f"索引区范围非法（first={first} last={last} size={len(data)}）")
        self.data = data
        self.first = first
        self.last = last
        self.count = (last - first) // 7 + 1
        self.little_ip = self._detect_ip_order()

    def _detect_ip_order(self) -> bool:
        """索引按开始IP升序。小端读若处处非降 ⇒ 小端（本源如此）；否则按大端（cz88 官方文件）。"""
        prev = -1
        step = max(1, self.count // 2000)
        for idx in range(0, self.count, step):
            e = self.data[self.first + idx * 7:self.first + idx * 7 + 7]
            if len(e) < 4:
                break
            v = int.from_bytes(e[:4], "little")
            if v < prev:
                return False
            prev = v
        return True

    def _ip(self, b4: bytes) -> str:
        # 小端存储时 4 字节是「小端整数」→ 反转回网络序再打印；大端存储直接打印。
        return socket.inet_ntoa(bytes(reversed(b4)) if self.little_ip else b4)

    def _str(self, off: int, depth: int = 0) -> tuple[str, int]:
        """读一个字符串字段；首字节 0x01/0x02 时跟一层 3 字节偏移。→(文本, 下一字段起点)"""
        d = self.data
        if depth > 6 or not (0 <= off < len(d)):
            return "", len(d)
        if d[off] in (1, 2):
            p = int.from_bytes(d[off + 1:off + 4], "little")
            return self._str(p, depth + 1)
        end = d.find(b"\x00", off)
        if end < 0:
            end = len(d)
        return d[off:end].decode("gbk", errors="replace"), end + 1

    def record(self, idx: int) -> tuple[str, str, str, str] | None:
        """→ (ip_start, ip_end, country, area)，坏条目返回 None。"""
        e = self.data[self.first + idx * 7:self.first + idx * 7 + 7]
        if len(e) < 7:
            return None
        start = self._ip(e[:4])
        ptr = int.from_bytes(e[4:7], "little")
        d = self.data
        if not (0 <= ptr < len(d) - 8):
            return None
        end = self._ip(d[ptr:ptr + 4])          # 记录区条目头 4 字节 = 结束IP
        pos = ptr + 4
        if d[pos] in (1, 2):
            p = int.from_bytes(d[pos + 1:pos + 4], "little")
            country, q = self._str(p)           # 指向 [国家][地区] 两个串
            area, _ = self._str(q)
        else:
            country, pos2 = self._str(pos)
            if pos2 < len(d) and d[pos2] in (1, 2):
                p = int.from_bytes(d[pos2 + 1:pos2 + 4], "little")
                area, _ = self._str(p)
            else:
                area, _ = self._str(pos2)
        return start, end, country, area


def _segments(s: str) -> list[str]:
    """按 –/—/-/空白切段，再逐段剥装饰（顺序很重要：先切段再剥，
    否则 "中国–江苏–南京" 会被 DIRTY 一次吃掉，省市就没了）。"""
    out = []
    for part in SEP.split(s):
        part = DIRTY.sub("", part).strip()
        if part:
            out.append(part)
    return out


def clean(country: str, area: str) -> tuple[str, str, str, str]:
    """→ (国家/地区串, 省, 市, ISP)。

    兼容两种形态：metowolf 新式的「中国–江苏–南京 | 腾讯云」（省市在国家串里）
    与老式的「中国 | 江苏南京电信」（省市在地区串里）。
    """
    cs = _segments(country)
    as_ = _segments(area)
    c_join = "".join(cs)
    a_join = "".join(as_)
    isp = next((k for k in ISP_HINTS if k in a_join), "") or next(
        (k for k in ISP_HINTS if k in c_join), ""
    )
    province = ""
    city = ""
    for src in (cs, as_):
        for k, seg in enumerate(src):
            hit = next((p for p in PROVINCE_HINTS if p in seg), "")
            if not hit:
                continue
            province = hit
            rest = seg[seg.find(hit) + len(hit):]
            if not rest and k + 1 < len(src):
                rest = src[k + 1]
            rest = _ISP_RE.sub("", rest).strip()
            city = rest[:12]
            break
        if province:
            break
    return c_join, province, city, isp


def _plausible(s: str) -> bool:
    s = DIRTY.sub("", s).strip()
    return bool(s) and "\ufffd" not in s


def main() -> int:
    data = fetch_dat()
    if not data:
        # 源不可达 ≠ 本步失败：只是这一档缺数据，跳过即可（与 cn_extra / anycast
        # 的 skip 语义一致）。返回 1 会让每日汇总天天报一次假失败，掩盖真问题。
        print("geoip_enrich_qqwry: 无可用 dat（源不可达且无缓存）—— 本步跳过，不计失败")
        return 0
    try:
        qq = QQWry(data)
    except ValueError as exc:
        print(f"geoip_enrich_qqwry: 不是 QQWry 三段式布局（{exc}）—— 跳过，不计失败")
        return 0

    # 抽样自检：布局判断错了宁可一行不导，也别把乱码灌进库里（weight 800 会盖掉
    # 正经源）。旧解析器就是「能解出东西但全是乱码」，正是这里的护栏要挡的情况。
    import random
    sample = random.Random(20261108).sample(range(qq.count), min(300, qq.count))
    good = 0
    for i in sample:
        r = qq.record(i)
        if r and _plausible(r[2]):
            good += 1
    ratio = good * 100 // max(len(sample), 1)
    if ratio < 50:
        print(
            f"geoip_enrich_qqwry: 抽样自检仅 {ratio}% 记录可解析（{good}/{len(sample)}）"
            f"—— 疑似格式变体，本次一行不导（避免乱码污染库）"
        )
        return 0

    cu = int(time.time())
    conn = sqlite3.connect(DEFAULT_DB)
    n = 0
    skipped = 0
    try:
        init_schema(conn)
        for idx in range(qq.count):
            r = qq.record(idx)
            if not r:
                skipped += 1
                continue
            start, end, country, area = r
            c, prov, city, isp = clean(country, area)
            if not c:
                skipped += 1
                continue
            try:
                if int(ipaddress.IPv4Address(end)) < int(ipaddress.IPv4Address(start)):
                    skipped += 1
                    continue
            except ValueError:
                skipped += 1
                continue
            upsert_range(
                conn, start, end,
                {"country": c, "province": prov, "city": city, "isp": isp},
                weight=WEIGHT, source="qqwry", commit_unix=cu,
            )
            n += 1
            if n % 50000 == 0:
                conn.commit()
        conn.commit()
    finally:
        conn.close()
    print(f"geoip_enrich_qqwry: upserted {n} ranges (索引 {qq.count} 条, 跳过 {skipped}, 自检 {ratio}%)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
