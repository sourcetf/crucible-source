#!/usr/bin/env python3
"""§2.5/§4 netorg：网段注册公司（net_org ≠ as_org）。

- APNIC/RIPE/AFRINIC whois 文本 dump：inetnum/inet6num + organisation join → 820
- ARIN bulk networks CSV（data/geoip/sources/arin_networks.csv 存在时）→ 850
- LACNIC：dump 铺 CIDR（几乎无 org）→ RDAP https://rdap.lacnic.net/rdap/ip/{addr}
  直连 403/429 限流 → Tor SOCKS 池（GEOIP_TOR_SOCKS）+ NEWNYM 换路 + resume：
  lacnic-rdap-done.txt 跳过；失败写 lacnic-rdap-failed.txt 下一轮统一重试；
  日志 data/geoip/logs/lacnic-rdap-resume.log。目标形态 20 worker + 5 备用实例，
  端口 9150–9174（GEOIP_TOR_SOCKS 全列）。无 tor 时 dump 照常、RDAP 跳过。
- NIR live RDAP（JPNIC/CNNIC/KRNIC/TWNIC/IRINN/IDNIC/VNNIC）→ 950
"""
from __future__ import annotations

import gzip
import os
import re
import shutil
import socket
import sqlite3
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from geoip_common import (  # noqa: E402
    DEFAULT_DB,
    init_schema,
    logs_dir,
    sources_dir,
    upsert_range,
)
# fetch：geoip_http 的旧接口兼容名（get_dump 拉 RIR 全量 dump、rdap_ip 的非 Tor 分支
# 都在调用它）。此前只导入了 http_get，两处调用直接 NameError:
# "name 'fetch' is not defined" —— apnic/ripe 的 dump 每次都被跳过。
from geoip_http import http_get, fetch, tor_socks_endpoints  # noqa: E402
from geoip_tor_pool import ensure_tor_pool  # noqa: E402

SOURCES = sources_dir()
LOG = logs_dir() / "lacnic-rdap-resume.log"
DONE = SOURCES / "lacnic-rdap-done.txt"
FAILED = SOURCES / "lacnic-rdap-failed.txt"
DUMPS = {
    "apnic": "https://ftp.apnic.net/public/apnic-db/apnic.db.gz",
    "ripe": "https://ftp.ripe.net/ripe/dbase/ripe.db.gz",
    "afrinic": "https://ftp.afrinic.net/pub/dbase/afrinic.db.gz",
    "lacnic": "https://ftp.lacnic.net/lacnic/dbase/lacnic.db.gz",
}
RANGE_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})\s*-\s*(\d{1,3}(?:\.\d{1,3}){3})$")
CIDR_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})$")

RDAP_NIR = {
    "JP": "https://rdap.jpnic.net/ip/",
    "CN": "https://rdap.cnnic.cn/ip/",
    "KR": "https://rdap.krnic.net/ip/",
    "TW": "https://rdap.twnic.net.tw/ip/",
    "IN": "https://rdap.irinn.in/ip/",
    "ID": "https://rdap.idnic.net.id/ip/",
    "VN": "https://rdap.vnnic.vn/ip/",
}


def log(msg: str) -> None:
    LOG.parent.mkdir(parents=True, exist_ok=True)
    with LOG.open("a", encoding="utf-8") as f:
        f.write(f"[{time.strftime('%Y-%m-%dT%H:%M:%S')}] {msg}\n")


def _usable(p: Path, floor: int = 1_000_000) -> bool:
    try:
        return p.is_file() and p.stat().st_size >= floor
    except OSError:
        return False


def get_dump(name: str, url: str) -> Path | None:
    """返回可流式解析的 dump 路径；拿不到就 None。

    返回的可能是 `{name}.db`，也可能是 `{name}.db.gz`（`parse_objects` 两者都认）。
    """
    out = SOURCES / f"{name}.db"
    gz = SOURCES / f"{name}.db.gz"
    if _usable(out):
        return out
    SOURCES.mkdir(parents=True, exist_ok=True)
    # 已经下过一份像样的 .gz（RIPE 376MB）就不要为了「解压失败」再重下几百 MB。
    if not _usable(gz):
        try:
            raw = fetch(url, timeout=1800)
        except Exception as exc:
            print(f"warn: dump {name}: {exc}", file=sys.stderr)
            return gz if _usable(gz, 1) else None
        tmp_gz = gz.with_name(gz.name + ".tmp")
        try:
            tmp_gz.write_bytes(raw)
            os.replace(tmp_gz, gz)  # 原子落位：不会留下半个 .gz
        except OSError as exc:
            print(f"warn: dump {name}: 写 {gz.name} 失败: {exc}", file=sys.stderr)
            try:
                tmp_gz.unlink()
            except OSError:
                pass
            return None
    # 流式解压到 .tmp，校验够大后原子替换。
    # 原实现 `dst.write(src.read())` 把整份 dump 读进内存：RIPE 解压后约 2GB，
    # 在 2GB 内存的机器上 OOM（且磁盘吃紧时 write 半途失败）→ 留下 **0 字节** 的
    # ripe.db：上面的 reuse 检查（>1MB）看不见它，anycast 提取读到空文件**静默产 0 条**，
    # 下一轮又要重下 376MB 的 .gz。改流式 + 校验 + 原子替换，并把失败说清楚。
    #
    # 还要先看盘：RIR 文本 dump 解压后是 .gz 的 5~6 倍（RIPE 376MB → 约 2GB），
    # 空间不够时那次 write 会把盘写满（曾把根分区顶到 104%）并留下半截文件，
    # 所以直接跳过解压、走下面的 .gz 流式退路，不碰磁盘。
    try:
        free = shutil.disk_usage(SOURCES).free
        need = gz.stat().st_size * 6
    except OSError:
        free, need = 0, 0
    if free < need:
        print(
            f"warn: dump {name}: 剩余空间 {free // 1_048_576}MB < 解压所需 "
            f"约 {need // 1_048_576}MB —— 跳过解压，直接流式读 {gz.name}",
            file=sys.stderr,
        )
        return gz if _usable(gz, 1) else None
    tmp_out = out.with_name(out.name + ".tmp")
    try:
        with gzip.open(gz, "rb") as src, tmp_out.open("wb") as dst:
            shutil.copyfileobj(src, dst, length=1 << 20)
        if not _usable(tmp_out):
            raise RuntimeError("解压后过小（磁盘满或源文件损坏）")
        os.replace(tmp_out, out)
        return out
    except Exception as exc:
        print(
            f"warn: dump {name} 解压失败（{exc}）——退回直接流式读 {gz.name}",
            file=sys.stderr,
        )
        try:
            tmp_out.unlink()
        except OSError:
            pass
        return gz if _usable(gz, 1) else None


def parse_objects(path: Path):
    """流式解析 RIR 文本 dump：产出 (kind, obj) —— kind ∈ inetnum|organisation。

    `path` 可以是 `.db` 也可以是 `.db.gz`（见 `get_dump` 的退路）。
    """
    obj: dict[str, str] = {}
    key = None
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line or line.startswith("%") or line.startswith("#"):
                yield from flush_object(obj)
                obj = {}
                key = None
                continue
            if line[0] in " \t" and key:
                obj[key] += " " + line.strip()
                continue
            k, _, v = line.partition(":")
            if not _:
                continue
            k = k.strip().lower()
            v = v.strip()
            if k == "inetnum" or k == "inet6num":
                flush_object(obj)
                obj = {"type": "inetnum", "range": v}
                key = "range"
                continue
            if k == "organisation" and "range" not in obj:
                flush_object(obj)
                obj = {"type": "organisation", "handle": v}
                key = "handle"
                continue
            key = k
            obj[k] = v
    yield from flush_object(obj)


def flush_object(obj: dict):
    if not obj:
        return
    if obj.get("type") == "inetnum":
        yield "inetnum", obj
    elif obj.get("type") == "organisation":
        yield "organisation", obj


def enrich_from_dump(db_name: str, path: Path, conn: sqlite3.Connection, cu: int) -> tuple[int, int]:
    """一遍流式：organisation 先进内存映射；inetnum 边解析边 upsert（join 内存映射）。"""
    orgs: dict[str, str] = {}
    pending: list[tuple[str, str, str | None, str]] = []
    total_inet = 0
    for kind, obj in parse_objects(path):
        if kind == "organisation":
            handle = (obj.get("handle") or "").upper()
            name = obj.get("org-name") or obj.get("organisation") or ""
            if handle and name:
                orgs[handle] = name
        else:
            rng = obj.get("range", "")
            m = RANGE_RE.match(rng)
            cidr = CIDR_RE.match(rng)
            if m:
                start, end = m.group(1), m.group(2)
            elif cidr:
                import ipaddress
                try:
                    net = ipaddress.ip_network(cidr.group(1), strict=False)
                except ValueError:
                    continue
                start, end = str(net.network_address), str(net.broadcast_address)
            else:
                continue
            if ":" in start:
                continue  # v6 表后续接入
            org_handle = (obj.get("org") or "").upper()
            descr = obj.get("descr") or obj.get("owner") or ""
            pending.append((start, end, org_handle, descr))
            total_inet += 1
        if len(pending) >= 50000:
            flush_pending(conn, orgs, pending, cu, db_name)
            pending.clear()
    flush_pending(conn, orgs, pending, cu, db_name)
    return total_inet, len(orgs)


def flush_pending(conn, orgs, pending, cu, db_name):
    for start, end, handle, descr in pending:
        net_org = orgs.get(handle or "", "")
        if not net_org and descr:
            # descr 常含公司名（首行）；避免滥用城市/省份描述——仅当无 org handle。
            net_org = descr.split(",")[0].strip()[:64]
        if not net_org:
            continue
        upsert_range(
            conn, start, end, {"net_org": net_org},
            weight=820, source=f"whois-{db_name}", commit_unix=cu,
        )


def arin_csv(conn: sqlite3.Connection, cu: int) -> int:
    csvp = SOURCES / "arin_networks.csv"
    if not csvp.is_file():
        return 0
    import csv as _csv
    n = 0
    with csvp.open(encoding="utf-8", errors="replace") as f:
        for row in _csv.reader(f):
            if not row or row[0].startswith("#"):
                continue
            if row[0].lower() == "netrange":
                header_seen = True
                continue
            if len(row) < 5:
                continue
            m = RANGE_RE.match(row[0])
            if not m:
                continue
            net_org = row[4].strip() if len(row) > 4 else ""
            if not net_org:
                continue
            upsert_range(conn, m.group(1), m.group(2),
                         {"net_org": net_org},
                         weight=850, source="arin-csv", commit_unix=cu)
            n += 1
    return n


def rdap_ip(base: str, addr: str, use_tor: bool, proxy=None) -> dict | None:
    url = base + addr
    try:
        if use_tor and proxy:
            return json.loads(fetch_via_tor(url, proxy))
        return json.loads(fetch(url, timeout=30))
    except Exception:
        return None


def fetch_via_tor(url: str, proxy: tuple[str, int]) -> bytes:
    from geoip_http import _socks5_connect
    import urllib.parse
    u = urllib.parse.urlparse(url)
    s = _socks5_connect(u.hostname, u.port or 443, proxy)
    ctx = socket.ssl(s)
    req = (f"GET {u.path or '/'} HTTP/1.1\r\nHost: {u.hostname}\r\n"
           f"User-Agent: crucible-geoip/1.0\r\nConnection: close\r\n\r\n")
    ctx.sendall(req.encode())
    buf = b""
    while True:
        chunk = ctx.recv(65536)
        if not chunk:
            break
        buf += chunk
    s.close()
    head, _, body = buf.partition(b"\r\n\r\n")
    if b" 200 " not in head.split(b"\r\n")[0]:
        code = head.split(b"\r\n")[0].split(b" ")[1] if b" " in head else b"?"
        raise RuntimeError(f"rdap http {code.decode()}")
    return body


def newnym(proxy: tuple[str, int]) -> None:
    """控制端口 = SOCKS 端口 + 100（约定布局 9050/9150…）；无密码认证。"""
    try:
        s = socket.create_connection((proxy[0], proxy[1] + 100), timeout=10)
        s.sendall(b'AUTHENTICATE ""\r\n')
        s.recv(64)
        s.sendall(b"SIGNAL NEWNYM\r\n")
        s.recv(64)
        s.close()
        log(f"NEWNYM sent to control {proxy[0]}:{proxy[1] + 100}")
    except OSError as exc:
        log(f"NEWNYM failed {proxy}: {exc}")


def lacnic_rdap_pass(conn: sqlite3.Connection, cu: int) -> None:
    """§B.4：LACNIC RDAP——多 tor 池（一 worker 一实例）+ 电路隔离 + 3 轮重试。"""
    workers = int(os.environ.get("GEOIP_RDAP_WORKERS", "20"))
    spare = int(os.environ.get("GEOIP_RDAP_SPARE", "5"))
    ports = ensure_tor_pool(workers + spare)
    n = len(ports)
    queue: list[tuple[str, str]] = []
    # LACNIC 的 dump 只铺 CIDR、几乎不带 org，所以挑「还没有 net_org」的行去查 RDAP。
    # 原查询是 `WHERE source LIKE %lacnic% AND net_org = `：两个错误叠在一起——
    # `%lacnic%` 没加引号（SQL 语法错误），且 `net_org =` 后面根本没有值。
    # 于是本函数每次都在 execute() 抛 OperationalError，整个 netorg 步骤从未真正跑过
    # （调用处是 `|| echo warn`，失败被吞掉）。
    rows = conn.execute(
        """SELECT rowid, ip_start FROM geoip
           WHERE source LIKE '%lacnic%'
             AND (net_org IS NULL OR net_org = '')"""
    ).fetchall()
    for rowid, start in rows:
        import ipaddress
        addr = str(ipaddress.ip_network(f"{start}/20", strict=False).network_address)
        queue.append((str(rowid), addr))
    done: set[str] = set()
    if DONE.is_file():
        done = set(DONE.read_text(encoding="utf-8").split())
    todo = [q for q in queue if q[0] not in done]
    if not todo:
        log("lacnic rdap: nothing to do")
        return
    log(f"lacnic rdap: queue={len(todo)} (done={len(done)}) pool={n}")
    pid = os.getpid()
    failures: list[str] = []
    ok_count = {"v": 0}
    lock = threading.Lock()

    def attempt(rowid: str, addr: str, slot: int, si: int) -> bool:
        circ = f"lacnic-w{slot}-{pid}-t{si}"
        url = "https://rdap.lacnic.net/rdap/ip/" + addr
        try:
            data = json.loads(http_get(url, prefer_tor=True,
                                       tor_socks=ports[slot],
                                       tor_circuit=circ).decode("utf-8", errors="replace"))
        except Exception:
            return False
        name = data.get("name") or ""
        for ent in data.get("entities", []):
            if "registrant" in ent.get("roles", []):
                v = ent.get("vcardArray", [])
                if len(v) > 1:
                    for item in v[1]:
                        if item[0] == "fn" and item[3]:
                            name = name or item[3]
        if not name:
            return True  # RDAP 成功但无 org——记 done 防重扫
        start = conn.execute(
            "SELECT ip_start, ip_end FROM geoip WHERE rowid=?", (rowid,)
        ).fetchone()
        if start:
            upsert_range(conn, start[0], start[1], {"net_org": name},
                         weight=950, source="rdap-lacnic", commit_unix=cu)
        return True

    # 最多 3 轮统一重试；每任务先本口，429/403（http_get 内 NEWNYM）再热切邻口
    pending = list(todo)
    for rnd in range(3):
        idx = {"i": 0}
        failures = []

        def worker() -> None:
            while True:
                with lock:
                    i = idx["i"]
                    idx["i"] += 1
                    if i >= len(pending):
                        return
                    rowid, addr = pending[i]
                slot = i % n
                ok = False
                for si, s2 in enumerate((slot, (slot + 1) % n)):
                    if attempt(rowid, addr, s2, rnd):
                        with lock:
                            ok_count["v"] += 1
                        ok = True
                        break
                    # http_get 内部已对该实例 NEWNYM；这里热切邻口
                if not ok:
                    with lock:
                        failures.append(rowid)
                conn.commit()

        with ThreadPoolExecutor(max_workers=workers) as ex:
            list(ex.map(lambda _: worker(), range(workers)))
        pending = failures
        log(f"lacnic rdap round={rnd} ok_total={ok_count['v']} pending={len(pending)}")
        if not pending:
            break
    conn.commit()
    DONE.write_text("\n".join(sorted(done | {r for r, _ in todo if r not in set(failures)})),
                    encoding="utf-8")
    FAILED.write_text("\n".join(sorted(set(failures))), encoding="utf-8")
    log(f"done RDAP rdap-lacnic ok={ok_count['v']} still_failed={len(set(failures))}")


def nir_rdap_pass(conn: sqlite3.Connection, cu: int) -> int:
    """NIR live RDAP（限流 caps：GEOIP_NIR_MAX，默认 500/轮）。"""
    cap = int(os.environ.get("GEOIP_NIR_MAX", "500"))
    n = 0
    for cc, base in RDAP_NIR.items():
        rows = conn.execute(
            """SELECT rowid, ip_start FROM geoip
               WHERE net_org = '' AND country = ? LIMIT ?""",
            (cc, cap),
        ).fetchall()
        for rowid, start in rows:
            data = rdap_ip(base, start, False)
            if not data:
                continue
            name = data.get("name") or ""
            for ent in data.get("entities", []):
                v = ent.get("vcardArray", [])
                if len(v) > 1:
                    for item in v[1]:
                        if item[0] == "fn" and item[3]:
                            name = name or item[3]
            if name:
                end = conn.execute(
                    "SELECT ip_end FROM geoip WHERE rowid=?", (rowid,)
                ).fetchone()[0]
                upsert_range(conn, start, end, {"net_org": name},
                             weight=950, source=f"rdap-nir-{cc.lower()}", commit_unix=cu)
                n += 1
        conn.commit()
    return n


def main() -> int:
    cu = int(time.time())
    conn = sqlite3.connect(DEFAULT_DB)
    try:
        init_schema(conn)
        for name, url in DUMPS.items():
            path = get_dump(name, url)
            if not path:
                continue
            total, orgs = enrich_from_dump(name, path, conn, cu)
            print(f"geoip_enrich_netorg: {name} inetnums={total} orgs={orgs}")
            conn.commit()
        print(f"geoip_enrich_netorg: arin csv rows={arin_csv(conn, cu)}")
        conn.commit()
        print(f"geoip_enrich_netorg: nir rdap filled={nir_rdap_pass(conn, cu)}")
        conn.commit()
        lacnic_rdap_pass(conn, cu)
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
