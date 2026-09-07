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
import socket
import sqlite3
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from geoip_common import DEFAULT_DB, init_schema, upsert_range  # noqa: E402
from geoip_http import http_get, tor_socks_endpoints  # noqa: E402
from geoip_tor_pool import ensure_tor_pool  # noqa: E402

SOURCES = Path("data/geoip/sources")
LOG = Path("data/geoip/logs/lacnic-rdap-resume.log")
DONE = Path("data/geoip/sources/lacnic-rdap-done.txt")
FAILED = Path("data/geoip/sources/lacnic-rdap-failed.txt")
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


def get_dump(name: str, url: str) -> Path | None:
    out = SOURCES / f"{name}.db"
    if out.is_file() and out.stat().st_size > 1_000_000:
        return out
    gz = SOURCES / f"{name}.db.gz"
    SOURCES.mkdir(parents=True, exist_ok=True)
    try:
        raw = fetch(url, timeout=1800)
        gz.write_bytes(raw)
        with gzip.open(gz, "rb") as src, out.open("wb") as dst:
            dst.write(src.read())
        return out
    except Exception as exc:
        print(f"warn: dump {name}: {exc}", file=sys.stderr)
        return None


def parse_objects(path: Path):
    """流式解析 RIR 文本 dump：产出 (kind, obj) —— kind ∈ inetnum|organisation。"""
    obj: dict[str, str] = {}
    key = None
    with path.open(encoding="utf-8", errors="replace") as f:
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
    rows = conn.execute(
        """SELECT rowid, ip_start FROM geoip
           WHERE source LIKE %lacnic% AND net_org = """
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
