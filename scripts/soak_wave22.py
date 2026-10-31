#!/usr/bin/env python3
"""soak_wave22.py — 工号 1009 / agent-soak 长稳混合负载 + 泄漏判定装置（只读产品，不改 src）。

混合负载（每轮持续 duration 秒，按 window 切窗口）：
  * h1 静态：wrk -t2 -c32（10s 开 / 50s 关，避免访问日志单窗口写出几十 GB）
  * h2c 静态：h2load -c32 -m5 -t2（10s 开 / 50s 关）
  * h3：aioquic，小流量 1 req/s，20 req 一连接（27843）
  * 19 引擎轮流：每引擎 60s，4 个 keep-alive worker，GET / POST 交替，POST body
    短(64B)/大(16KiB) 交替；tsx 的 POST 405 属设计（Allow: GET, HEAD），按 expected 计
  * 上传/断点续传：每 120s 一个 1MiB 文件分 10 片 Content-Range 续传 + 一次全量 PUT
  * 下载 Range：每 10s 对静态/已上传文件发 Range 请求，校验 206 与字节数
  * DNS：权威 UDP A/AAAA/TXT（每 2s）；DoH GET/POST（每 10s，Host: crucible.local）
  * Admin：每 120s 登录（TLS cookie）→ 读 overview/catalog/logs → GET 配置 →
    POST /api/config/toml 原样保存（触发写盘+热载）
  * 配置热载：每 60s SIGHUP + 静态探针 + 访问日志 marker 行核对（丢行=0 才算过）
  * 日志轮换：每 5min 记录 inode/size 与 SIGHUP 后是否 reopen（当前实现无 reopen）

采样（每 5s）：/proc/<pid>/{status,fd,stat} 的 RSS/VmSize/线程/fd、子进程数、
/proc/net/tcp[6]、/proc/net/udp 连接状态计数、loadavg。

每 1 分钟聚合：各 loader 的请求数、非 2xx 分类、p50/p99（从请求样本估计）。
结束后：RSS/fd/线程斜率（KB/min、个/min）+ 逐分钟中位序列的单调性判定；
非 2xx/超时/重置清单；孤儿进程与临时文件/socket 检查。

用法：
  python3 scripts/soak_wave22.py --pid $(cat ~/scratch-soak/webserver.pid) \
      --duration 3600 --window 1200 --label window1-fastpath-on \
      --outdir ~/scratch-soak/run1 [--stop-server]

退出码：0 全部通过；1 有泄漏/错误率超阈/丢日志行/孤儿；2 服务器中途死亡/装置失败。
"""
import argparse
import asyncio
import base64
import errno
import http.client
import json
import os
import random
import re
import signal
import socket
import ssl
import statistics
import struct
import subprocess
import sys
import threading
import time
from collections import Counter, defaultdict

# ---------------------------------------------------------------------------
# 常量 / 端口
# ---------------------------------------------------------------------------
STATIC = 27881
APPS = 27895
TLS12 = 27845
TLS13 = 27846
H3 = 27843
DOH = 27844
DNS = 27854
ADMIN = 27844

BASE = "/home/dev123/scratch-soak"
WRK = "/home/dev123/local/usr/bin/wrk"
H2LOAD = "/home/dev123/local/usr/bin/h2load"
LIBENV = dict(os.environ)
LIBENV["LD_LIBRARY_PATH"] = "/home/dev123/local/usr/lib/x86_64-linux-gnu:" + LIBENV.get("LD_LIBRARY_PATH", "")

ENGINES = ["/php/", "/rust/", "/c/", "/go/", "/lua/", "/asp/", "/python/", "/ruby/",
           "/perl/", "/jsp/", "/do/", "/wsgi/", "/asgi/", "/psgi/", "/rack/", "/cgi/",
           "/uwsgi/", "/tsx/", "/aspnet/"]
# tsx 引擎按设计只服务 GET/HEAD（src/server/apps/tsx.rs: Allow: GET, HEAD）
EXPECTED_NON2XX = {("/tsx/", 405)}
SMALL_BODY = b"x" * 64
LARGE_BODY = b"y" * 16384

SAMPLE_EVERY = 5
ENGINE_WINDOW = 60
UPLOAD_EVERY = 120
ADMIN_EVERY = 120
RELOAD_EVERY = 60
LOGCHECK_EVERY = 300
DNS_EVERY = 2
DOH_EVERY = 10
RANGE_EVERY = 10
WRK_ON, WRK_OFF = 10, 50
H2_ON, H2_OFF = 10, 50
LAT_CAP = 20000
ERR_EVENT_CAP = 20000
WARMUP = 300.0

T0 = time.time()
T0_MONO = time.monotonic()


def now_rel():
    return time.time() - T0


def mono_rel():
    return time.monotonic() - T0_MONO


# ---------------------------------------------------------------------------
# 统计聚合
# ---------------------------------------------------------------------------
class Stats:
    def __init__(self):
        self.lock = threading.Lock()
        self.buckets = defaultdict(dict)   # minute -> loader -> dict
        self.totals = defaultdict(lambda: {"n": 0, "ok": 0, "err": 0})
        self.codes = defaultdict(Counter)  # loader -> Counter(code/kind)
        self.err_events = []
        self.err_total = 0
        self.expected_non2xx = Counter()
        self.flushed = []

    def _bucket(self, minute, loader):
        b = self.buckets[minute].get(loader)
        if b is None:
            b = {"n": 0, "ok": 0, "err": 0, "codes": Counter(), "lat": [],
                 "rps_sum": 0.0, "rps_n": 0}
            self.buckets[minute][loader] = b
        return b

    def observe(self, loader, code, lat_ms, target="", path="", kind=None):
        minute = int(mono_rel() // 60)
        ok = isinstance(code, int) and 200 <= code < 300
        key = code if kind is None else kind
        with self.lock:
            b = self._bucket(minute, loader)
            b["n"] += 1
            if ok:
                b["ok"] += 1
            else:
                b["err"] += 1
            b["codes"][key] += 1
            if len(b["lat"]) < LAT_CAP:
                b["lat"].append(lat_ms)
            self.totals[loader]["n"] += 1
            self.codes[loader][key] += 1
            if ok:
                self.totals[loader]["ok"] += 1
            else:
                self.totals[loader]["err"] += 1
                self.err_total += 1
                exp = False
                if isinstance(code, int):
                    if (path, code) in EXPECTED_NON2XX:
                        exp = True
                    # SIGHUP 后用于核对访问日志不丢行的唯一路径探测，404 是预期
                    if code == 404 and str(path).startswith("/soak-probe-sighup-"):
                        exp = True
                if exp:
                    self.expected_non2xx[(path, code)] += 1
                elif len(self.err_events) < ERR_EVENT_CAP:
                    self.err_events.append({
                        "t": round(now_rel(), 2), "loader": loader, "target": target,
                        "path": path, "code": key, "lat_ms": round(lat_ms, 2)})

    def observe_summary(self, loader, n, err, rps, p50, p99, target="", extra=None):
        """wrk / h2load 的整轮汇总（非逐请求）。"""
        minute = int(mono_rel() // 60)
        with self.lock:
            b = self._bucket(minute, loader)
            b["n"] += n
            b["err"] += err
            b["ok"] += max(0, n - err)
            b["codes"]["summary"] += n
            b["rps_sum"] += rps
            b["rps_n"] += 1
            if p50 is not None:
                b.setdefault("tool_p50", []).append(p50)
            if p99 is not None:
                b.setdefault("tool_p99", []).append(p99)
            self.totals[loader]["n"] += n
            self.totals[loader]["err"] += err
            self.totals[loader]["ok"] += max(0, n - err)
            self.codes[loader]["summary"] += n
            if err:
                self.err_total += err
                if len(self.err_events) < ERR_EVENT_CAP:
                    self.err_events.append({
                        "t": round(now_rel(), 2), "loader": loader, "target": target,
                        "path": "", "code": "non2xx_summary", "lat_ms": None,
                        "n_err": err, "extra": extra or {}})

    def flush(self, upto_minute=None):
        """把已结束的分钟桶转成可写记录。"""
        cur = int(mono_rel() // 60)
        out = []
        with self.lock:
            for m in sorted(self.buckets):
                if upto_minute is not None:
                    if m < upto_minute:
                        pass
                    else:
                        break
                else:
                    if m >= cur:
                        break
                for loader, b in self.buckets[m].items():
                    lat = b["lat"]
                    if lat:
                        s = sorted(lat)
                        p50 = s[min(len(s) - 1, int(len(s) * 0.50))]
                        p99 = s[min(len(s) - 1, int(len(s) * 0.99))]
                    else:
                        p50 = p99 = None
                    if b.get("tool_p50"):
                        p50 = statistics.median(b["tool_p50"])
                    if b.get("tool_p99"):
                        p99 = statistics.median(b["tool_p99"])
                    out.append({
                        "minute": m, "loader": loader, "n": b["n"], "ok": b["ok"],
                        "err": b["err"], "codes": dict(b["codes"]),
                        "p50_ms": None if p50 is None else round(p50, 3),
                        "p99_ms": None if p99 is None else round(p99, 3),
                        "rps": round(b["rps_sum"] / b["rps_n"], 2) if b["rps_n"] else None,
                    })
                del self.buckets[m]
        self.flushed.extend(out)
        return out


# ---------------------------------------------------------------------------
# /proc 采样
# ---------------------------------------------------------------------------
def read_status(pid):
    rss = vsize = threads = None
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    rss = int(line.split()[1])
                elif line.startswith("VmSize:"):
                    vsize = int(line.split()[1])
                elif line.startswith("Threads:"):
                    threads = int(line.split()[1])
    except OSError:
        pass
    return rss, vsize, threads


def read_fd_count(pid):
    try:
        return len(os.listdir(f"/proc/{pid}/fd"))
    except OSError:
        return None


def read_cpu_ticks(pid):
    try:
        with open(f"/proc/{pid}/stat") as f:
            data = f.read()
        # comm 里可能有空格/括号，按最后一个 ')' 之后切
        rest = data[data.rfind(")") + 2:].split()
        return int(rest[11]) + int(rest[12])  # utime + stime (字段 14/15)
    except (OSError, IndexError, ValueError):
        return None


def read_proc_children(pid):
    """返回 (direct_count, all_descendant_pids)。"""
    ppid_map = {}
    try:
        for name in os.listdir("/proc"):
            if not name.isdigit():
                continue
            try:
                with open(f"/proc/{name}/stat") as f:
                    d = f.read()
                ppid = int(d[d.rfind(")") + 2:].split()[1])
                ppid_map[int(name)] = ppid
            except (OSError, IndexError, ValueError):
                continue
    except OSError:
        return 0, set()
    direct = sum(1 for c, p in ppid_map.items() if p == pid)
    desc = set()
    frontier = {pid}
    for _ in range(8):
        nxt = {c for c, p in ppid_map.items() if p in frontier and c not in desc}
        if not nxt:
            break
        desc |= nxt
        frontier = nxt
    return direct, desc


def hexport(s):
    try:
        return int(s, 16)
    except ValueError:
        return -1


def read_net_counts(ports):
    """统计 /proc/net/tcp[6]/udp 中与本实例端口相关的 socket 状态。"""
    counts = Counter()
    estab = 0
    total = 0
    try:
        for path in ("/proc/net/tcp", "/proc/net/tcp6"):
            with open(path) as f:
                next(f, None)
                for line in f:
                    parts = line.split()
                    if len(parts) < 4:
                        continue
                    lp = hexport(parts[1].rsplit(":", 1)[-1])
                    rp = hexport(parts[2].rsplit(":", 1)[-1])
                    st = parts[3]
                    if lp in ports or rp in ports:
                        total += 1
                        counts[st] += 1
                        if st == "01":
                            estab += 1
    except OSError:
        pass
    udp = 0
    try:
        with open("/proc/net/udp") as f:
            next(f, None)
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and hexport(parts[1].rsplit(":", 1)[-1]) in ports:
                    udp += 1
    except OSError:
        pass
    return {"tcp_total": total, "tcp_estab": estab,
            "tcp_states": {k: v for k, v in counts.items()}, "udp": udp}


def sample_proc(pid):
    rss, vsize, threads = read_status(pid)
    direct, desc = read_proc_children(pid)
    s = {
        "t": round(now_rel(), 2),
        "rss_kb": rss, "vsize_kb": vsize, "threads": threads,
        "fd": read_fd_count(pid),
        "children": direct,
        "descendants": len(desc),
        "cpu_ticks": read_cpu_ticks(pid),
        "load1": round(os.getloadavg()[0], 3),
    }
    s.update(read_net_counts(set(range(27800, 27900))))
    return s


# ---------------------------------------------------------------------------
# 小工具：TLS / HTTP 客户端
# ---------------------------------------------------------------------------
SSLCTX = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
SSLCTX.check_hostname = False
SSLCTX.verify_mode = ssl.CERT_NONE


def tls_conn(port, timeout=10):
    return http.client.HTTPSConnection("127.0.0.1", port, context=SSLCTX, timeout=timeout)


def http_probe(port, path, method="GET", body=None, headers=None, timeout=10):
    t0 = time.perf_counter()
    try:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
        c.request(method, path, body=body, headers=headers or {})
        r = c.getresponse()
        data = r.read()
        c.close()
        return r.status, data, (time.perf_counter() - t0) * 1000
    except Exception as e:
        return None, type(e).__name__, (time.perf_counter() - t0) * 1000


def tls_probe(port, path, method="GET", body=None, headers=None, timeout=10):
    t0 = time.perf_counter()
    try:
        c = tls_conn(port, timeout)
        c.request(method, path, body=body, headers=headers or {})
        r = c.getresponse()
        data = r.read()
        st, hdrs = r.status, dict(r.getheaders())
        c.close()
        return st, data, hdrs, (time.perf_counter() - t0) * 1000
    except Exception as e:
        return None, type(e).__name__, {}, (time.perf_counter() - t0) * 1000


# DNS wire helpers -----------------------------------------------------------
def dns_query_wire(name, qtype, txid=None):
    tmap = {"A": 1, "AAAA": 28, "TXT": 16, "NS": 2}
    qn = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    if txid is None:
        txid = random.randrange(65536)
    return struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0) + qn + struct.pack(">HH", tmap[qtype], 1)


def dns_rcode(msg):
    return (msg[3] & 0x0F) if len(msg) >= 4 else None


def dns_ancount(msg):
    return struct.unpack(">H", msg[6:8])[0] if len(msg) >= 12 else None


# ---------------------------------------------------------------------------
# 负载线程
# ---------------------------------------------------------------------------
def run_tool_loop(loader, cmd, interval_on, interval_off, stop, stats, parser):
    while not stop.is_set():
        try:
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 env=LIBENV, text=True)
        except Exception as e:
            stats.observe(loader, None, 0, kind="spawn_error")
            print(f"[soak] {loader} spawn failed: {e}", flush=True)
            stop.wait(5)
            continue
        try:
            out, _ = p.communicate(timeout=interval_on + 60)
        except subprocess.TimeoutExpired:
            p.kill()
            out, _ = p.communicate()
        try:
            rec = parser(out)
        except Exception as e:
            rec = {"rps": 0.0, "n": 0, "err": 0, "p50": None, "p99": None, "raw_err": str(e)}
        stats.observe_summary(loader, int(rec.get("n", 0)), int(rec.get("err", 0)),
                              float(rec.get("rps", 0.0)), rec.get("p50"), rec.get("p99"),
                              target=loader, extra={"out_tail": out[-800:]})
        stop.wait(interval_off)


WRK_RPS = re.compile(r"Requests/sec:\s+([0-9.]+)")
WRK_NON2XX = re.compile(r"Non-2xx or 3xx responses:\s+(\d+)")
WRK_TOTAL = re.compile(r"(\d+) requests in ([0-9.]+)s")
WRK_PCT = re.compile(r"^\s*(50|99)%\s+([0-9.]+)(ms|s|us)", re.M)


def parse_wrk(out):
    m = WRK_RPS.search(out)
    rps = float(m.group(1)) if m else 0.0
    m = WRK_TOTAL.search(out)
    n = int(m.group(1)) if m else 0
    m = WRK_NON2XX.search(out)
    err = int(m.group(1)) if m else 0
    pcts = {}
    for pm in WRK_PCT.finditer(out):
        v = float(pm.group(2))
        unit = pm.group(3)
        v = v * 1000 if unit == "s" else (v / 1000 if unit == "us" else v)
        pcts[int(pm.group(1))] = v
    return {"rps": rps, "n": n, "err": err, "p50": pcts.get(50), "p99": pcts.get(99)}


H2_REQ = re.compile(r"requests:\s+(\d+) total,\s+(\d+) started,\s+(\d+) done,\s+"
                    r"(\d+) succeeded,\s+(\d+) failed,\s+(\d+) errored,\s+(\d+) timeout")
H2_RPS = re.compile(r"([0-9.]+) req/s")


def parse_h2load(out):
    rps = 0.0
    m = H2_RPS.search(out)
    if m:
        rps = float(m.group(1))
    n = err = 0
    m = H2_REQ.search(out)
    if m:
        n = int(m.group(1))
        err = int(m.group(6)) + int(m.group(7)) + int(m.group(5))
    return {"rps": rps, "n": n, "err": err, "p50": None, "p99": None}


def engine_worker(path, stop, deadline, stats, wid):
    conn = None
    post = False
    large = False
    req_i = 0
    while not stop.is_set() and time.monotonic() < deadline:
        if conn is None:
            conn = http.client.HTTPConnection("127.0.0.1", APPS, timeout=15)
        method = "POST" if post else "GET"
        body = (LARGE_BODY if large else SMALL_BODY) if post else None
        headers = {"Content-Type": "application/octet-stream"} if post else {}
        t0 = time.perf_counter()
        kind = None
        try:
            conn.request(method, path, body=body, headers=headers)
            r = conn.getresponse()
            data = r.read()
            code = r.status
        except socket.timeout:
            code, data, kind = None, b"", "timeout"
            try:
                conn.close()
            except Exception:
                pass
            conn = None
        except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError) as e:
            code, data, kind = None, b"", "reset"
            conn = None
        except Exception as e:
            code, data, kind = None, b"", f"exc:{type(e).__name__}"
            conn = None
        lat = (time.perf_counter() - t0) * 1000
        stats.observe("engines", code if kind is None else kind, lat,
                      target=path, path=path, kind=kind)
        post = not post
        if not post:
            large = not large
        req_i += 1
        # 限速：每 worker ~100 req/s，避免大 body 打满 loopback 与访问日志
        if req_i % 8 == 0:
            time.sleep(0.002)
        elif req_i % 8 == 4:
            time.sleep(0.004)


def engines_loop(stop, stats):
    cycle = 0
    while not stop.is_set():
        for path in ENGINES:
            if stop.is_set():
                return
            deadline = time.monotonic() + ENGINE_WINDOW
            print(f"[soak] engines: {path} for {ENGINE_WINDOW}s (cycle {cycle})", flush=True)
            ths = [threading.Thread(target=engine_worker,
                                    args=(path, stop, deadline, stats, i), daemon=True)
                   for i in range(4)]
            for t in ths:
                t.start()
            for t in ths:
                t.join()
        cycle += 1


def upload_cycle(stats, seq):
    total = 1024 * 1024
    data = os.urandom(total)
    fname = f"/soak-upload-{os.getpid()}-{seq}.bin"
    # 10 片续传（最后一片收尾 → 201）
    chunk = (total + 9) // 10
    ok_all = True
    for i in range(10):
        a = i * chunk
        b = min(total, a + chunk) - 1
        part = data[a:b + 1]
        st, body, _, lat = tls_probe(H3, fname, "PUT", part, {
            "Content-Range": f"bytes {a}-{b}/{total}",
            "Content-Type": "application/octet-stream",
            "Host": f"127.0.0.1:{H3}"})
        stats.observe("upload", st, lat, target=fname, path=fname,
                      kind=None if st is not None else f"exc:{body}")
        if st not in (201, 202):
            ok_all = False
            break
    # 全量 PUT
    fname2 = fname.replace(".bin", "-full.bin")
    st, body, _, lat = tls_probe(H3, fname2, "PUT", data, {
        "Content-Type": "application/octet-stream", "Host": f"127.0.0.1:{H3}"})
    stats.observe("upload", st, lat, target=fname2, path=fname2,
                  kind=None if st is not None else f"exc:{body}")
    # 读回校验（Range 全量）
    st, body, _, lat = tls_probe(H3, fname, "GET", None,
                                 {"Range": f"bytes=0-{total - 1}", "Host": f"127.0.0.1:{H3}"})
    stats.observe("range", st, lat, target=fname, path=fname,
                  kind=None if st == 206 else f"code:{st}")
    intact = (st == 206 and body == data)
    if not intact:
        stats.observe("range", None, 0, target=fname, path=fname, kind="content_mismatch")
    return ok_all and intact, fname, fname2


def upload_loop(stop, stats, events):
    seq = 0
    while not stop.is_set():
        try:
            ok, f1, f2 = upload_cycle(stats, seq)
            events.append({"t": round(now_rel(), 2), "event": "upload",
                           "seq": seq, "ok": ok, "files": [f1, f2]})
        except Exception as e:
            events.append({"t": round(now_rel(), 2), "event": "upload_exc",
                           "seq": seq, "err": repr(e)})
            stats.observe("upload", None, 0, kind="exc")
        seq += 1
        stop.wait(UPLOAD_EVERY)


def range_loop(stop, stats):
    while not stop.is_set():
        st, body, lat = http_probe(STATIC, "/index.html", headers={"Range": "bytes=0-99"})
        stats.observe("range", st, lat, target="static", path="/index.html")
        if st == 206 and len(body) != 100:
            stats.observe("range", None, lat, target="static", path="/index.html",
                          kind="bad_len")
        st, body, _, lat = tls_probe(H3, "/range.bin", headers={
            "Range": "bytes=100-1999", "Host": f"127.0.0.1:{H3}"})
        stats.observe("range", st, lat, target="upload-root", path="/range.bin")
        if st == 206 and len(body) != 1900:
            stats.observe("range", None, lat, target="upload-root", path="/range.bin",
                          kind="bad_len")
        stop.wait(RANGE_EVERY)


def dns_loop(stop, stats):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    qseq = 0
    while not stop.is_set():
        for name, qtype in (("www.soak.test", "A"), ("www.soak.test", "AAAA"),
                            ("www.soak.test", "TXT")):
            wire = dns_query_wire(name, qtype)
            t0 = time.perf_counter()
            try:
                sock.sendto(wire, ("127.0.0.1", DNS))
                resp, _ = sock.recvfrom(4096)
                lat = (time.perf_counter() - t0) * 1000
                rc = dns_rcode(resp)
                an = dns_ancount(resp)
                ok = rc == 0 and an is not None and an >= 1
                stats.observe("dns_auth", 200 if ok else None, lat,
                              target=name, path=f"{qtype}",
                              kind=None if ok else f"rcode={rc},an={an}")
            except socket.timeout:
                stats.observe("dns_auth", None, 0, target=name, path=qtype, kind="timeout")
            except Exception as e:
                stats.observe("dns_auth", None, 0, target=name, path=qtype,
                              kind=f"exc:{type(e).__name__}")
        qseq += 1
        stop.wait(DNS_EVERY)


def doh_cycle(stats):
    name = "www.soak.test"
    q = dns_query_wire(name, "A")
    b64 = base64.urlsafe_b64encode(q).decode().rstrip("=")
    st, body, _, lat = tls_probe(DOH, f"/dns-query?dns={b64}", "GET", None,
                                 {"Host": "crucible.local"})
    ok = st == 200 and dns_rcode(body) == 0
    stats.observe("doh", 200 if ok else st, lat, target="doh-get", path="/dns-query",
                  kind=None if ok else f"bad:{st}")
    st, body, _, lat = tls_probe(DOH, "/dns-query", "POST", q,
                                 {"Host": "crucible.local",
                                  "Content-Type": "application/dns-message"})
    ok = st == 200 and dns_rcode(body) == 0
    stats.observe("doh", 200 if ok else st, lat, target="doh-post", path="/dns-query",
                  kind=None if ok else f"bad:{st}")


def doh_loop(stop, stats):
    while not stop.is_set():
        try:
            doh_cycle(stats)
        except Exception as e:
            stats.observe("doh", None, 0, kind=f"exc:{type(e).__name__}")
        stop.wait(DOH_EVERY)


def admin_cycle(stats, events):
    body = json.dumps({"username": "admin", "password": "admin"}).encode()
    st, data, hdrs, lat = tls_probe(ADMIN, "/__admin/api/login", "POST", body, {
        "Host": f"127.0.0.1:{ADMIN}", "Content-Type": "application/json",
        "Origin": f"https://127.0.0.1:{ADMIN}"})
    login_st = st
    stats.observe("admin", st, lat, target="login", path="/api/login")
    cookie = ""
    for k, v in hdrs.items():
        if k.lower() == "set-cookie":
            cookie = v.split(";")[0]
            break
    h = {"Host": f"127.0.0.1:{ADMIN}"}
    if cookie:
        h["Cookie"] = cookie
    st, data, _, lat = tls_probe(ADMIN, "/__admin/api/overview", "GET", None, h)
    stats.observe("admin", st, lat, target="overview", path="/api/overview")
    st, data, _, lat = tls_probe(ADMIN, "/__admin/api/catalog", "GET", None, h)
    stats.observe("admin", st, lat, target="catalog", path="/api/catalog")
    st, data, _, lat = tls_probe(ADMIN, "/__admin/api/logs?limit=50", "GET", None, h)
    stats.observe("admin", st, lat, target="logs", path="/api/logs")
    # 保存一次设置：GET 当前 TOML → 原样 POST 回去（写盘 + 热载）
    st, cfg, _, lat = tls_probe(ADMIN, "/__admin/api/config", "GET", None, h)
    stats.observe("admin", st, lat, target="config_get", path="/api/config")
    saved = None
    if st == 200 and cfg:
        h2 = dict(h)
        h2["Origin"] = f"https://127.0.0.1:{ADMIN}"
        st, out, _, lat = tls_probe(ADMIN, "/__admin/api/config/toml", "POST", cfg, h2)
        saved = st
        stats.observe("admin", st, lat, target="config_save", path="/api/config/toml")
    events.append({"t": round(now_rel(), 2), "event": "admin_cycle",
                   "login": login_st, "save": saved, "cookie": bool(cookie)})


def admin_loop(stop, stats, events):
    while not stop.is_set():
        try:
            admin_cycle(stats, events)
        except Exception as e:
            events.append({"t": round(now_rel(), 2), "event": "admin_exc", "err": repr(e)})
            stats.observe("admin", None, 0, kind=f"exc:{type(e).__name__}")
        stop.wait(ADMIN_EVERY)


# 访问日志 marker 核对 -------------------------------------------------------
class LogWatcher:
    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()

    def size(self):
        try:
            return os.path.getsize(self.path)
        except OSError:
            return 0

    def find_between(self, start, end, needle):
        try:
            with open(self.path, "rb") as f:
                f.seek(start)
                data = f.read(max(0, end - start))
            return needle.encode() in data
        except OSError:
            return False


def reload_loop(stop, stats, events, pid, logwatcher):
    n = 0
    while not stop.is_set():
        stop.wait(RELOAD_EVERY)
        if stop.is_set():
            break
        n += 1
        start = logwatcher.size()
        try:
            os.kill(pid, signal.SIGHUP)
            sent = True
        except OSError as e:
            events.append({"t": round(now_rel(), 2), "event": "sighup_fail", "n": n, "err": str(e)})
            sent = False
        marker = f"/soak-probe-sighup-{int(time.time() * 1000)}-{n}.html"
        st, body, lat = http_probe(STATIC, marker)
        stats.observe("reload_probe", st, lat, target="static", path=marker)
        # marker 行最多等 6s（访问日志后台 flush 250ms）
        found = False
        deadline = time.monotonic() + 6
        while time.monotonic() < deadline and not stop.is_set():
            if logwatcher.find_between(start, logwatcher.size(), marker):
                found = True
                break
            time.sleep(0.1)
        events.append({"t": round(now_rel(), 2), "event": "sighup", "n": n,
                       "sent": sent, "probe": st, "marker_found": found,
                       "marker": marker})
        if not found:
            stats.observe("log", None, 0, kind="marker_missing", path=marker)


def logcheck_loop(stop, events, logwatcher):
    while not stop.is_set():
        stop.wait(LOGCHECK_EVERY)
        if stop.is_set():
            break
        try:
            st = os.stat(logwatcher.path)
            events.append({"t": round(now_rel(), 2), "event": "logcheck",
                           "ino": st.st_ino, "size": st.st_size,
                           "mtime": round(st.st_mtime, 3),
                           "reopen_supported": False,
                           "note": "access_log has no reopen/rotate API; SIGHUP only reloads config"})
        except OSError as e:
            events.append({"t": round(now_rel(), 2), "event": "logcheck_fail", "err": str(e)})


# H3 小流量 ---------------------------------------------------------------
def h3_loop(stop, stats):
    import ssl as _ssl
    from aioquic.asyncio.client import connect
    from aioquic.asyncio.protocol import QuicConnectionProtocol
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.h3.connection import H3Connection
    from aioquic.h3.events import HeadersReceived, DataReceived

    class Client(QuicConnectionProtocol):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            self.h3 = H3Connection(self._quic)
            self.st = None
            self.body = b""
            self.done = asyncio.Event()

        def quic_event_received(self, ev):
            for e in self.h3.handle_event(ev):
                if isinstance(e, HeadersReceived):
                    for k, v in e.headers:
                        if k == b":status":
                            self.st = int(v)
                    if e.stream_ended:
                        self.done.set()
                elif isinstance(e, DataReceived):
                    self.body += e.data
                    if e.stream_ended:
                        self.done.set()

        async def get(self, path):
            sid = self._quic.get_next_available_stream_id()
            self.h3.send_headers(sid, [
                (b":method", b"GET"), (b":scheme", b"https"),
                (b":authority", f"127.0.0.1:{H3}".encode()), (b":path", path.encode())],
                end_stream=True)
            self.transmit()
            try:
                await asyncio.wait_for(self.done.wait(), timeout=8)
            except asyncio.TimeoutError:
                pass
            if self.st is not None:
                await asyncio.sleep(0.05)
            return self.st, self.body

    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"], verify_mode=_ssl.CERT_NONE)

    async def run():
        while not stop.is_set():
            try:
                async with connect("127.0.0.1", H3, configuration=cfg, create_protocol=Client) as c:
                    for _ in range(20):
                        if stop.is_set():
                            break
                        t0 = time.perf_counter()
                        try:
                            st, body = await c.get("/index.html")
                            kind = None
                        except Exception as e:
                            st, body, kind = None, b"", f"exc:{type(e).__name__}"
                        lat = (time.perf_counter() - t0) * 1000
                        stats.observe("h3", st if kind is None else kind, lat,
                                      target="h3", path="/index.html", kind=kind)
                        for _ in range(10):
                            if stop.is_set():
                                break
                            await asyncio.sleep(0.1)
            except Exception as e:
                stats.observe("h3", None, 0, target="h3", path="/index.html",
                              kind=f"connect:{type(e).__name__}")
                for _ in range(20):
                    if stop.is_set():
                        break
                    await asyncio.sleep(0.1)

    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(run())
    finally:
        loop.close()


# ---------------------------------------------------------------------------
# 结束后分析
# ---------------------------------------------------------------------------
def linreg_slope(xs, ys):
    n = len(xs)
    if n < 2:
        return 0.0
    mx = sum(xs) / n
    my = sum(ys) / n
    den = sum((x - mx) ** 2 for x in xs)
    if den == 0:
        return 0.0
    return sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / den


def nondecreasing_frac(seq):
    if len(seq) < 2:
        return 1.0
    up = sum(1 for a, b in zip(seq, seq[1:]) if b >= a)
    return up / (len(seq) - 1)


def analyze(samples, stats, events, duration, label):
    steady = [s for s in samples if s["t"] >= min(WARMUP, duration * 0.25)]
    out = {"label": label, "duration_s": duration, "samples": len(samples),
           "steady_samples": len(steady)}
    if len(steady) < 6:
        out["error"] = "not enough steady samples"
        return out
    xs = [s["t"] / 60.0 for s in steady]

    def series(key):
        return [s[key] for s in steady if isinstance(s.get(key), (int, float))]

    for key, unit in (("rss_kb", "KB/min"), ("fd", "count/min"),
                      ("threads", "count/min"), ("vsize_kb", "KB/min"),
                      ("children", "count/min"), ("tcp_estab", "count/min")):
        vals = [(s["t"] / 60.0, s[key]) for s in steady if isinstance(s.get(key), (int, float))]
        if len(vals) < 6:
            continue
        slope = linreg_slope([a for a, _ in vals], [b for _, b in vals])
        ys = [b for _, b in vals]
        out[key] = {
            "slope": round(slope, 3), "unit": unit,
            "first": ys[0], "last": ys[-1], "min": min(ys), "max": max(ys),
            "median": statistics.median(ys),
            "net": ys[-1] - ys[0],
            "nondecreasing_frac": round(nondecreasing_frac(ys), 3),
        }
    # 逐分钟中位（去抖动）序列
    per_min = defaultdict(lambda: defaultdict(list))
    for s in steady:
        m = int(s["t"] // 60)
        for k in ("rss_kb", "fd", "threads"):
            if isinstance(s.get(k), (int, float)):
                per_min[m][k].append(s[k])
    mins = sorted(per_min)
    med = {k: [statistics.median(per_min[m][k]) for m in mins if per_min[m][k]]
           for k in ("rss_kb", "fd", "threads")}
    out["per_minute_medians"] = {k: [round(v, 1) for v in vals] for k, vals in med.items()}
    slopes_med = {}
    for k, vals in med.items():
        if len(vals) >= 3:
            sl = linreg_slope(list(range(len(vals))), vals)
            slopes_med[k] = round(sl, 3)
    out["slope_per_minute_medians"] = slopes_med

    rss = out.get("rss_kb", {})
    fd = out.get("fd", {})
    th = out.get("threads", {})
    rss_leak = (rss.get("slope", 0) >= 1024.0 or
                (rss.get("nondecreasing_frac", 0) >= 0.95 and rss.get("net", 0) > 5120))
    fd_leak = (slopes_med.get("fd", 0) > 0.05 and fd.get("net", 0) >= 3)
    th_leak = (slopes_med.get("threads", 0) > 0.05 and th.get("net", 0) >= 2)
    out["leak"] = {"rss": bool(rss_leak), "fd": bool(fd_leak), "threads": bool(th_leak)}
    out["leak_thresholds"] = {
        "rss": "slope<1024 KB/min AND not monotonic(nondecreasing>=0.95 & net>5MB)",
        "fd": "median slope<=0.05/min or net<3", "threads": "median slope<=0.05/min or net<2"}

    # 请求总账
    tot = sum(v["n"] for v in stats.totals.values())
    err = sum(v["err"] for v in stats.totals.values())
    exp = sum(stats.expected_non2xx.values())
    out["requests"] = {"total": tot, "non2xx": err,
                       "non2xx_rate": round(err / tot, 6) if tot else None,
                       "expected_non2xx": exp,
                       "unexpected_non2xx": err - exp}
    out["per_loader"] = {k: dict(v) for k, v in stats.totals.items()}
    out["codes"] = {k: dict(v) for k, v in stats.codes.items()}
    out["errors"] = stats.err_events[:ERR_EVENT_CAP]
    out["error_events_truncated"] = stats.err_total > len(stats.err_events)
    out["events"] = events
    # 每分钟聚合
    minutes = sorted({r["minute"] for r in stats.flushed})
    out["minute_metrics"] = [r for r in stats.flushed if r["minute"] in minutes]
    # 1 分钟总 RPS 与错误率（跨 loader）
    per_min_all = defaultdict(lambda: {"n": 0, "err": 0, "rps": 0.0})
    for r in stats.flushed:
        m = per_min_all[r["minute"]]
        m["n"] += r["n"]
        m["err"] += r["err"]
    for m in per_min_all:
        per_min_all[m]["err_rate"] = round(per_min_all[m]["err"] / per_min_all[m]["n"], 6) \
            if per_min_all[m]["n"] else None
    out["minute_totals"] = {str(k): v for k, v in sorted(per_min_all.items())}
    return out


# ---------------------------------------------------------------------------
# 孤儿 / 临时文件检查
# ---------------------------------------------------------------------------
ORPHAN_PATTERNS = ("config-soak.toml", "/home/dev123/scratch-soak/",
                   "jsp-sidecar.jar", "sidecar.rb", "libapp_rack",
                   "php-fpm", "go-shm-server", "ruby34")


def scan_processes(known_pids):
    """返回 (ppid1_suspects, known_alive)。"""
    suspects = []
    known_alive = []
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        pid = int(name)
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                cmd = f.read().replace(b"\0", b" ").decode("utf-8", "replace").strip()
        except OSError:
            continue
        if not cmd:
            continue
        try:
            with open(f"/proc/{pid}/stat") as f:
                d = f.read()
            ppid = int(d[d.rfind(")") + 2:].split()[1])
        except (OSError, IndexError, ValueError):
            continue
        if pid in known_pids and pid != os.getpid():
            known_alive.append({"pid": pid, "cmd": cmd[:300], "ppid": ppid})
        if ppid == 1 and any(p in cmd for p in ORPHAN_PATTERNS):
            suspects.append({"pid": pid, "cmd": cmd[:300], "ppid": ppid})
    return suspects, known_alive


def scan_leftovers():
    import glob
    pats = [BASE + "/**/*.upload.part", BASE + "/**/.*.upload.part",
            BASE + "/**/*.sock", BASE + "/state-dns/**/*.part",
            BASE + "/www-upload/*.part"]
    found = []
    for pat in pats:
        found.extend(glob.glob(pat, recursive=True))
    return sorted(set(found))


def probe_engines(stats=None):
    bad = {}
    for p in ENGINES:
        st, body, lat = http_probe(APPS, p)
        if st != 200:
            bad[p] = st
        if stats is not None:
            stats.observe("preflight", st, lat, target=p, path=p)
    return bad


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, required=True)
    ap.add_argument("--duration", type=int, default=3600)
    ap.add_argument("--window", type=int, default=1200)
    ap.add_argument("--label", default="window")
    ap.add_argument("--outdir", default=None)
    ap.add_argument("--stop-server", action="store_true")
    ap.add_argument("--skip-h3", action="store_true")
    args = ap.parse_args()

    outdir = args.outdir or os.path.join(BASE, "run-" + time.strftime("%Y%m%d-%H%M%S"))
    os.makedirs(outdir, exist_ok=True)
    logpath = os.path.join(BASE, "logs", "webserver.log")
    watcher = LogWatcher(logpath)

    pid = args.pid
    try:
        os.kill(pid, 0)
    except OSError:
        print(f"[soak] pid {pid} not alive", flush=True)
        return 2

    # 预检
    pre = {}
    for name, port, path, use_tls in (
            ("static_h1", STATIC, "/index.html", False),
            ("tls12", TLS12, "/", True),
            ("tls13", TLS13, "/", True),
            ("h3_listener_static", H3, "/index.html", True)):
        if use_tls:
            st, data, _, lat = tls_probe(port, path)
        else:
            st, data, lat = http_probe(port, path)
        pre[name] = st
    pre["engines_bad"] = probe_engines()
    doh_tmp = Stats()
    try:
        doh_cycle(doh_tmp)
        pre["doh"] = "ok"
    except Exception as e:
        pre["doh"] = repr(e)
    dns_ok = 0
    for nm, qt in (("www.soak.test", "A"), ("www.soak.test", "AAAA"),
                   ("www.soak.test", "TXT")):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(3)
            s.sendto(dns_query_wire(nm, qt), ("127.0.0.1", DNS))
            r, _ = s.recvfrom(4096)
            if dns_rcode(r) == 0 and (dns_ancount(r) or 0) >= 1:
                dns_ok += 1
            s.close()
        except Exception:
            pass
    pre["dns_auth_ok"] = dns_ok
    print(f"[soak] preflight: {pre}", flush=True)

    stats = Stats()
    events = []
    samples = []
    known_desc = set()
    stop = threading.Event()

    threads = [
        threading.Thread(target=run_tool_loop, daemon=True,
                         args=("wrk_h1", [WRK, "-t2", "-c32", "-d10s", "--latency",
                                          f"http://127.0.0.1:{STATIC}/index.html"],
                               WRK_ON, WRK_OFF, stop, stats, parse_wrk)),
        threading.Thread(target=run_tool_loop, daemon=True,
                         args=("h2load", [H2LOAD, "-c32", "-m5", "-t2", "-D10", "-n0",
                                          f"http://127.0.0.1:{STATIC}/index.html"],
                               H2_ON, H2_OFF, stop, stats, parse_h2load)),
        threading.Thread(target=engines_loop, daemon=True, args=(stop, stats)),
        threading.Thread(target=upload_loop, daemon=True, args=(stop, stats, events)),
        threading.Thread(target=range_loop, daemon=True, args=(stop, stats)),
        threading.Thread(target=dns_loop, daemon=True, args=(stop, stats)),
        threading.Thread(target=doh_loop, daemon=True, args=(stop, stats)),
        threading.Thread(target=admin_loop, daemon=True, args=(stop, stats, events)),
        threading.Thread(target=reload_loop, daemon=True, args=(stop, stats, events, pid, watcher)),
        threading.Thread(target=logcheck_loop, daemon=True, args=(stop, events, watcher)),
    ]
    if not args.skip_h3:
        threads.append(threading.Thread(target=h3_loop, daemon=True, args=(stop, stats)))
    for t in threads:
        t.start()

    sample_f = open(os.path.join(outdir, "samples.jsonl"), "w")
    minute_f = open(os.path.join(outdir, "minute_metrics.jsonl"), "w")
    event_f = open(os.path.join(outdir, "events.jsonl"), "w")
    start_wall = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    window_idx = 0
    next_boundary = args.window
    next_sample = 0.0
    server_died = False
    last_cpu = None
    while mono_rel() < args.duration and not stop.is_set():
        rel = mono_rel()
        if rel >= next_sample:
            s = sample_proc(pid)
            if s["rss_kb"] is None:
                server_died = True
                events.append({"t": round(now_rel(), 2), "event": "server_died"})
                break
            if last_cpu is not None and s["cpu_ticks"] is not None:
                s["cpu_pct"] = round((s["cpu_ticks"] - last_cpu) / SAMPLE_EVERY * 100 / os.sysconf("SC_CLK_TCK"), 1)
            last_cpu = s["cpu_ticks"]
            _, desc = read_proc_children(pid)
            known_desc |= desc
            samples.append(s)
            sample_f.write(json.dumps(s) + "\n")
            sample_f.flush()
            next_sample += SAMPLE_EVERY
        # 分钟桶落盘
        for rec in stats.flush():
            minute_f.write(json.dumps(rec) + "\n")
        minute_f.flush()
        # 窗口边界
        if rel >= next_boundary:
            window_idx += 1
            next_boundary += args.window
            events.append({"t": round(now_rel(), 2), "event": "window_boundary",
                           "window": window_idx})
        time.sleep(0.5)

    stop.set()
    for t in threads:
        t.join(timeout=20)
    for rec in stats.flush(upto_minute=10 ** 9):
        minute_f.write(json.dumps(rec) + "\n")
    minute_f.close()
    # 事件全量重写（避免增量去重逻辑出错）
    with open(os.path.join(outdir, "events.jsonl"), "w") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")
    event_f.close()

    # 停止前快照
    end_sample = sample_proc(pid)
    samples.append(end_sample)

    # 可选停服 + 孤儿检查
    orphan = {}
    if args.stop_server:
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                os.kill(pid, 0)
            except OSError:
                break
            time.sleep(0.5)
        time.sleep(2)
        suspects, known_alive = scan_processes(known_desc | {pid})
        orphan = {
            "known_descendants": len(known_desc),
            "known_still_alive": known_alive,
            "ppid1_suspects": suspects,
            "leftover_files": scan_leftovers(),
            "server_pid_alive": os.path.exists(f"/proc/{pid}"),
        }
        with open(os.path.join(outdir, "orphans.json"), "w") as f:
            json.dump(orphan, f, indent=2)
    else:
        suspects, known_alive = scan_processes(known_desc | {pid})
        orphan = {"known_descendants": len(known_desc),
                  "known_still_alive": known_alive,
                  "ppid1_suspects": suspects,
                  "leftover_files": scan_leftovers(),
                  "server_pid_alive": True}
        with open(os.path.join(outdir, "orphans.json"), "w") as f:
            json.dump(orphan, f, indent=2)

    result = analyze(samples, stats, events, args.duration, args.label)
    result["preflight"] = pre
    result["orphans"] = orphan
    result["start_wall"] = start_wall
    result["server_died"] = server_died
    result["pid"] = pid
    with open(os.path.join(outdir, "summary.json"), "w") as f:
        json.dump(result, f, indent=2)
    with open(os.path.join(outdir, "samples.csv"), "w") as f:
        cols = ["t", "rss_kb", "vsize_kb", "threads", "fd", "children", "descendants",
                "tcp_total", "tcp_estab", "udp", "load1", "cpu_pct"]
        f.write(",".join(cols) + "\n")
        for s in samples:
            f.write(",".join(str(s.get(c, "")) for c in cols) + "\n")

    # 结论
    leak = result.get("leak", {})
    req = result.get("requests", {})
    print(f"\n[soak] ===== {args.label} =====", flush=True)
    print(f"[soak] duration={args.duration}s samples={len(samples)} "
          f"requests={req.get('total')} non2xx={req.get('non2xx')} "
          f"rate={req.get('non2xx_rate')}", flush=True)
    for k in ("rss_kb", "fd", "threads"):
        v = result.get(k, {})
        print(f"[soak] {k}: slope={v.get('slope')} {v.get('unit')} "
              f"first={v.get('first')} last={v.get('last')} "
              f"nondec={v.get('nondecreasing_frac')}", flush=True)
    print(f"[soak] leak={leak}", flush=True)
    print(f"[soak] orphans: known_alive={len(orphan.get('known_still_alive', []))} "
          f"ppid1_suspects={len(orphan.get('ppid1_suspects', []))} "
          f"leftovers={len(orphan.get('leftover_files', []))}", flush=True)
    print(f"[soak] outdir={outdir}", flush=True)

    failed = bool(leak.get("rss") or leak.get("fd") or leak.get("threads")) or server_died
    if req.get("total") and (req.get("non2xx_rate") or 0) > 0.001:
        failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
