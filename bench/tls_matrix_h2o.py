#!/usr/bin/env python3
"""TLS matrix vs h2o 2.2.5: plain-h1 / tls12-h1 / tls13-h1 / tls13-h2 (+m1).

Spec shape (webserver-rebuild-prompt-v2.txt §0/§22.1, bench/spec_gate):
  * small static file (127 B index.html), both sides serve the *same* file/inode
  * both sides 2 worker threads (ours CRUCIBLE_WORKER_THREADS=2, h2o num-threads: 2)
  * keep-alive; h1 = ``wrk -t2 -c64 -d10s --latency``;
    h2 = ``h2load -n 0 -c 50 -t 2 -D 10 -m 10`` (primary) + ``-m 1`` (supplementary)
  * gates: throughput ``h2o_rps / ours_rps <= 1.2``; latency ``ours_mean / h2o_mean <= 1.2``
  * ABBA alternation per round (order *and* CPU core sets), medians over 5 rounds
  * ours access log ON (realtime=false) -- stricter than h2o (no access log)

Freshly added in wave-22:
  * wrk parser now reads the real p50/p99 from ``Latency Distribution``
    (the old code mis-labelled Avg/Stdev/Max as mean/p50/p99);
  * h2load parser reads ``status codes: N 2xx, ...`` (the old regex never matched);
  * all server threads are pinned with ``taskset`` and ABBA-swapped between two
    disjoint core sets; the load generator gets its own core set;
  * per-round server CPU is the sum over all threads, plus utime/stime and
    voluntary/involuntary context switches;
  * server processes get their own session and are killed as a group; ports are
    checked before start; a dead server fails fast with its log tail;
  * h1/h2 latency p50/p99 for h2 comes from a separate short ``--log-file`` run
    (the measured rounds stay log-free so the client is not I/O-bound);
  * optional ``--handshake``: openssl s_time full-handshake rate + server CPU
    per handshake, h2load all-new-connections rate;
  * optional ``--profile``: strace -c (+ perf stat -d if available) around one
    measured round on each side.

Usage:
  python3 bench/tls_matrix_h2o.py \
      --ours ~/scratch-tlsmatrix/target/release/webserver \
      --h2o ~/scratch-perfgate/bin/h2o \
      --work ~/scratch-tlsmatrix/w1 --logdir ~/scratch-tlsmatrix/logs/w1 \
      --rounds 5 --duration 10 --handshake --profile tls13-h2
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import resource
import shlex
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

WRK_DEFAULT = "/home/dev123/local/usr/bin/wrk"
H2LOAD_DEFAULT = "/home/dev123/local/usr/bin/h2load"
STRACE_DEFAULT = "/home/dev123/local/usr/bin/strace"
LOCAL_LIB_DIRS = ("/home/dev123/local/usr/lib/x86_64-linux-gnu",
                  "/home/dev123/local/usr/lib")

TICKS = os.sysconf("SC_CLK_TCK")


@dataclass(frozen=True)
class Matrix:
    name: str
    oport: int
    hport: int
    tls: bool
    proto: str                 # "h1" | "h2"
    tlsver: Optional[str]      # "TLSv1.2" | "TLSv1.3" | None
    h2m: Optional[int] = None  # h2load -m (None for h1)
    supplementary: bool = False


# 26200-26299 is this agent's port block (ours *81..*84, h2o *91..*94).
MATRICES: Tuple[Matrix, ...] = (
    Matrix("plain-h1", 26281, 26291, False, "h1", None),
    Matrix("tls12-h1", 26282, 26292, True, "h1", "TLSv1.2"),
    Matrix("tls13-h1", 26283, 26293, True, "h1", "TLSv1.3"),
    Matrix("tls13-h2", 26284, 26294, True, "h2", "TLSv1.3", h2m=10),
)
# m1 shares the tls13-h2 listener; reported next to the four gate matrices.
SUPPLEMENTARY: Tuple[Matrix, ...] = (
    Matrix("tls13-h2-m1", 26284, 26294, True, "h2", "TLSv1.3", h2m=1, supplementary=True),
)


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------
def loadavg() -> str:
    with open("/proc/loadavg") as f:
        return f.read().split()[0]


def med(xs: Sequence[float]) -> float:
    return statistics.median(xs) if xs else 0.0


def md5(path: str) -> str:
    try:
        h = hashlib.md5()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return "n/a"


def tool_version(path: str, args: Sequence[str]) -> str:
    try:
        p = subprocess.run([path, *args], stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, text=True, timeout=10,
                           env=client_env())
        out = (p.stdout or "").strip().splitlines()
        return out[0] if out else "n/a"
    except (OSError, subprocess.SubprocessError):
        return "n/a"


def _scale(v: float, suffix: str) -> float:
    return v * {"": 1.0, "k": 1e3, "m": 1e6, "g": 1e9}[suffix.lower()]


def _to_us(v: str, unit: str) -> float:
    return float(v) * {"us": 1.0, "ms": 1e3, "s": 1e6}[unit]


_NUM = r"([\d.]+)\s*([KMGkmg]?)"


# ---------------------------------------------------------------------------
# output parsers (the part that was wrong in the interrupted version)
# ---------------------------------------------------------------------------
def parse_wrk(out: str) -> Dict[str, float]:
    """wrk -t.. -c.. --latency.

    Layout::

        Latency    344.04us   23.50us   1.20ms   91.00%     <- Avg/Stdev/Max
        Latency Distribution
           50%  330.00us
           99%  700.00us
    """
    res: Dict[str, float] = {"rps": 0.0, "lat_mean_us": 0.0, "lat_p50_us": 0.0,
                             "lat_p99_us": 0.0, "requests": 0.0, "non2xx": 0.0}
    m = re.search(r"Requests/sec:\s*" + _NUM, out)
    if m:
        res["rps"] = _scale(float(m.group(1)), m.group(2))
    # Avg is the first value on the "Latency" line (NOT p50).
    m = re.search(r"^\s*Latency\s+([\d.]+)(us|ms|s)\s+([\d.]+)(us|ms|s)\s+"
                  r"([\d.]+)(us|ms|s)", out, re.M)
    if m:
        res["lat_mean_us"] = _to_us(m.group(1), m.group(2))
        res["lat_sd_us"] = _to_us(m.group(3), m.group(4))
        res["lat_max_us"] = _to_us(m.group(5), m.group(6))
    for pm in re.finditer(r"^\s*(\d+)%\s+([\d.]+)(us|ms|s)\s*$", out, re.M):
        pct = int(pm.group(1))
        us = _to_us(pm.group(2), pm.group(3))
        if pct == 50:
            res["lat_p50_us"] = us
        elif pct == 99:
            res["lat_p99_us"] = us
    m = re.search(r"(\d+)\s+requests in", out)
    if m:
        res["requests"] = float(m.group(1))
    m = re.search(r"Non-2xx or 3xx responses:\s*(\d+)", out)
    if m:
        res["non2xx"] = float(m.group(1))
    # keep-alive runners may close a few idle sockets; wrk reports read errors
    m = re.search(r"Socket errors:.*?read\s+(\d+),\s+write\s+(\d+),\s+"
                  r"connect\s+(\d+),\s+timeout\s+(\d+)", out)
    if m:
        res["sock_errors"] = float(sum(int(m.group(i)) for i in range(1, 5)))
    return res


def parse_h2load(out: str) -> Dict[str, float]:
    """h2load stdout (mean latency, status-code table, request counters)."""
    res: Dict[str, float] = {"rps": 0.0, "lat_mean_us": 0.0, "requests": 0.0,
                             "succeeded": 0.0, "failed": 0.0, "errored": 0.0,
                             "timeout": 0.0, "non2xx": 0.0}
    m = re.search(r"finished in ([\d.]+)(us|ms|s),\s*" + _NUM + r"req/s,\s*"
                  + _NUM + r"B/s", out)
    if m:
        res["rps"] = _scale(float(m.group(3)), m.group(4))
        res["finished_s"] = float(m.group(1)) * {"us": 1e-6, "ms": 1e-3, "s": 1.0}[m.group(2)]
    m = re.search(
        r"requests:\s*(\d+)\s+total,\s*(\d+)\s+started,\s*(\d+)\s+done,\s*(\d+)\s+succeeded,"
        r"\s*(\d+)\s+failed,\s*(\d+)\s+errored,\s*(\d+)\s+timeout", out)
    if m:
        res["requests"] = float(m.group(1))
        res["started"] = float(m.group(2))
        res["done"] = float(m.group(3))
        res["succeeded"] = float(m.group(4))
        res["failed"] = float(m.group(5))
        res["errored"] = float(m.group(6))
        res["timeout"] = float(m.group(7))
    m = re.search(r"status codes:\s*(\d+)\s+2xx,\s*(\d+)\s+3xx,\s*(\d+)\s+4xx,"
                  r"\s*(\d+)\s+5xx", out)
    if m:
        res["non2xx"] = float(int(m.group(2)) + int(m.group(3)) + int(m.group(4)))
        res["status_2xx"] = float(m.group(1))
        res["status_3xx"] = float(m.group(2))
        res["status_4xx"] = float(m.group(3))
        res["status_5xx"] = float(m.group(4))
    m = re.search(r"time for request:\s*([\d.]+)(us|ms|s)\s+([\d.]+)(us|ms|s)\s+"
                  r"([\d.]+)(us|ms|s)\s+([\d.]+)(us|ms|s)", out)
    if m:
        res["lat_min_us"] = _to_us(m.group(1), m.group(2))
        res["lat_max_us"] = _to_us(m.group(3), m.group(4))
        res["lat_mean_us"] = _to_us(m.group(5), m.group(6))
        res["lat_sd_us"] = _to_us(m.group(7), m.group(8))
    m = re.search(r"req/s\s*:\s*([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)", out)
    if m:
        res["client_rps_min"] = float(m.group(1))
        res["client_rps_max"] = float(m.group(2))
        res["client_rps_mean"] = float(m.group(3))
    return res


def _percentile(sorted_xs: List[float], p: float) -> float:
    if not sorted_xs:
        return 0.0
    k = max(0, min(len(sorted_xs) - 1, int(round((p / 100.0) * (len(sorted_xs) - 1)))))
    return sorted_xs[k]


def parse_h2load_log(path: str) -> Dict[str, float]:
    """h2load ``--log-file``: ``start_us<TAB>status<TAB>request_us`` per line."""
    durs: List[float] = []
    bad = 0
    try:
        with open(path, "r", errors="replace") as f:
            for line in f:
                parts = line.rstrip("\n").split("\t")
                if len(parts) < 3:
                    continue
                try:
                    status = int(parts[1])
                    durs.append(float(parts[2]))
                except ValueError:
                    continue
                if status < 0 or not (200 <= status < 300):
                    bad += 1
    except OSError:
        return {"log_requests": 0.0, "lat_p50_us": 0.0, "lat_p99_us": 0.0,
                "log_non2xx": 0.0}
    durs.sort()
    return {"log_requests": float(len(durs)),
            "lat_p50_us": _percentile(durs, 50),
            "lat_p99_us": _percentile(durs, 99),
            "lat_log_mean_us": (sum(durs) / len(durs)) if durs else 0.0,
            "log_non2xx": float(bad)}


# ---------------------------------------------------------------------------
# process / CPU accounting
# ---------------------------------------------------------------------------
def proc_snapshot(pid: int) -> Optional[Dict[str, int]]:
    """utime/stime/context switches summed over every thread of ``pid``.

    /proc/<pid>/stat only covers the main thread; worker threads carry the
    actual request work, so a per-process sum is required for an honest
    CPU-per-request number.
    """
    base = f"/proc/{pid}"
    try:
        tids = os.listdir(f"{base}/task")
    except OSError:
        return None
    ut = st = vol = invol = 0
    for tid in tids:
        try:
            with open(f"{base}/task/{tid}/stat") as f:
                data = f.read()
            rest = data[data.rfind(")") + 2:].split()
            ut += int(rest[11])
            st += int(rest[12])
        except (OSError, IndexError, ValueError):
            pass
        try:
            with open(f"{base}/task/{tid}/status") as f:
                for line in f:
                    if line.startswith("voluntary_ctxt_switches:"):
                        vol += int(line.split()[1])
                    elif line.startswith("nonvoluntary_ctxt_switches:"):
                        invol += int(line.split()[1])
        except (OSError, IndexError, ValueError):
            pass
    return {"ticks": ut + st, "utime": ut, "stime": st,
            "vol_ctx": vol, "invol_ctx": invol}


def proc_cpu_seconds(pid: int) -> Optional[float]:
    snap = proc_snapshot(pid)
    return None if snap is None else snap["ticks"] / TICKS


def set_affinity(pid: int, cpus: str) -> bool:
    if not cpus or not shutil.which("taskset"):
        return False
    try:
        tids = os.listdir(f"/proc/{pid}/task")
    except OSError:
        return False
    ok = False
    for tid in tids:
        p = subprocess.run(["taskset", "-pc", cpus, tid], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
        ok = ok or p.returncode == 0
    return ok


def affinity_of(pid: int) -> str:
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("Cpus_allowed_list:"):
                    return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return "n/a"


# ---------------------------------------------------------------------------
# client invocations
# ---------------------------------------------------------------------------
def client_env(tlsver: Optional[str] = None, work: Optional[str] = None) -> Dict[str, str]:
    env = dict(os.environ)
    env["LD_LIBRARY_PATH"] = ":".join(LOCAL_LIB_DIRS) + (
        ":" + env["LD_LIBRARY_PATH"] if env.get("LD_LIBRARY_PATH") else "")
    env["LC_ALL"] = "C"
    if tlsver and work:
        # Client-side protocol pin: h2o 2.2.5 ignores maximum-version for TLS1.3
        # (verified with s_client), so both sides are made to negotiate the
        # matrix version by capping the OpenSSL client.  wrk/h2load/curl all
        # read OPENSSL_CONF.
        env["OPENSSL_CONF"] = os.path.join(work, f"openssl-{tlsver}.cnf")
    return env


def write_openssl_confs(work: str) -> None:
    for ver in ("TLSv1.2", "TLSv1.3"):
        body = (
            "openssl_conf = default_conf\n"
            "[default_conf]\n"
            "ssl_conf = ssl_sect\n"
            "[ssl_sect]\n"
            "system_default = system_default_sect\n"
            "[system_default_sect]\n"
            f"MinProtocol = {ver}\n"
            f"MaxProtocol = {ver}\n"
        )
        with open(os.path.join(work, f"openssl-{ver}.cnf"), "w") as f:
            f.write(body)


def client_cmd(kind: str, url: str, duration: int, h2m: Optional[int],
               cpus: str = "", light: bool = False) -> List[str]:
    if kind == "wrk":
        cmd = [shutil.which("wrk") or WRK_DEFAULT,
               "-t1", "-c10"] if light else [
               shutil.which("wrk") or WRK_DEFAULT, "-t2", "-c64"]
        cmd += [f"-d{duration}s", "--latency", url]
    else:
        conc, threads = (10, 1) if light else (50, 2)
        m = 1 if light else (h2m or 1)
        cmd = [shutil.which("h2load") or H2LOAD_DEFAULT,
               "-n", "0", "-c", str(conc), "-t", str(threads), "-D", str(duration),
               "-m", str(m), url]
    if cpus and shutil.which("taskset"):
        cmd = ["taskset", "-c", cpus] + cmd
    return cmd


def run_client(kind: str, url: str, duration: int, h2m: Optional[int],
               env: Dict[str, str], cpus: str = "",
               log_path: Optional[str] = None,
               light: bool = False) -> Tuple[Dict[str, float], str, float, float, float, int]:
    cmd = client_cmd(kind, url, duration, h2m, cpus, light)
    if log_path:
        # only used by the dedicated latency-trace runs, never by gate rounds
        cmd.insert(-1, f"--log-file={log_path}")
    ru0 = resource.getrusage(resource.RUSAGE_CHILDREN)
    t0 = time.time()
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       text=True, timeout=duration + 180, env=env)
    wall = time.time() - t0
    ru1 = resource.getrusage(resource.RUSAGE_CHILDREN)
    cli_cpu = (ru1.ru_utime - ru0.ru_utime) + (ru1.ru_stime - ru0.ru_stime)
    out = p.stdout or ""
    res = parse_wrk(out) if kind == "wrk" else parse_h2load(out)
    if log_path and os.path.exists(log_path):
        res.update(parse_h2load_log(log_path))
    res.update({"wall_s": wall, "rc": p.returncode, "cmd": " ".join(cmd),
                "cli_cpu_s": cli_cpu})
    return res, out, wall, cli_cpu, t0, p.returncode


# ---------------------------------------------------------------------------
# configs / servers
# ---------------------------------------------------------------------------
def write_configs(work: str, www: str, cert: str, key: str,
                  matrices: Sequence[Matrix], access_log: bool = True) -> Tuple[str, str]:
    """Write ours.toml and h2o.conf; one docroot per matrix, shared by both.

    The product refuses two listeners with the same root (bind_key cross-site
    guard), so every matrix gets its own copy of the same 127 B file; h2o's
    ``file.dir`` points at *that same directory*, i.e. both servers read the
    identical inode for a given matrix.
    """
    ours = os.path.join(work, "ours.toml")
    blocks = [f"[access_log]\nenable = {str(access_log).lower()}\n"
              "level = \"info\"\nrealtime = false\n"]
    for m in matrices:
        root = os.path.join(work, f"www-{m.name}")
        os.makedirs(root, exist_ok=True)
        shutil.copyfile(os.path.join(www, "index.html"), os.path.join(root, "index.html"))
        b = (f'[[listeners]]\naddress = "127.0.0.1"\nport = {m.oport}\n'
             f'root = "{root}"\nautoindex = false\n'
             f'http_versions = ["{m.proto}"]\nserver_name = "{m.name}.bench.test"\n')
        if m.tls:
            b += (f'[listeners.ssl]\ncert = "{cert}"\nkey = "{key}"\n'
                  f'versions = ["{m.tlsver}"]\n')
        blocks.append(b)
    with open(ours, "w") as f:
        f.write("\n".join(blocks))

    h2o = os.path.join(work, "h2o.conf")
    lines = ["num-threads: 2\nhosts:\n"]
    for m in matrices:
        if m.supplementary:
            continue
        root = os.path.join(work, f"www-{m.name}")
        lines.append(f'  "{m.name}":\n    listen:\n      host: 127.0.0.1\n'
                     f'      port: {m.hport}\n')
        if m.tls:
            lines.append("      ssl:\n"
                         f"        certificate-file: {cert}\n"
                         f"        key-file: {key}\n"
                         "        cipher-suite: ECDHE-RSA-AES128-GCM-SHA256\n")
        lines.append(f'    paths:\n      "/":\n        file.dir: {root}\n')
    with open(h2o, "w") as f:
        f.write("".join(lines))
    return ours, h2o


def port_free(port: int) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def wait_ports(procs: Dict[str, subprocess.Popen], ports: Sequence[int],
               timeout: float = 20.0) -> Optional[str]:
    end = time.time() + timeout
    while time.time() < end:
        dead = [name for name, p in procs.items() if p.poll() is not None]
        if dead:
            return f"server exited before ready: {', '.join(dead)}"
        if all(port_free(p) is False for p in ports):
            return None
        time.sleep(0.2)
    up = [p for p in ports if not port_free(p)]
    return f"servers not ready after {timeout:.0f}s (listening: {up}, want {list(ports)})"


def tail(path: str, n: int = 30) -> str:
    try:
        with open(path, "r", errors="replace") as f:
            return "".join(f.readlines()[-n:])
    except OSError:
        return ""


def kill_group(p: subprocess.Popen) -> None:
    try:
        os.killpg(os.getpgid(p.pid), signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        try:
            p.terminate()
        except ProcessLookupError:
            return
    try:
        p.wait(timeout=10)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(p.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass


# ---------------------------------------------------------------------------
# TLS / ALPN probes and handshake benchmarks
# ---------------------------------------------------------------------------
def s_client(port: int, tlsver: Optional[str] = None, alpn: Optional[str] = None,
             timeout: int = 10, env: Optional[Dict[str, str]] = None) -> Dict[str, Optional[str]]:
    cmd = ["openssl", "s_client", "-connect", f"127.0.0.1:{port}",
           "-servername", "bench.test"]
    if tlsver == "TLSv1.2":
        cmd.append("-tls1_2")
    elif tlsver == "TLSv1.3":
        cmd.append("-tls1_3")
    if alpn:
        cmd += ["-alpn", alpn]
    try:
        p = subprocess.run(cmd, input="", stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, text=True, timeout=timeout,
                           env=env or client_env())
    except (OSError, subprocess.SubprocessError) as e:
        return {"error": str(e)}
    out = p.stdout or ""
    res: Dict[str, Optional[str]] = {"rc": str(p.returncode)}
    m = re.search(r"^\s*Protocol\s*:\s*(\S+)", out, re.M)
    res["protocol"] = m.group(1) if m else None
    m = re.search(r"Cipher is (\S+)", out)
    res["cipher"] = m.group(1) if m else None
    m = re.search(r"ALPN protocol:\s*(\S+)", out)
    res["alpn"] = m.group(1) if m else ("none" if "No ALPN negotiated" in out else None)
    return res


def s_time(port: int, tlsver: str, seconds: int, pid: int,
           cpus: str = "") -> Dict[str, float]:
    cmd = ["openssl", "s_time", "-connect", f"127.0.0.1:{port}", "-new",
           "-time", str(seconds), "-tls1_2" if tlsver == "TLSv1.2" else "-tls1_3"]
    if cpus and shutil.which("taskset"):
        cmd = ["taskset", "-c", cpus] + cmd
    c0 = proc_snapshot(pid)
    t0 = time.time()
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           text=True, timeout=seconds + 60, env=client_env())
        out = p.stdout or ""
    except (OSError, subprocess.SubprocessError) as e:
        return {"error": str(e), "handshakes": 0.0}
    wall = time.time() - t0
    c1 = proc_snapshot(pid)
    m = re.search(r"(\d+)\s+connections in [\d.]+\s+real seconds", out)
    if not m:
        m = re.search(r"(\d+)\s+connections in [\d.]+s;", out)
    n = float(m.group(1)) if m else 0.0
    res = {"handshakes": n, "wall_s": wall,
           "rate_per_s": (n / wall) if wall > 0 else 0.0}
    if c0 and c1:
        cpu_s = (c1["ticks"] - c0["ticks"]) / TICKS
        res["srv_cpu_s"] = cpu_s
        res["srv_cpu_us_per_hs"] = (cpu_s / n * 1e6) if n else 0.0
    if n == 0:
        res["raw_tail"] = out[-400:]
    return res


def h2load_new_conn(url: str, conns: int, env: Dict[str, str], cpus: str,
                    pid: int) -> Dict[str, float]:
    """Every connection serves exactly one request -> rate ~= new conns/s."""
    cmd = [shutil.which("h2load") or H2LOAD_DEFAULT, "-n", str(conns),
           "-c", str(conns), "-t", "2", "-m", "1", url]
    if cpus and shutil.which("taskset"):
        cmd = ["taskset", "-c", cpus] + cmd
    c0 = proc_snapshot(pid)
    t0 = time.time()
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           text=True, timeout=120, env=env)
        out = p.stdout or ""
    except (OSError, subprocess.SubprocessError) as e:
        return {"error": str(e), "conn_per_s": 0.0}
    wall = time.time() - t0
    c1 = proc_snapshot(pid)
    res = parse_h2load(out)
    res["wall_s"] = wall
    res["conn_per_s"] = (res.get("succeeded", 0.0) / wall) if wall > 0 else 0.0
    if c0 and c1:
        cpu_s = (c1["ticks"] - c0["ticks"]) / TICKS
        res["srv_cpu_s"] = cpu_s
        res["srv_cpu_us_per_conn"] = (cpu_s / res["succeeded"] * 1e6
                                      if res.get("succeeded") else 0.0)
    return res


# ---------------------------------------------------------------------------
# profiling (strace -c / perf stat -d)
# ---------------------------------------------------------------------------
def _parse_strace(path: str) -> Dict[str, object]:
    """strace -f -c: ``%time seconds usecs/call calls [errors] syscall``."""
    rows = []
    total_calls = 0
    total_errors = 0
    try:
        with open(path, "r", errors="replace") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 5:
                    continue
                name = parts[-1]
                if name in ("syscall", "total") or not re.fullmatch(r"[a-zA-Z0-9_]+", name):
                    continue
                try:
                    calls = int(parts[3])
                except (ValueError, IndexError):
                    continue
                errs = 0
                if len(parts) >= 6:
                    try:
                        errs = int(parts[4])
                    except ValueError:
                        errs = 0
                total_calls += calls
                total_errors += errs
                rows.append({"syscall": name, "calls": calls, "errors": errs})
    except OSError:
        return {"error": "missing strace output"}
    rows.sort(key=lambda r: r["calls"], reverse=True)
    return {"total_calls": total_calls, "total_errors": total_errors,
            "top": rows[:20], "n_syscalls": len(rows)}


def _parse_perf(path: str) -> Dict[str, object]:
    out: Dict[str, object] = {}
    try:
        with open(path, "r", errors="replace") as f:
            text = f.read()
    except OSError:
        return {"error": "missing perf output"}
    m = re.search(r"([\d,.]+)\s+seconds time elapsed", text)
    if m:
        out["seconds_elapsed"] = float(m.group(1).replace(",", ""))
    for key, pat in (
            ("context_switches", r"([\d,]+)\s+context-switches(?::[a-z]+)?"),
            ("cpu_migrations", r"([\d,]+)\s+cpu-migrations(?::[a-z]+)?"),
            ("page_faults", r"([\d,]+)\s+page-faults(?::[a-z]+)?"),
            ("cycles", r"([\d,]+)\s+(?:cpu-)?cycles(?::[a-z]+)?"),
            ("instructions", r"([\d,]+)\s+instructions(?::[a-z]+)?"),
            ("branches", r"([\d,]+)\s+branches(?::[a-z]+)?"),
            ("branch_misses", r"([\d,]+)\s+branch-misses(?::[a-z]+)?"),
            ("task_clock_ms", r"([\d,.]+)\s+msec task-clock(?::[a-z]+)?"),
            ("user_seconds", r"([\d.]+)\s+seconds user"),
            ("sys_seconds", r"([\d.]+)\s+seconds sys")):
        mm = re.search(pat, text)
        if mm:
            out[key] = float(mm.group(1).replace(",", ""))
    if "user_seconds" in out and "sys_seconds" in out:
        tot = out["user_seconds"] + out["sys_seconds"]
        out["user_pct"] = 100.0 * out["user_seconds"] / tot if tot else 0.0
    if not out:
        out["raw_head"] = text[:600]
    return out


def _children_of(pid: int) -> List[int]:
    out: List[int] = []
    try:
        with open(f"/proc/{pid}/task/{pid}/children") as f:
            out = [int(x) for x in f.read().split()]
    except OSError:
        for d in os.listdir("/proc"):
            if not d.isdigit():
                continue
            try:
                with open(f"/proc/{d}/stat") as f:
                    data = f.read()
                rest = data[data.rfind(")") + 2:].split()
                if int(rest[1]) == pid:
                    out.append(int(d))
            except (OSError, IndexError, ValueError):
                pass
    return out


def pids_in_group(pgid: int) -> List[int]:
    out: List[int] = []
    for d in os.listdir("/proc"):
        if not d.isdigit():
            continue
        try:
            with open(f"/proc/{d}/stat") as f:
                data = f.read()
            rest = data[data.rfind(")") + 2:].split()
            if int(rest[2]) == pgid:
                out.append(int(d))
        except (OSError, IndexError, ValueError):
            pass
    return out


def find_descendant(parent: int, needle: str) -> Optional[int]:
    """Find the server process below a strace/perf wrapper by config path."""
    stack = [(parent, 0)]
    seen = set()
    while stack:
        pid, depth = stack.pop()
        if pid in seen:
            continue
        seen.add(pid)
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                cmd = f.read().replace(b"\0", b" ").decode("utf-8", "replace")
            if pid != parent and needle in cmd:
                return pid
        except OSError:
            pass
        if depth < 6:
            stack += [(c, depth + 1) for c in _children_of(pid)]
    return None


def write_profile_configs(work: str, m: Matrix, cert: str, key: str,
                          oport: int, hport: int,
                          access_log: bool = True) -> Tuple[str, str]:
    root = os.path.join(work, f"www-{m.name}")
    ours = os.path.join(work, "ours-profile.toml")
    b = (f"[access_log]\nenable = {str(access_log).lower()}\n"
         "level = \"info\"\nrealtime = false\n\n"
         f'[[listeners]]\naddress = "127.0.0.1"\nport = {oport}\n'
         f'root = "{root}"\nautoindex = false\n'
         f'http_versions = ["{m.proto}"]\nserver_name = "{m.name}.profile.test"\n')
    if m.tls:
        b += (f'[listeners.ssl]\ncert = "{cert}"\nkey = "{key}"\n'
              f'versions = ["{m.tlsver}"]\n')
    with open(ours, "w") as f:
        f.write(b)
    h2o = os.path.join(work, "h2o-profile.conf")
    c = ["num-threads: 2\nhosts:\n",
         f'  "{m.name}":\n    listen:\n      host: 127.0.0.1\n      port: {hport}\n']
    if m.tls:
        c.append("      ssl:\n"
                 f"        certificate-file: {cert}\n"
                 f"        key-file: {key}\n"
                 "        cipher-suite: ECDHE-RSA-AES128-GCM-SHA256\n")
    c.append(f'    paths:\n      "/":\n        file.dir: {root}\n')
    with open(h2o, "w") as f:
        f.write("".join(c))
    return ours, h2o


def _tool_paths() -> Tuple[str, Optional[str]]:
    strace = shutil.which("strace") or (
        STRACE_DEFAULT if os.path.exists(STRACE_DEFAULT) else "")
    perf = shutil.which("perf") or (
        "/home/dev123/local/usr/bin/perf"
        if os.path.exists("/home/dev123/local/usr/bin/perf") else None)
    return strace, perf


def profile_case(m: Matrix, ours_bin: str, h2o_bin: str, work: str, logdir: str,
                 cert: str, key: str, duration: int, args) -> Dict[str, object]:
    """Run one short round per (tool, side) with the server *under* the tool.

    Attaching with ``-p`` is blocked by yama/ptrace_scope=1 (a sibling cannot
    ptrace another child), so the profiled server is started as a child of
    strace/perf on dedicated ports; the wrapper is then the tracer and the
    syscall/PMC attribution is valid.
    """
    oport = 26285 + args.port_offset
    hport = 26295 + args.port_offset
    busy = [p for p in (oport, hport) if not port_free(p)]
    if busy:
        return {"error": f"profile ports busy: {busy}"}
    oconf, hconf = write_profile_configs(work, m, cert, key, oport, hport,
                                         access_log=not args.no_access_log)
    kinds = {"ours": ([ours_bin, "--config", oconf], oconf, oport),
             "h2o": ([h2o_bin, "-c", hconf], hconf, hport)}
    # h2o config path is in the cmdline too (needle); ours too
    scheme = "https" if m.tls else "http"
    kind = "wrk" if m.proto == "h1" else "h2load"
    env = client_env(m.tlsver if m.tls else None, work)
    strace_bin, perf_bin = _tool_paths()
    tools: List[Tuple[str, Optional[List[str]]]] = []
    if strace_bin:
        tools.append(("strace", [strace_bin]))
    if perf_bin:
        tools.append(("perf", [perf_bin, "stat", "-d"]))
    result: Dict[str, object] = {"ports": {"ours": oport, "h2o": hport}, "runs": {},
                                 "notes": {
                                     "strace": "ours: -f -c (all threads); h2o: -c "
                                               "(main thread only: h2o forks a "
                                               "non-dumpable helper and strace -f "
                                               "deadlocks its event loop)",
                                     "perf": "perf stat -d wraps each server; "
                                             "context-switches:u is unreliable on "
                                             "this WSL kernel (reads 0)"}}
    for tool, wrapper in tools:
        if not wrapper:
            continue
        result["runs"][tool] = {}
        for who, (server_cmd, needle, port) in kinds.items():
            out_path = os.path.join(logdir, f"{tool}-{m.name}-{who}.txt")
            log_path = os.path.join(logdir, f"{tool}-{m.name}-{who}.log")
            # Attach-as-parent trick: bash starts the server, then exec()s into
            # the tracer, so the tracer is the server's *parent* and yama
            # ptrace_scope=1 allows attaching to every thread.  This avoids
            # `strace -f` at fork time (h2o forks a non-dumpable helper and
            # deadlocks when followed).
            server_argv = ["env", "-u", "LD_LIBRARY_PATH", "taskset", "-c",
                           args.cpu_ours if who == "ours" else args.cpu_h2o,
                           *server_cmd]
            tool_argv = (wrapper + (["-f", "-c"] if tool == "strace" else []))
            script = (shlex.join(server_argv) + " > " + shlex.quote(log_path)
                      + " 2>&1 & SPID=$!; sleep 1; exec "
                      + " ".join(shlex.quote(x) for x in tool_argv)
                      + " -p $SPID -o " + shlex.quote(out_path))
            proc = subprocess.Popen(["/bin/bash", "-c", script],
                                    stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL,
                                    start_new_session=True, env=client_env())
            entry: Dict[str, object] = {"cmd": script}
            server_pid = None
            pgid = os.getpgid(proc.pid) if proc.poll() is None else 0
            try:
                deadline = time.time() + 20
                while time.time() < deadline and port_free(port):
                    if proc.poll() is not None:
                        break
                    time.sleep(0.2)
                server_pid = find_descendant(proc.pid, needle)
                entry["server_pid"] = server_pid
                if server_pid is None or port_free(port):
                    entry["error"] = "server did not start"
                    entry["log_tail"] = tail(log_path)
                else:
                    entry["affinity"] = affinity_of(server_pid)
                    # Give bash (sleep 1) + the tracer time to attach before
                    # the load starts; otherwise most of the measured window
                    # is not traced (observed as calls/req << 1).
                    time.sleep(2.5)
                    if proc.poll() is not None:
                        entry["error"] = "tracer exited before load"
                        entry["log_tail"] = tail(log_path)
                    else:
                        url = f"{scheme}://127.0.0.1:{port}/"
                        # Light shape: profiling overhead dominates at c50/m10
                        # and can stall the client; both sides use c10/m1.
                        row = one_round(who, server_pid, kind, url, duration, m.h2m,
                                        env, "" if args.no_pin else args.cpu_client,
                                        logdir, f"profile-{m.name}-{who}", light=True)
                        entry["round"] = {k: v for k, v in row.items()
                                          if k not in ("url",)}
                        # Detach/print the tracer first (fast), then stop the
                        # server in the finally block.
                        proc.send_signal(signal.SIGINT)
            except (OSError, subprocess.SubprocessError) as e:
                entry["error"] = str(e)
            finally:
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    proc.wait(timeout=5)
                # The tracer has exited; stop every process left in its group
                # (server + h2o's forked helper) individually.
                members = [p for p in pids_in_group(pgid) if p != proc.pid] if pgid else []
                for p in members:
                    for sig in (signal.SIGTERM, signal.SIGCONT):
                        try:
                            os.kill(p, sig)
                        except ProcessLookupError:
                            pass
                for _ in range(20):
                    members = [p for p in members if os.path.exists(f"/proc/{p}")]
                    if not members:
                        break
                    time.sleep(0.2)
                for p in members:
                    try:
                        os.kill(p, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
            if os.path.exists(out_path):
                entry[tool] = (_parse_strace(out_path) if tool == "strace"
                               else _parse_perf(out_path))
            result["runs"][tool][who] = entry
    return result


# ---------------------------------------------------------------------------
# one measured round
# ---------------------------------------------------------------------------
def one_round(label: str, pid: int, kind: str, url: str, duration: int,
              h2m: Optional[int], env: Dict[str, str], cpus: str,
              outdir: str, tag: str, light: bool = False) -> Dict[str, float]:
    os.makedirs(outdir, exist_ok=True)
    s0 = proc_snapshot(pid)
    res, raw, wall, cli_cpu, _t0, rc = run_client(kind, url, duration, h2m, env, cpus,
                                                  light=light)
    s1 = proc_snapshot(pid)
    n = res.get("succeeded") or res.get("requests") or (res.get("rps", 0.0) * wall)
    if s0 and s1:
        cpu_s = (s1["ticks"] - s0["ticks"]) / TICKS
        res["srv_cpu_s"] = cpu_s
        res["srv_cores"] = cpu_s / wall if wall > 0 else 0.0
        res["srv_cpu_us_per_req"] = (cpu_s / n * 1e6) if n else 0.0
        res["srv_utime_s"] = (s1["utime"] - s0["utime"]) / TICKS
        res["srv_stime_s"] = (s1["stime"] - s0["stime"]) / TICKS
        res["vol_ctx"] = s1["vol_ctx"] - s0["vol_ctx"]
        res["invol_ctx"] = s1["invol_ctx"] - s0["invol_ctx"]
        tot = (s1["ticks"] - s0["ticks"]) or 1
        res["srv_user_pct"] = 100.0 * (s1["utime"] - s0["utime"]) / tot
    res.update({"label": label, "url": url, "loadavg": loadavg(), "rc": rc,
                "n_requests": n,
                "ts": time.strftime("%H:%M:%S")})
    with open(os.path.join(outdir, f"raw-{tag}-{label}.out"), "w") as f:
        f.write(raw)
    return res


# ---------------------------------------------------------------------------
# preflight
# ---------------------------------------------------------------------------
def preflight(m: Matrix, work: str, env: Dict[str, str]) -> Tuple[bool, List[str]]:
    notes: List[str] = []
    ok = True
    scheme = "https" if m.tls else "http"
    opts = ["--http2"] if m.proto == "h2" else ["--http1.1"]
    for who, port in (("ours", m.oport), ("h2o", m.hport)):
        url = f"{scheme}://127.0.0.1:{port}/"
        body = os.path.join(work, f"body-{m.name}-{who}")
        p = subprocess.run(["curl", "-sk", *opts, "--max-time", "10",
                            "-o", body, "-w", "%{http_code} %{http_version}", url],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           text=True, env=env)
        want_ver = "2" if m.proto == "h2" else "1.1"
        code, ver = (p.stdout.strip().split() + ["", ""])[:2]
        size = os.path.getsize(body) if os.path.exists(body) else -1
        good = code == "200" and ver == want_ver and size == 127
        ok = ok and good
        notes.append(f"precheck {m.name}/{who}: {url} -> code={code} "
                     f"http={ver} body={size}B {'OK' if good else 'FAIL'}")
        if os.path.exists(body):
            os.unlink(body)
    return ok, notes


def tls_matrix_probes(m: Matrix, work: str) -> Dict[str, object]:
    out: Dict[str, object] = {}
    # same OPENSSL_CONF the load generator will use: proves the measured
    # client really negotiates the matrix version (h2o ignores max-version).
    pin_env = client_env(m.tlsver, work)
    for who, port in (("ours", m.oport), ("h2o", m.hport)):
        out[who] = {
            "forced": s_client(port, tlsver=m.tlsver),
            "pinned": s_client(port, env=pin_env),
            "alpn_h2": s_client(port, tlsver=m.tlsver, alpn="h2"),
            "alpn_h1": s_client(port, tlsver=m.tlsver, alpn="http/1.1"),
            "default": s_client(port),
        }
    return out


# ---------------------------------------------------------------------------
# reporting
# ---------------------------------------------------------------------------
def summarize_case(m: Matrix, rows: List[Dict[str, float]],
                   trace: Dict[str, Dict[str, float]],
                   thr_gate: float, lat_gate: float) -> Dict[str, object]:
    a = [x for x in rows if x["label"] == "ours"]
    b = [x for x in rows if x["label"] == "h2o"]
    a_rps, b_rps = med([x["rps"] for x in a]), med([x["rps"] for x in b])
    a_lat, b_lat = med([x["lat_mean_us"] for x in a]), med([x["lat_mean_us"] for x in b])
    pair_thr, pair_lat, pair_p50, pair_p99 = [], [], [], []
    for r in range(len(a)):
        ra, rb = a[r], b[r]
        if ra["rps"] > 0 and rb["rps"] > 0:
            pair_thr.append(rb["rps"] / ra["rps"])
        if ra.get("lat_mean_us", 0) > 0 and rb.get("lat_mean_us", 0) > 0:
            pair_lat.append(ra["lat_mean_us"] / rb["lat_mean_us"])
        if ra.get("lat_p50_us", 0) > 0 and rb.get("lat_p50_us", 0) > 0:
            pair_p50.append(ra["lat_p50_us"] / rb["lat_p50_us"])
        if ra.get("lat_p99_us", 0) > 0 and rb.get("lat_p99_us", 0) > 0:
            pair_p99.append(ra["lat_p99_us"] / rb["lat_p99_us"])
    thr = med(pair_thr) if pair_thr else (b_rps / a_rps if a_rps > 0 else float("inf"))
    lat = med(pair_lat) if pair_lat else (a_lat / b_lat if b_lat > 0 else float("inf"))

    # h2 has no native percentile output: p50/p99 come from the short trace run
    lat_src = "rounds"
    if m.proto == "h2" and trace:
        lat_src = "trace-3s"
        for who, arr in (("ours", a), ("h2o", b)):
            if who in trace and trace[who].get("log_requests", 0) > 0:
                for x in arr:
                    x["lat_p50_us"] = trace[who]["lat_p50_us"]
                    x["lat_p99_us"] = trace[who]["lat_p99_us"]
        pair_p50, pair_p99 = [], []
        if (trace.get("ours", {}).get("lat_p50_us", 0) > 0 and
                trace.get("h2o", {}).get("lat_p50_us", 0) > 0):
            pair_p50 = [trace["ours"]["lat_p50_us"] / trace["h2o"]["lat_p50_us"]]
        if (trace.get("ours", {}).get("lat_p99_us", 0) > 0 and
                trace.get("h2o", {}).get("lat_p99_us", 0) > 0):
            pair_p99 = [trace["ours"]["lat_p99_us"] / trace["h2o"]["lat_p99_us"]]

    a_p50 = med([x.get("lat_p50_us", 0) for x in a])
    b_p50 = med([x.get("lat_p50_us", 0) for x in b])
    a_p99 = med([x.get("lat_p99_us", 0) for x in a])
    b_p99 = med([x.get("lat_p99_us", 0) for x in b])
    bad = sum(int(x.get("non2xx", 0)) + int(x.get("failed", 0)) +
              int(x.get("sock_errors", 0)) for x in rows)
    all_ok = all(x.get("rc", 0) == 0 and x.get("n_requests", 0) > 0 and
                 x.get("non2xx", 0) == 0 and x.get("failed", 0) == 0 for x in rows)
    verdict = "PASS" if (thr <= thr_gate and lat <= lat_gate and all_ok) else "FAIL"
    if m.supplementary:
        verdict = verdict + " (info)"
    return {
        "matrix": m.name, "client": "wrk" if m.proto == "h1" else "h2load",
        "h2_m": m.h2m, "supplementary": m.supplementary,
        "rounds": len(rows) // 2,
        "ours_rps": a_rps, "h2o_rps": b_rps,
        "throughput_ratio_h2o_over_ours": thr,
        "throughput_ratio_pairs": pair_thr,
        "ours_lat_mean_us": a_lat, "h2o_lat_mean_us": b_lat,
        "latency_ratio_ours_over_h2o": lat,
        "latency_ratio_pairs": pair_lat,
        "lat_source": lat_src,
        "ours_lat_p50_us": a_p50, "h2o_lat_p50_us": b_p50,
        "ours_lat_p99_us": a_p99, "h2o_lat_p99_us": b_p99,
        "p50_ratio_pairs": pair_p50, "p99_ratio_pairs": pair_p99,
        "ours_cpu_us_per_req": med([x.get("srv_cpu_us_per_req", 0) for x in a]),
        "h2o_cpu_us_per_req": med([x.get("srv_cpu_us_per_req", 0) for x in b]),
        "ours_cores": med([x.get("srv_cores", 0) for x in a]),
        "h2o_cores": med([x.get("srv_cores", 0) for x in b]),
        "ours_user_pct": med([x.get("srv_user_pct", 0) for x in a]),
        "h2o_user_pct": med([x.get("srv_user_pct", 0) for x in b]),
        "ctx_switches_per_req": {
            "ours": med([(x.get("vol_ctx", 0) + x.get("invol_ctx", 0)) /
                         (x.get("n_requests") or 1) for x in a]),
            "h2o": med([(x.get("vol_ctx", 0) + x.get("invol_ctx", 0)) /
                        (x.get("n_requests") or 1) for x in b]),
        },
        "bad_statuses": bad,
        "verdict": verdict,
    }


def write_markdown(path: str, meta: Dict[str, object], summary: List[Dict[str, object]],
                   handshake: Optional[Dict[str, object]], alpn: Dict[str, object],
                   thr_gate: float, lat_gate: float) -> None:
    def f(x, nd=1):
        try:
            return f"{float(x):.{nd}f}"
        except (TypeError, ValueError):
            return "-"

    L = [
        "# TLS matrix vs h2o 2.2.5 (wave-22)", "",
        f"- date `{meta['date']}` host `{meta['host']}` cores {meta['cores']}",
        f"- ours `{meta['ours_bin']}` md5 `{meta['ours_md5']}`",
        f"- h2o `{meta['h2o_bin']}` md5 `{meta['h2o_md5']}` `{meta['h2o_version']}`",
        f"- clients `{meta['wrk_version']}` / `{meta['h2load_version']}`",
        f"- shape: h1 `wrk -t2 -c64 -d{meta['duration_s']}s --latency`; "
        f"h2 `h2load -n0 -c50 -t2 -D{meta['duration_s']} -m10` (+m1); "
        f"payload 127 B same inode; threads 2/2; ours access log ON",
        f"- rounds {meta['rounds']} ABBA, CPU sets ours/h2o swapped each round; "
        f"gates thr(h2o/ours) <= {thr_gate}, lat(ours/h2o) <= {lat_gate}", "",
        "| case | client | ours rps | h2o rps | thr h2o/ours | lat mean ours/h2o | "
        "p50 ours/h2o (ratio) | p99 ours/h2o (ratio) | ours cores | h2o cores | verdict |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---|",
    ]
    for s in summary:
        L.append(
            f"| {s['matrix']} | {s['client']}"
            f"{'' if s['h2_m'] is None else ' m'+str(s['h2_m'])} | "
            f"{f(s['ours_rps'])} | {f(s['h2o_rps'])} | "
            f"{f(s['throughput_ratio_h2o_over_ours'], 3)} | "
            f"{f(s['latency_ratio_ours_over_h2o'], 3)} | "
            f"{f(s['ours_lat_p50_us'])}/{f(s['h2o_lat_p50_us'])} "
            f"({f(med(s['p50_ratio_pairs']), 3)}) | "
            f"{f(s['ours_lat_p99_us'])}/{f(s['h2o_lat_p99_us'])} "
            f"({f(med(s['p99_ratio_pairs']), 3)}) | "
            f"{f(s['ours_cores'], 2)} | {f(s['h2o_cores'], 2)} | {s['verdict']} |")
    L += ["", "Per-round paired ratios (thr = h2o/ours, lat = ours/h2o):", "",
          "| case | thr pairs | lat pairs | bad |", "|---|---|---|---:|"]
    for s in summary:
        L.append(f"| {s['matrix']} | " +
                 ", ".join(f"{v:.3f}" for v in s["throughput_ratio_pairs"]) +
                 " | " + ", ".join(f"{v:.3f}" for v in s["latency_ratio_pairs"]) +
                 f" | {s['bad_statuses']} |")
    L += ["", "Server cost (median):", "",
          "| case | ours µs/req | h2o µs/req | ours user% | h2o user% | "
          "ctx/req ours | ctx/req h2o |", "|---|---:|---:|---:|---:|---:|---:|"]
    for s in summary:
        L.append(f"| {s['matrix']} | {f(s['ours_cpu_us_per_req'], 2)} | "
                 f"{f(s['h2o_cpu_us_per_req'], 2)} | {f(s['ours_user_pct'])} | "
                 f"{f(s['h2o_user_pct'])} | "
                 f"{f(s['ctx_switches_per_req']['ours'], 3)} | "
                 f"{f(s['ctx_switches_per_req']['h2o'], 3)} |")
    if handshake:
        L += ["", "## Handshake rate (openssl s_time -new, full handshakes)", "",
              "| listener | ours conn/s | h2o conn/s | ratio ours/h2o | "
              "ours µs CPU/hs | h2o µs CPU/hs |", "|---|---:|---:|---:|---:|---:|"]
        for k, v in handshake.get("s_time", {}).items():
            L.append(f"| {k} | {f(v['ours']['rate_per_s'], 1)} | "
                     f"{f(v['h2o']['rate_per_s'], 1)} | "
                     f"{f(v['ours']['rate_per_s'] / v['h2o']['rate_per_s'], 3)
                        if v['h2o']['rate_per_s'] else '-'} | "
                     f"{f(v['ours'].get('srv_cpu_us_per_hs', 0), 1)} | "
                     f"{f(v['h2o'].get('srv_cpu_us_per_hs', 0), 1)} |")
        for k, v in handshake.get("new_conn_h2", {}).items():
            L.append(f"| {k} (h2load -n/-c all-new) | {f(v['ours']['conn_per_s'], 1)} | "
                     f"{f(v['h2o']['conn_per_s'], 1)} | "
                     f"{f(v['ours']['conn_per_s'] / v['h2o']['conn_per_s'], 3)
                        if v['h2o']['conn_per_s'] else '-'} | "
                     f"{f(v['ours'].get('srv_cpu_us_per_conn', 0), 1)} | "
                     f"{f(v['h2o'].get('srv_cpu_us_per_conn', 0), 1)} |")
    if alpn:
        L += ["", "## ALPN split", "",
              "| matrix | side | forced proto | cipher | ALPN(h2 offer) | ALPN(h1 offer) |",
              "|---|---|---|---|---|---|"]
        for case, per_side in alpn.items():
            for side, v in per_side.items():
                L.append(f"| {case} | {side} | {v['forced'].get('protocol')} | "
                         f"{v['forced'].get('cipher')} | {v['alpn_h2'].get('alpn')} | "
                         f"{v['alpn_h1'].get('alpn')} |")
    L.append("")
    with open(path, "w") as fh:
        fh.write("\n".join(L) + "\n")


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ours", required=True)
    ap.add_argument("--h2o", default="/home/dev123/scratch-perfgate/bin/h2o")
    ap.add_argument("--work", default=os.path.expanduser("~/scratch-tlsmatrix/work"))
    ap.add_argument("--logdir", default=os.path.expanduser("~/scratch-tlsmatrix/logs"))
    ap.add_argument("--rounds", type=int, default=5)
    ap.add_argument("--duration", type=int, default=10)
    ap.add_argument("--trace-seconds", type=int, default=3)
    ap.add_argument("--thr-gate", type=float, default=1.2)
    ap.add_argument("--lat-gate", type=float, default=1.2)
    ap.add_argument("--port-offset", type=int, default=0)
    ap.add_argument("--cpu-ours", default="0,1")
    ap.add_argument("--cpu-h2o", default="2,3")
    ap.add_argument("--cpu-client", default="4-7")
    ap.add_argument("--no-pin", action="store_true")
    ap.add_argument("--no-supplementary", action="store_true")
    ap.add_argument("--only", default="",
                    help="comma-separated case names to run (diagnostics)")
    ap.add_argument("--no-access-log", action="store_true",
                    help="diagnostic A/B only: turn ours access log OFF")
    ap.add_argument("--skip-preflight", action="store_true")
    ap.add_argument("--handshake", action="store_true",
                    help="run openssl s_time / all-new-connection handshake probes")
    ap.add_argument("--handshake-seconds", type=int, default=5)
    ap.add_argument("--handshake-reps", type=int, default=3)
    ap.add_argument("--profile", default="",
                    help="comma-separated case names to profile with strace/perf")
    ap.add_argument("--profile-seconds", type=int, default=5)
    ap.add_argument("--out", default="")
    ap.add_argument("--md", default="")
    args = ap.parse_args()
    if args.rounds < 3:
        print("warning: --rounds < 3 is below the spec's >=3 alternating rounds",
              file=sys.stderr)

    cases = list(MATRICES)
    if not args.no_supplementary:
        cases += list(SUPPLEMENTARY)
    if args.only:
        wanted = {x.strip() for x in args.only.split(",") if x.strip()}
        cases = [m for m in cases if m.name in wanted]
        if not cases:
            print(f"ERROR: --only {args.only!r} matched no case", file=sys.stderr)
            return 2
    if args.port_offset:
        cases = [Matrix(m.name, m.oport + args.port_offset, m.hport + args.port_offset,
                        m.tls, m.proto, m.tlsver, m.h2m, m.supplementary)
                 for m in cases]
    gate_cases = [m for m in cases if not m.supplementary]
    # unique (name,port) pairs for config generation; m1 reuses tls13-h2 ports
    config_cases: List[Matrix] = []
    seen = set()
    for m in cases:
        if m.name in seen:
            continue
        seen.add(m.name)
        config_cases.append(m)
    # the m1 variant is not a listener of its own
    config_cases = [m for m in config_cases if not m.supplementary]

    work = os.path.abspath(args.work)
    logdir = os.path.abspath(args.logdir)
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(os.path.join(work, "www"), exist_ok=True)
    os.makedirs(logdir, exist_ok=True)
    payload = os.path.join(work, "www", "index.html")
    with open(payload, "wb") as f:
        f.write(b"y" * 127)
    write_openssl_confs(work)

    # Port conflicts: fail before spawning anything.
    want_ports = []
    for m in config_cases:
        want_ports += [m.oport, m.hport]
    busy = [p for p in want_ports if not port_free(p)]
    if busy:
        print(f"ERROR: ports already in use: {busy} (block 26200-26299)", file=sys.stderr)
        return 2

    cert = os.path.join(work, "cert.pem")
    key = os.path.join(work, "key.pem")
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3",
        "-keyout", key, "-out", cert, "-subj", "/CN=bench.test",
        "-addext", "subjectAltName=DNS:bench.test,IP:127.0.0.1",
    ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    ours_conf, h2o_conf = write_configs(work, os.path.join(work, "www"), cert, key,
                                        config_cases,
                                        access_log=not args.no_access_log)
    # same payload inode check for every matrix docroot
    payload_md5 = md5(payload)
    for m in config_cases:
        p = os.path.join(work, f"www-{m.name}", "index.html")
        assert os.path.getsize(p) == 127 and md5(p) == payload_md5

    env_ours = dict(os.environ)
    env_ours.update({
        "CRUCIBLE_WORKER_THREADS": "2",
        "CRUCIBLE_DNS_STATE_ROOT": os.path.join(work, "state-dns"),
        "RUST_LOG": "info",
    })
    ours_log_path = os.path.join(logdir, "ours.log")
    h2o_log_path = os.path.join(logdir, "h2o.log")
    ours_log = open(ours_log_path, "w")
    h2o_log = open(h2o_log_path, "w")
    ours = subprocess.Popen([args.ours, "--config", ours_conf], env=env_ours,
                            stdout=ours_log, stderr=subprocess.STDOUT,
                            start_new_session=True)
    h2o = subprocess.Popen([args.h2o, "-c", h2o_conf], env=dict(os.environ),
                           stdout=h2o_log, stderr=subprocess.STDOUT,
                           start_new_session=True)
    meta: Dict[str, object] = {
        "date": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "host": os.uname().nodename, "cores": os.cpu_count(),
        "loadavg_start": loadavg(),
        "ours_bin": os.path.abspath(args.ours), "ours_md5": md5(args.ours),
        "h2o_bin": os.path.abspath(args.h2o), "h2o_md5": md5(args.h2o),
        "h2o_version": tool_version(args.h2o, ["--version"]),
        "wrk_version": tool_version(shutil.which("wrk") or WRK_DEFAULT, ["--version"]),
        "h2load_version": tool_version(shutil.which("h2load") or H2LOAD_DEFAULT,
                                       ["--version"]),
        "payload": {"path": payload, "bytes": 127, "md5": payload_md5},
        "rounds": args.rounds, "duration_s": args.duration,
        "cpu_sets": {"ours": args.cpu_ours, "h2o": args.cpu_h2o,
                     "client": args.cpu_client, "pinned": not args.no_pin},
        "shape": {
            "h1": f"wrk -t2 -c64 -d{args.duration}s --latency",
            "h2": f"h2load -n 0 -c 50 -t 2 -D {args.duration} -m 10 (also m1)",
            "payload": "127 B index.html, same inode for both servers per matrix",
            "threads": "ours CRUCIBLE_WORKER_THREADS=2 / h2o num-threads: 2",
            "keep_alive": True,
            "ours_access_log": ("OFF (diagnostic A/B)" if args.no_access_log
                                else "ON (level=info, realtime=false)"),
            "h2o_access_log": "OFF",
            "tls12_client_pin": "OPENSSL_CONF MaxProtocol=TLSv1.2 (h2o ignores "
                                "maximum-version for TLS1.3; verified by s_client)",
        },
    }

    summary_all: List[Dict[str, object]] = []
    rows_all: List[Dict[str, float]] = []
    handshake: Optional[Dict[str, object]] = None
    profiles: Dict[str, object] = {}
    alpn_res: Dict[str, object] = {}
    try:
        err = wait_ports({"ours": ours, "h2o": h2o}, want_ports)
        if err:
            print(f"ERROR: {err}\n--- ours.log ---\n{tail(ours_log_path)}\n"
                  f"--- h2o.log ---\n{take_tail(h2o_log_path)}", file=sys.stderr)
            return 2
        time.sleep(0.5)

        if not args.no_pin:
            up = set_affinity(ours.pid, args.cpu_ours)
            hp = set_affinity(h2o.pid, args.cpu_h2o)
            print(f"affinity ours={affinity_of(ours.pid)} h2o={affinity_of(h2o.pid)} "
                  f"(set={up}/{hp}) client={args.cpu_client}", flush=True)

        # preflight + TLS/ALPN probes on the distinct listeners
        for m in config_cases:
            env = client_env(m.tlsver if m.tls else None, work)
            if not args.skip_preflight:
                ok, notes = preflight(m, work, env)
                for n in notes:
                    print(n, flush=True)
                if not ok:
                    print("preflight failed; aborting", file=sys.stderr)
                    return 2
            if m.tls:
                probes = tls_matrix_probes(m, work)
                alpn_res[m.name] = probes
                for who, v in probes.items():
                    got = v["pinned"].get("protocol")
                    if got != m.tlsver:
                        print(f"FATAL: {m.name}/{who}: client with OPENSSL_CONF "
                              f"pinned to {m.tlsver} negotiated {got!r}", file=sys.stderr)
                        return 2
                    print(f"pin {m.name}/{who}: {m.tlsver} OK "
                          f"(cipher {v['pinned'].get('cipher')})", flush=True)

        for m in cases:
            kind = "wrk" if m.proto == "h1" else "h2load"
            scheme = "https" if m.tls else "http"
            ours_url = f"{scheme}://127.0.0.1:{m.oport}/"
            h2o_url = f"{scheme}://127.0.0.1:{m.hport}/"
            env = client_env(m.tlsver if m.tls else None, work)
            print(f"== {m.name}: ours={ours_url} h2o={h2o_url} client={kind}"
                  f"{'' if m.h2m is None else ' m='+str(m.h2m)}", flush=True)
            # warmup (not counted)
            for who, pid, url in (("ours", ours.pid, ours_url),
                                  ("h2o", h2o.pid, h2o_url)):
                if not args.no_pin:
                    set_affinity(pid, args.cpu_ours if who == "ours" else args.cpu_h2o)
                run_client(kind, url, min(3, args.duration), m.h2m, env,
                           cpus="" if args.no_pin else args.cpu_client)
            local: List[Dict[str, float]] = []
            for r in range(args.rounds):
                aff_ours = args.cpu_ours if r % 2 == 0 else args.cpu_h2o
                aff_h2o = args.cpu_h2o if r % 2 == 0 else args.cpu_ours
                if not args.no_pin:
                    set_affinity(ours.pid, aff_ours)
                    set_affinity(h2o.pid, aff_h2o)
                order = [("ours", ours.pid, ours_url), ("h2o", h2o.pid, h2o_url)]
                if r % 2 == 1:
                    order.reverse()
                for label, pid, url in order:
                    row = one_round(label, pid, kind, url, args.duration, m.h2m,
                                    env, "" if args.no_pin else args.cpu_client,
                                    logdir, f"{m.name}-r{r}")
                    row.update({"matrix": m.name, "round": r})
                    local.append(row)
                    rows_all.append(row)
                    ok = (row.get("non2xx", 0) == 0 and row.get("failed", 0) == 0
                          and row.get("rc", 0) == 0 and row.get("n_requests", 0) > 0)
                    print(f"  r{r} {label:4s} rps={row['rps']:10.1f} "
                          f"lat={row.get('lat_mean_us', 0):9.1f}us "
                          f"p50={row.get('lat_p50_us', 0):8.1f} "
                          f"p99={row.get('lat_p99_us', 0):8.1f} "
                          f"cpu/req={row.get('srv_cpu_us_per_req', 0):7.2f}us "
                          f"cores={row.get('srv_cores', 0):4.2f} "
                          f"usr={row.get('srv_user_pct', 0):5.1f}% "
                          f"ctx/req={((row.get('vol_ctx', 0) + row.get('invol_ctx', 0))
                                      / (row.get('n_requests') or 1)):6.2f} "
                          f"load={row['loadavg']} {'OK' if ok else 'BAD'}", flush=True)
            # h2 p50/p99 from a separate short log-file trace window
            trace: Dict[str, Dict[str, float]] = {}
            if m.proto == "h2":
                for who, pid, url in (("ours", ours.pid, ours_url),
                                      ("h2o", h2o.pid, h2o_url)):
                    lp = os.path.join(logdir, f"trace-{m.name}-{who}.h2load.log")
                    if not args.no_pin:
                        set_affinity(pid, args.cpu_ours if who == "ours" else args.cpu_h2o)
                    tr, _raw, _w, _c, _t, _rc = run_client(
                        kind, url, args.trace_seconds, m.h2m, env,
                        cpus="" if args.no_pin else args.cpu_client, log_path=lp)
                    trace[who] = tr
            s = summarize_case(m, local, trace, args.thr_gate, args.lat_gate)
            s["cpu_sets_per_round"] = {"ours": [args.cpu_ours if r % 2 == 0
                                                else args.cpu_h2o for r in range(args.rounds)],
                                       "h2o": [args.cpu_h2o if r % 2 == 0
                                               else args.cpu_ours for r in range(args.rounds)]}
            if trace:
                s["lat_trace"] = trace
            summary_all.append(s)
            print(f"  SUMMARY {s['matrix']}: ours={s['ours_rps']:.1f} rps/"
                  f"{s['ours_lat_mean_us']:.0f}us h2o={s['h2o_rps']:.1f} rps/"
                  f"{s['h2o_lat_mean_us']:.0f}us "
                  f"thr(h2o/ours)={s['throughput_ratio_h2o_over_ours']:.3f} "
                  f"lat(ours/h2o)={s['latency_ratio_ours_over_h2o']:.3f} "
                  f"p50={med(s['p50_ratio_pairs']):.3f} "
                  f"p99={med(s['p99_ratio_pairs']):.3f} -> {s['verdict']}", flush=True)

        # optional strace/perf profiling: each profiled server runs *under* the
        # tool on dedicated ports (attach -p is blocked by yama scope=1).
        prof_names = [x.strip() for x in args.profile.split(",") if x.strip()]
        for name in prof_names:
            m = next((c for c in cases if c.name == name), None)
            if m is None:
                print(f"profile: unknown case {name}", file=sys.stderr)
                continue
            print(f"== profile {m.name} ({args.profile_seconds}s per side, "
                  f"ports 26285/26295)", flush=True)
            out = profile_case(m, args.ours, args.h2o, work, logdir, cert, key,
                               args.profile_seconds, args)
            profiles[m.name] = out
            for tool, runs in out.get("runs", {}).items():
                for who, entry in runs.items():
                    detail = entry.get(tool, {})
                    print(f"  {tool} {who}: rps={entry.get('round', {}).get('rps', 0):.0f} "
                          f"calls={detail.get('total_calls', 'n/a')} "
                          f"cycles={detail.get('cycles', 'n/a')} "
                          f"ctxsw={detail.get('context_switches', 'n/a')} "
                          f"user%={detail.get('user_pct', 'n/a')}", flush=True)

        # optional handshake / all-new-connection probes
        if args.handshake:
            hs: Dict[str, object] = {"s_time": {}, "new_conn_h2": {}}
            for m in config_cases:
                if not m.tls:
                    continue
                key = f"{m.name} ({m.tlsver})"
                entry = {}
                for who, pid, port in (("ours", ours.pid, m.oport),
                                       ("h2o", h2o.pid, m.hport)):
                    if not args.no_pin:
                        set_affinity(pid, args.cpu_ours if who == "ours" else args.cpu_h2o)
                    reps = [s_time(port, m.tlsver, args.handshake_seconds, pid,
                                   "" if args.no_pin else args.cpu_client)
                            for _ in range(args.handshake_reps)]
                    entry[who] = {
                        "rate_per_s": med([x.get("rate_per_s", 0) for x in reps]),
                        "srv_cpu_us_per_hs": med([x.get("srv_cpu_us_per_hs", 0)
                                                  for x in reps]),
                        "reps": reps,
                    }
                    print(f"  s_time {key}/{who}: "
                          f"{entry[who]['rate_per_s']:.1f} conn/s "
                          f"{entry[who]['srv_cpu_us_per_hs']:.1f}us CPU/hs", flush=True)
                hs["s_time"][key] = entry
            m = next((c for c in cases if c.name == "tls13-h2"), None)
            if m:
                env = client_env(m.tlsver, work)
                entry = {}
                for who, pid, port in (("ours", ours.pid, m.oport),
                                       ("h2o", h2o.pid, m.hport)):
                    if not args.no_pin:
                        set_affinity(pid, args.cpu_ours if who == "ours" else args.cpu_h2o)
                    reps = [h2load_new_conn(f"https://127.0.0.1:{port}/", 600, env,
                                            "" if args.no_pin else args.cpu_client, pid)
                            for _ in range(3)]
                    entry[who] = {
                        "conn_per_s": med([x.get("conn_per_s", 0) for x in reps]),
                        "srv_cpu_us_per_conn": med([x.get("srv_cpu_us_per_conn", 0)
                                                    for x in reps]),
                        "reps": reps,
                    }
                    print(f"  h2load all-new {who}: "
                          f"{entry[who]['conn_per_s']:.1f} conn/s "
                          f"{entry[who]['srv_cpu_us_per_conn']:.1f}us CPU/conn",
                          flush=True)
                hs["new_conn_h2"]["tls13-h2"] = entry
            handshake = hs

        # TLS1.2 vs TLS1.3 attribution numbers (same host, ours/h2o)
        by = {s["matrix"]: s for s in summary_all}
        attrib = {}
        for who in ("ours", "h2o"):
            a = by.get("tls12-h1", {}).get(f"{who}_rps", 0.0)
            b = by.get("tls13-h1", {}).get(f"{who}_rps", 0.0)
            ca = by.get("tls12-h1", {}).get(f"{who}_cpu_us_per_req", 0.0)
            cb = by.get("tls13-h1", {}).get(f"{who}_cpu_us_per_req", 0.0)
            attrib[who] = {
                "tls12_rps": a, "tls13_rps": b,
                "tls13_over_tls12_rps": (b / a) if a else 0.0,
                "tls12_cpu_us_per_req": ca, "tls13_cpu_us_per_req": cb,
                "tls13_over_tls12_cpu": (cb / ca) if ca else 0.0,
            }

        print()
        hdr = (f"{'case':<14} {'client':<7} {'ours_rps':>11} {'h2o_rps':>11} "
               f"{'thr':>6} {'ours_lat':>9} {'h2o_lat':>9} {'lat':>6} "
               f"{'p50':>6} {'p99':>6} {'verdict':>11}")
        print(hdr)
        print("-" * len(hdr))
        for s in summary_all:
            print(f"{s['matrix']:<14} {s['client']:<7} {s['ours_rps']:>11.1f} "
                  f"{s['h2o_rps']:>11.1f} "
                  f"{s['throughput_ratio_h2o_over_ours']:>6.3f} "
                  f"{s['ours_lat_mean_us']:>8.1f}u {s['h2o_lat_mean_us']:>8.1f}u "
                  f"{s['latency_ratio_ours_over_h2o']:>6.3f} "
                  f"{med(s['p50_ratio_pairs']):>6.3f} {med(s['p99_ratio_pairs']):>6.3f} "
                  f"{s['verdict']:>11}")
        print()
        print(f"gates: throughput h2o/ours <= {args.thr_gate}, "
              f"latency ours/h2o <= {args.lat_gate}")
        out_path = args.out or os.path.join(work, "tls-matrix.json")
        with open(out_path, "w") as f:
            json.dump({"config": vars(args), "meta": meta, "summary": summary_all,
                       "rounds": rows_all, "alpn": alpn_res,
                       "handshake": handshake, "profile": profiles,
                       "attribution": attrib}, f, indent=1, sort_keys=True)
        print(f"wrote {out_path}")
        if args.md:
            write_markdown(args.md, meta, summary_all, handshake, alpn_res,
                           args.thr_gate, args.lat_gate)
            print(f"wrote {args.md}")
        return 0 if all(s["verdict"] == "PASS" for s in summary_all
                        if not s["supplementary"]) else 1
    finally:
        kill_group(ours)
        kill_group(h2o)
        ours_log.close()
        h2o_log.close()


def take_tail(path: str, n: int = 30) -> str:
    return tail(path, n)


if __name__ == "__main__":
    raise SystemExit(main())
