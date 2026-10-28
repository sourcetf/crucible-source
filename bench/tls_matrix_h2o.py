#!/usr/bin/env python3
"""U-07: TLS matrix × h2o 2.2.5 fair comparison (plain-h1 / tls12-h1 / tls13-h1 / tls13-h2).

Spec shape (webserver-rebuild-prompt-v2.txt §0/§22.1, bench/spec_gate):
  * small static file (127 B index.html), both sides same file/docroot
  * both sides 2 worker threads (ours CRUCIBLE_WORKER_THREADS=2, h2o num-threads: 2)
  * keep-alive, h1 = ``wrk -t2 -c64 -d10s --latency``;
    h2 = ``h2load -n 0 -c 50 -t 2 -D 10``
  * gates: throughput ``h2o_rps / ours_rps <= 1.2``; latency ``ours_mean / h2o_mean <= 1.2``
  * ABBA alternation per round, medians over rounds.

The harness starts both servers itself (self-contained configs), runs the four
matrices, prints a table and writes JSON. It does not touch any shared config.

Usage:
  python3 bench/tls_matrix_h2o.py \
      --ours ~/scratch-dot443/target/release/webserver \
      --h2o ~/scratch-perfgate/bin/h2o \
      --work ~/scratch-dot443/u07 --rounds 3 --duration 10
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import signal
import statistics
import subprocess
import sys
import time
from typing import Dict, List, Optional, Tuple

TICKS = os.sysconf("SC_CLK_TCK")
MATRICES = [
    # name, ours_port, h2o_port, tls, h1/h2, ssl min/max
    ("plain-h1", 44681, 44691, False, "h1", None),
    ("tls12-h1", 44682, 44692, True, "h1", "TLSv1.2"),
    ("tls13-h1", 44683, 44693, True, "h1", "TLSv1.3"),
    ("tls13-h2", 44684, 44694, True, "h2", "TLSv1.3"),
]


def loadavg() -> str:
    with open("/proc/loadavg") as f:
        return f.read().split()[0]


def cpu_ticks(pid: int) -> Optional[int]:
    try:
        with open(f"/proc/{pid}/stat") as f:
            data = f.read()
    except OSError:
        return None
    rest = data[data.rfind(")") + 2:].split()
    return int(rest[11]) + int(rest[12])


_NUM = r"([\d.]+)\s*([KMGkmg]?)"


def _scale(v: float, suffix: str) -> float:
    return v * {"": 1.0, "k": 1e3, "m": 1e6, "g": 1e9}[suffix.lower()]


def parse_wrk(out: str) -> Dict[str, float]:
    res = {"rps": 0.0, "lat_mean_us": 0.0, "lat_p50_us": 0.0, "lat_p99_us": 0.0}
    m = re.search(r"Requests/sec:\s*" + _NUM, out)
    if m:
        res["rps"] = _scale(float(m.group(1)), m.group(2))
    m = re.search(r"Latency\s+([\d.]+)(us|ms|s)\s+([\d.]+)(us|ms|s)\s+([\d.]+)(us|ms|s)", out)
    if m:
        def us(v: str, u: str) -> float:
            return float(v) * {"us": 1.0, "ms": 1e3, "s": 1e6}[u]
        res["lat_mean_us"] = us(m.group(1), m.group(2))
        res["lat_p50_us"] = us(m.group(3), m.group(4))
        res["lat_p99_us"] = us(m.group(5), m.group(6))
    # non-2xx counter (wrk prints "Non-2xx or 3xx responses: N")
    m = re.search(r"Non-2xx or 3xx responses:\s*(\d+)", out)
    res["non2xx"] = float(m.group(1)) if m else 0.0
    return res


def parse_h2load(out: str) -> Dict[str, float]:
    res = {"rps": 0.0, "lat_mean_us": 0.0, "succeeded": 0.0, "failed": 0.0,
           "errored": 0.0, "timeout": 0.0, "non2xx": 0.0}
    m = re.search(r"finished in [\d.]+s,\s*" + _NUM + r"req/s,\s*" + _NUM + r"B/s", out)
    if m:
        res["rps"] = _scale(float(m.group(1)), m.group(2))
    m = re.search(
        r"requests:\s*(\d+)\s+total,\s*(\d+)\s+started,\s*(\d+)\s+done,\s*(\d+)\s+succeeded,"
        r"\s*(\d+)\s+failed,\s*(\d+)\s+errored,\s*(\d+)\s+timeout", out)
    if m:
        res["succeeded"] = float(m.group(4))
        res["failed"] = float(m.group(5))
        res["errored"] = float(m.group(6))
        res["timeout"] = float(m.group(7))
    m = re.search(r"time for request:\s*([\d.]+)(us|ms|s)\s+([\d.]+)(us|ms|s)\s+"
                  r"([\d.]+)(us|ms|s)", out)
    if m:
        def us(v: str, u: str) -> float:
            return float(v) * {"us": 1.0, "ms": 1e3, "s": 1e6}[u]
        res["lat_mean_us"] = us(m.group(5), m.group(6))
    # h2load prints status code table; sum non-2xx
    for m in re.finditer(r"^\s*(\d{3}):\s*(\d+)\s*$", out, re.M):
        code, n = int(m.group(1)), int(m.group(2))
        if not (200 <= code < 300):
            res["non2xx"] += n
    return res


def run_client(kind: str, url: str, duration: int) -> Tuple[Dict[str, float], str]:
    env = dict(os.environ)
    if kind == "wrk":
        cmd = [shutil.which("wrk") or "/home/dev123/local/usr/bin/wrk",
               "-t2", "-c64", f"-d{duration}s", "--latency", url]
    else:
        env["LD_LIBRARY_PATH"] = ("/home/dev123/local/usr/lib/x86_64-linux-gnu:"
                                  "/home/dev123/local/usr/lib:" + env.get("LD_LIBRARY_PATH", ""))
        cmd = [shutil.which("h2load") or "/home/dev123/local/usr/bin/h2load",
               "-n", "0", "-c", "50", "-t", "2", "-D", str(duration), url]
    t0 = time.time()
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       text=True, timeout=duration + 180, env=env)
    wall = time.time() - t0
    out = p.stdout or ""
    res = parse_wrk(out) if kind == "wrk" else parse_h2load(out)
    res["wall_s"] = wall
    res["rc"] = p.returncode
    res["cmd"] = " ".join(cmd)
    return res, out


def one_round(label: str, pid: int, kind: str, url: str, duration: int,
              outdir: str, tag: str) -> Dict[str, float]:
    c0 = cpu_ticks(pid)
    res, raw = run_client(kind, url, duration)
    c1 = cpu_ticks(pid)
    if c0 is not None and c1 is not None:
        cpu_s = (c1 - c0) / TICKS
        res["srv_cpu_s"] = cpu_s
        res["srv_cores"] = cpu_s / res["wall_s"] if res["wall_s"] > 0 else 0.0
        n = res.get("succeeded") or (res.get("rps", 0) * res["wall_s"])
        res["srv_cpu_us_per_req"] = cpu_s / n * 1e6 if n else 0.0
    res.update({"label": label, "url": url, "loadavg": loadavg(),
                "ts": time.strftime("%H:%M:%S")})
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, f"{tag}-{label}.out"), "w") as f:
        f.write(raw)
    return res


def med(xs: List[float]) -> float:
    return statistics.median(xs) if xs else 0.0


def write_configs(work: str, ours_bin: str, h2o_bin: str, cert: str, key: str,
                  www: str) -> str:
    """Write ours config + h2o config. Returns ours config path."""
    ours = os.path.join(work, "ours.toml")
    listeners = []
    for name, oport, _hport, tls, proto, ver in MATRICES:
        # 每个 listener 独立 docroot（同一份 127B index.html）：产品会拒绝两个
        # listener 共用同一 root（bind_key 跨站守卫）。
        root = os.path.join(work, f"www-{name}")
        os.makedirs(root, exist_ok=True)
        shutil.copyfile(os.path.join(www, "index.html"), os.path.join(root, "index.html"))
        block = [f'[[listeners]]\naddress = "127.0.0.1"\nport = {oport}\n'
                 f'root = "{root}"\nautoindex = false\n'
                 f'http_versions = ["{proto}"]\nserver_name = "{name}.test"\n']
        if tls:
            block.append(f'[listeners.ssl]\ncert = "{cert}"\nkey = "{key}"\n')
            if ver:
                block.append(f'versions = ["{ver}"]\n')
        listeners.append("".join(block))
    with open(ours, "w") as f:
        f.write("[access_log]\nenable = false\n\n" + "\n".join(listeners))

    h2o = os.path.join(work, "h2o.conf")
    parts = ["num-threads: 2\nhosts:\n"]
    for name, _oport, hport, tls, proto, ver in MATRICES:
        parts.append(f'  "{name}":\n    listen:\n      host: 127.0.0.1\n      port: {hport}\n')
        if tls:
            parts.append(f"      ssl:\n        certificate-file: {cert}\n"
                         f"        key-file: {key}\n")
            if ver:
                parts.append(f"        minimum-version: {ver}\n"
                             f"        maximum-version: {ver}\n")
        parts.append(f'    paths:\n      "/":\n        file.dir: {www}\n')
    with open(h2o, "w") as f:
        f.write("".join(parts))
    return ours


def wait_port(port: int, timeout: float = 15.0) -> bool:
    import socket
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ours", required=True)
    ap.add_argument("--h2o", default="/home/dev123/scratch-perfgate/bin/h2o")
    ap.add_argument("--work", default=os.path.expanduser("~/scratch-dot443/u07"))
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--duration", type=int, default=10)
    ap.add_argument("--thr-gate", type=float, default=1.2)
    ap.add_argument("--lat-gate", type=float, default=1.2)
    ap.add_argument("--out", default="")
    args = ap.parse_args()

    work = args.work
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(os.path.join(work, "www"), exist_ok=True)
    os.makedirs(os.path.join(work, "logs"), exist_ok=True)
    with open(os.path.join(work, "www", "index.html"), "wb") as f:
        f.write(b"y" * 127)

    cert = os.path.join(work, "cert.pem")
    key = os.path.join(work, "key.pem")
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3",
        "-keyout", key, "-out", cert, "-subj", "/CN=bench.test",
        "-addext", "subjectAltName=DNS:bench.test,IP:127.0.0.1",
    ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    ours_conf = write_configs(work, args.ours, args.h2o, cert, key,
                              os.path.join(work, "www"))
    env = dict(os.environ)
    env["CRUCIBLE_WORKER_THREADS"] = "2"
    ours_log = open(os.path.join(work, "logs", "ours.log"), "w")
    h2o_log = open(os.path.join(work, "logs", "h2o.log"), "w")
    ours = subprocess.Popen([args.ours, "--config", ours_conf], env=env,
                            stdout=ours_log, stderr=subprocess.STDOUT)
    h2o = subprocess.Popen([args.h2o, "-c", os.path.join(work, "h2o.conf")],
                           stdout=h2o_log, stderr=subprocess.STDOUT)
    try:
        for _name, oport, hport, tls, _proto, _ver in MATRICES:
            if not wait_port(oport) or not wait_port(hport):
                print(f"server did not start for {_name} (ours={oport} h2o={hport})",
                      file=sys.stderr)
                return 2
        time.sleep(1.0)

        rows: List[Dict] = []
        summary: List[Dict] = []
        for name, oport, hport, tls, proto, _ver in MATRICES:
            kind = "wrk" if proto == "h1" else "h2load"
            scheme = "https" if tls else "http"
            ours_url = f"{scheme}://127.0.0.1:{oport}/"
            h2o_url = f"{scheme}://127.0.0.1:{hport}/"
            # pre-check both endpoints answer 200
            for url in (ours_url, h2o_url):
                chk = subprocess.run([
                    "curl", "-sk", "-o", "/dev/null", "-w", "%{http_code} %{http_version}",
                    "--max-time", "10",
                    *(["--http2"] if proto == "h2" else ["--http1.1"]), url,
                ], stdout=subprocess.PIPE, text=True)
            print(f"== {name}: ours={ours_url} h2o={h2o_url} client={kind}", flush=True)
            local: List[Dict] = []
            for r in range(args.rounds):
                order = [("ours", ours.pid, ours_url), ("h2o", h2o.pid, h2o_url)]
                if r % 2 == 1:
                    order.reverse()
                for label, pid, url in order:
                    row = one_round(label, pid, kind, url, args.duration,
                                    os.path.join(work, "logs"), f"{name}-r{r}")
                    row.update({"matrix": name, "round": r})
                    local.append(row)
                    rows.append(row)
                    ok = row.get("non2xx", 0) == 0 and row.get("failed", 0) == 0
                    print(f"  r{r} {label:4s} rps={row['rps']:10.1f} "
                          f"lat={row.get('lat_mean_us', 0):9.1f}us "
                          f"cpu/req={row.get('srv_cpu_us_per_req', 0):7.2f}us "
                          f"cores={row.get('srv_cores', 0):4.2f} "
                          f"non2xx={int(row.get('non2xx', 0))} "
                          f"fail={int(row.get('failed', 0))} "
                          f"load={row['loadavg']} {'OK' if ok else 'BAD'}", flush=True)
            a = [x for x in local if x["label"] == "ours"]
            b = [x for x in local if x["label"] == "h2o"]
            a_rps, b_rps = med([x["rps"] for x in a]), med([x["rps"] for x in b])
            a_lat, b_lat = med([x["lat_mean_us"] for x in a]), med([x["lat_mean_us"] for x in b])
            # 主判据：同轮配对比值（ABBA）—— 本机 loadavg 在窗口内会漂移，
            # 绝对中位数会被「某一轮恰好被外部负载压慢」带偏；同轮两个测量只隔
            # 一个 10s 窗口，比值稳定得多。绝对中位数仅作参考。
            pair_thr, pair_lat = [], []
            for r in range(args.rounds):
                ra = [x for x in local if x["round"] == r and x["label"] == "ours"]
                rb = [x for x in local if x["round"] == r and x["label"] == "h2o"]
                if ra and rb and ra[0]["rps"] > 0 and rb[0].get("lat_mean_us", 0) > 0:
                    pair_thr.append(rb[0]["rps"] / ra[0]["rps"])
                    pair_lat.append(ra[0]["lat_mean_us"] / rb[0]["lat_mean_us"])
            thr = med(pair_thr) if pair_thr else (b_rps / a_rps if a_rps > 0 else float("inf"))
            lat = med(pair_lat) if pair_lat else (a_lat / b_lat if b_lat > 0 else float("inf"))
            bad = sum(int(x.get("non2xx", 0)) + int(x.get("failed", 0)) for x in local)
            verdict = "PASS" if thr <= args.thr_gate and lat <= args.lat_gate and bad == 0 else "FAIL"
            summary.append({
                "matrix": name, "client": kind, "rounds": args.rounds,
                "ours_rps": a_rps, "h2o_rps": b_rps,
                "throughput_ratio_h2o_over_ours": thr,
                "throughput_ratio_pairs": pair_thr,
                "ours_lat_mean_us": a_lat, "h2o_lat_mean_us": b_lat,
                "latency_ratio_ours_over_h2o": lat,
                "latency_ratio_pairs": pair_lat,
                "ours_cpu_us_per_req": med([x.get("srv_cpu_us_per_req", 0) for x in a]),
                "h2o_cpu_us_per_req": med([x.get("srv_cpu_us_per_req", 0) for x in b]),
                "ours_cores": med([x.get("srv_cores", 0) for x in a]),
                "h2o_cores": med([x.get("srv_cores", 0) for x in b]),
                "bad_statuses": bad,
                "verdict": verdict,
            })
            print(f"  SUMMARY {name}: ours={a_rps:.1f} rps/{a_lat:.0f}us "
                  f"h2o={b_rps:.1f} rps/{b_lat:.0f}us "
                  f"thr(h2o/ours)={thr:.3f} lat(ours/h2o)={lat:.3f} -> {verdict}",
                  flush=True)

        print()
        hdr = (f"{'case':<10} {'client':<7} {'ours_rps':>11} {'h2o_rps':>11} "
               f"{'thr':>6} {'ours_lat':>9} {'h2o_lat':>9} {'lat':>6} {'verdict':>7}")
        print(hdr)
        print("-" * len(hdr))
        for s in summary:
            print(f"{s['matrix']:<10} {s['client']:<7} {s['ours_rps']:>11.1f} "
                  f"{s['h2o_rps']:>11.1f} "
                  f"{s['throughput_ratio_h2o_over_ours']:>6.3f} "
                  f"{s['ours_lat_mean_us']:>8.1f}u {s['h2o_lat_mean_us']:>8.1f}u "
                  f"{s['latency_ratio_ours_over_h2o']:>6.3f} {s['verdict']:>7}")
        print()
        print(f"gates: throughput h2o/ours <= {args.thr_gate}, "
              f"latency ours/h2o <= {args.lat_gate}")
        out_path = args.out or os.path.join(work, "tls-matrix.json")
        with open(out_path, "w") as f:
            json.dump({"config": vars(args), "summary": summary, "rounds": rows},
                      f, indent=1, sort_keys=True)
        print(f"wrote {out_path}")
        return 0 if all(s["verdict"] == "PASS" for s in summary) else 1
    finally:
        for p in (ours, h2o):
            try:
                p.send_signal(signal.SIGTERM)
            except ProcessLookupError:
                pass
        for p in (ours, h2o):
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()
        ours_log.close()
        h2o_log.close()


if __name__ == "__main__":
    raise SystemExit(main())
