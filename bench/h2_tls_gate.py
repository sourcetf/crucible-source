#!/usr/bin/env python3
"""HTTP/2 (h2load) fair gate for TLS1.3 listeners, ABBA-paired.

The spec gate (bench/h2_fair_gate.py:37) uses:
    h2load -n 0 -c 50 -t 2 -D <duration> <url>
This harness runs that exact shape (plus an optional multiplexing depth -m)
against two URLs that are already serving TLS1.3 + ALPN h2, alternating the
order per round (ABBA) and taking medians. It records rps, mean latency,
per-request server CPU from /proc/<pid>/stat, cores, status codes and loadavg,
so cross-window absolute numbers never have to be trusted.

Usage:
  python3 bench/h2_tls_gate.py \
    --a-label ours --a-url https://127.0.0.1:41081/ --a-pid $(cat ours.pid) \
    --b-label h2o  --b-url https://127.0.0.1:41091/ --b-pid $(cat h2o.pid) \
    --modes 1,10 --conc 50 --threads 2 --duration 10 --rounds 3 \
    --out ~/scratch-h2gate/logs/gate-c50.json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import statistics
import subprocess
import time
from typing import Dict, List, Optional, Tuple

H2LOAD = os.environ.get("H2LOAD") or shutil.which("h2load") or "/home/dev123/local/usr/bin/h2load"
LIBPATH = os.environ.get(
    "H2LOAD_LD_LIBRARY_PATH",
    "/home/dev123/local/usr/lib/x86_64-linux-gnu:/home/dev123/local/usr/lib",
)
TICKS = os.sysconf("SC_CLK_TCK")


def loadavg() -> str:
    with open("/proc/loadavg") as f:
        return f.read().split()[0]


def cpu_ticks(pid: int) -> Optional[int]:
    try:
        with open(f"/proc/{pid}/stat") as f:
            data = f.read()
    except OSError:
        return None
    # comm can contain spaces/parens; fields after the last ')' are stable.
    rest = data[data.rfind(")") + 2 :].split()
    # rest[0] is state (field 3); utime is field 14 -> rest[11], stime 15 -> rest[12]
    return int(rest[11]) + int(rest[12])


_NUM = r"([\d.]+)\s*([KMGkmg]?)"


def _scale(v: float, suffix: str) -> float:
    return v * {"": 1.0, "k": 1e3, "m": 1e6, "g": 1e9}[suffix.lower()]


def parse_h2load(out: str) -> Dict[str, float]:
    res: Dict[str, float] = {"rps": 0.0, "lat_mean_us": 0.0, "lat_p50_us": 0.0,
                             "lat_p99_us": 0.0, "requests": 0.0, "succeeded": 0.0,
                             "failed": 0.0, "errored": 0.0, "timeout": 0.0}
    m = re.search(r"finished in [\d.]+s,\s*" + _NUM + r"req/s,\s*" + _NUM + r"B/s", out)
    if m:
        res["rps"] = _scale(float(m.group(1)), m.group(2))
    m = re.search(
        r"requests:\s*(\d+)\s+total,\s*(\d+)\s+started,\s*(\d+)\s+done,\s*(\d+)\s+succeeded,"
        r"\s*(\d+)\s+failed,\s*(\d+)\s+errored,\s*(\d+)\s+timeout",
        out,
    )
    if m:
        res["requests"] = float(m.group(1))
        res["succeeded"] = float(m.group(4))
        res["failed"] = float(m.group(5))
        res["errored"] = float(m.group(6))
        res["timeout"] = float(m.group(7))
    m = re.search(r"time for request:\s*([\d.]+)(us|ms|s)\s+([\d.]+)(us|ms|s)\s+"
                  r"([\d.]+)(us|ms|s)", out)
    if m:
        def us(v: str, u: str) -> float:
            return float(v) * {"us": 1.0, "ms": 1e3, "s": 1e6}[u]
        res["lat_min_us"] = us(m.group(1), m.group(2))
        res["lat_max_us"] = us(m.group(3), m.group(4))
        res["lat_mean_us"] = us(m.group(5), m.group(6))
    m = re.search(r"req/s\s*:\s*([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)", out)
    if m:
        # percentile under the req/s line is per-client distribution, not per-request;
        # keep it for reference only.
        res["client_rps_pmin"] = float(m.group(1))
        res["client_rps_pmax"] = float(m.group(2))
        res["client_rps_mean"] = float(m.group(3))
    return res


def run_h2load(url: str, conc: int, threads: int, duration: int, m: int) -> Tuple[Dict[str, float], str]:
    env = dict(os.environ)
    env["LD_LIBRARY_PATH"] = LIBPATH + (":" + env["LD_LIBRARY_PATH"] if env.get("LD_LIBRARY_PATH") else "")
    cmd = [H2LOAD, "-n", "0", "-c", str(conc), "-t", str(threads),
           "-D", str(duration), "-m", str(m), url]
    t0 = time.time()
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                       timeout=duration + 120, env=env)
    wall = time.time() - t0
    res = parse_h2load(p.stdout)
    res["wall_s"] = wall
    res["cmd"] = " ".join(cmd)
    res["rc"] = p.returncode
    return res, p.stdout


def one_round(label: str, url: str, pid: Optional[int], conc: int, threads: int,
              duration: int, m: int, outdir: str, tag: str) -> Dict[str, float]:
    c0 = cpu_ticks(pid) if pid else None
    res, raw = run_h2load(url, conc, threads, duration, m)
    c1 = cpu_ticks(pid) if pid else None
    if c0 is not None and c1 is not None and res["succeeded"] > 0:
        cpu_s = (c1 - c0) / TICKS
        res["srv_cpu_s"] = cpu_s
        res["srv_cpu_us_per_req"] = cpu_s / res["succeeded"] * 1e6
        res["srv_cores"] = cpu_s / res["wall_s"] if res["wall_s"] > 0 else 0.0
    res.update({"label": label, "url": url, "m": m, "conc": conc,
                "loadavg": loadavg(), "ts": time.strftime("%H:%M:%S")})
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, f"h2load-{tag}-{label}-m{m}.out"), "w") as f:
        f.write(raw)
    return res


def med(xs: List[float]) -> float:
    return statistics.median(xs) if xs else 0.0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--a-label", default="ours")
    ap.add_argument("--a-url", required=True)
    ap.add_argument("--a-pid", type=int, default=0)
    ap.add_argument("--b-label", default="h2o")
    ap.add_argument("--b-url", required=True)
    ap.add_argument("--b-pid", type=int, default=0)
    ap.add_argument("--modes", default="1,10")
    ap.add_argument("--conc", type=int, default=50)
    ap.add_argument("--threads", type=int, default=2)
    ap.add_argument("--duration", type=int, default=10)
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--out", required=True)
    ap.add_argument("--outdir", default="")
    args = ap.parse_args()

    outdir = args.outdir or (os.path.dirname(os.path.abspath(args.out)) or ".")
    modes = [int(x) for x in args.modes.split(",") if x.strip()]
    all_rows: List[Dict[str, float]] = []
    data = {"config": vars(args), "rounds": all_rows, "summary": {}}

    for m in modes:
        rows = []
        for r in range(args.rounds):
            order = [(args.a_label, args.a_url, args.a_pid),
                     (args.b_label, args.b_url, args.b_pid)]
            if r % 2 == 1:
                order.reverse()
            for (label, url, pid) in order:
                row = one_round(label, url, pid or None, args.conc, args.threads,
                                args.duration, m, outdir, f"r{r}")
                rows.append(row)
                all_rows.append(row)
                print(f"m={m} r={r} {label:10s} rps={row['rps']:10.1f} "
                      f"lat_mean={row.get('lat_mean_us', 0):9.1f}us "
                      f"cpu/req={row.get('srv_cpu_us_per_req', 0):8.2f}us "
                      f"cores={row.get('srv_cores', 0):4.2f} "
                      f"ok={int(row['succeeded'])} fail={int(row['failed'])} "
                      f"err={int(row['errored'])} to={int(row['timeout'])} "
                      f"load={row['loadavg']}", flush=True)
        a = [x for x in rows if x["label"] == args.a_label]
        b = [x for x in rows if x["label"] == args.b_label]
        a_rps, b_rps = med([x["rps"] for x in a]), med([x["rps"] for x in b])
        a_lat, b_lat = med([x.get("lat_mean_us", 0) for x in a]), med([x.get("lat_mean_us", 0) for x in b])
        a_cpu = med([x.get("srv_cpu_us_per_req", 0) for x in a])
        b_cpu = med([x.get("srv_cpu_us_per_req", 0) for x in b])
        a_cores = med([x.get("srv_cores", 0) for x in a])
        b_cores = med([x.get("srv_cores", 0) for x in b])
        thr = (b_rps / a_rps) if a_rps > 0 else float("inf")
        lat = (a_lat / b_lat) if b_lat > 0 else float("inf")
        summary = {
            "a": args.a_label, "b": args.b_label, "m": m, "conc": args.conc,
            "a_rps": a_rps, "b_rps": b_rps,
            "throughput_ratio_b_over_a": thr,
            "a_lat_mean_us": a_lat, "b_lat_mean_us": b_lat,
            "latency_ratio_a_over_b": lat,
            "a_cpu_us_per_req": a_cpu, "b_cpu_us_per_req": b_cpu,
            "a_cores": a_cores, "b_cores": b_cores,
            "a_rps_all": [x["rps"] for x in a], "b_rps_all": [x["rps"] for x in b],
            "a_lat_all": [x.get("lat_mean_us", 0) for x in a],
            "b_lat_all": [x.get("lat_mean_us", 0) for x in b],
            "verdict": "PASS" if thr <= 1.2 and lat <= 1.2 else "FAIL",
        }
        data["summary"][f"m{m}"] = summary
        print(f"SUMMARY m={m}: {args.a_label} rps={a_rps:.1f} ({args.a_label} cores={a_cores:.2f} "
              f"cpu/req={a_cpu:.2f}us) {args.b_label} rps={b_rps:.1f} "
              f"({args.b_label} cores={b_cores:.2f} cpu/req={b_cpu:.2f}us) | "
              f"thr {args.b_label}/{args.a_label}={thr:.3f} "
              f"lat {args.a_label}/{args.b_label}={lat:.3f} -> {summary['verdict']}", flush=True)

    with open(args.out, "w") as f:
        json.dump(data, f, indent=1, sort_keys=True)
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
