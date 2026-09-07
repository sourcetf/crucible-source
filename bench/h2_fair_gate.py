#!/usr/bin/env python3
"""HTTP/2 fair gate: dual formulas vs h2o baseline (wrk / h2load)."""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from typing import Optional, Tuple


def which_first(*names: str) -> Optional[str]:
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    return None


def run_wrk(url: str, duration: int) -> Optional[str]:
    wrk = shutil.which("wrk")
    if not wrk:
        return None
    cmd = [wrk, "-t2", "-c64", f"-d{duration}s", "--latency", url]
    try:
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, timeout=duration + 60)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None


def run_h2load(url: str, duration: int) -> Optional[str]:
    h2load = which_first("h2load")
    if not h2load:
        return None
    cmd = [h2load, "-n", "0", "-c", "50", "-t", "2", "-D", str(duration), url]
    try:
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, timeout=duration + 60)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None


def parse_wrk(out: str) -> Tuple[float, float]:
    rps = 0.0
    lat_us = 0.0
    m = re.search(r"Requests/sec:\s+([\d.]+)", out)
    if m:
        rps = float(m.group(1))
    m = re.search(r"Latency\s+([\d.]+)(us|ms|s)", out)
    if m:
        v = float(m.group(1))
        unit = m.group(2)
        if unit == "ms":
            lat_us = v * 1000
        elif unit == "s":
            lat_us = v * 1_000_000
        else:
            lat_us = v
    return rps, lat_us


def parse_h2load(out: str) -> Tuple[float, float]:
    rps = 0.0
    lat_us = 0.0
    m = re.search(r"finished in [\d.]+.*?,\s*([\d.]+)\s*req/s", out)
    if m:
        rps = float(m.group(1))
    m = re.search(r"time for request:\s+[\d.]+.*?\s+([\d.]+)(us|ms|s)", out)
    if m:
        v = float(m.group(1))
        unit = m.group(2)
        if unit == "ms":
            lat_us = v * 1000
        elif unit == "s":
            lat_us = v * 1_000_000
        else:
            lat_us = v
    return rps, lat_us


def measure(url: str, duration: int) -> Tuple[float, float, str]:
    out = run_h2load(url, duration)
    if out:
        rps, lat = parse_h2load(out)
        return rps, lat, "h2load"
    out = run_wrk(url, duration)
    if out:
        rps, lat = parse_wrk(out)
        return rps, lat, "wrk"
    return 0.0, 0.0, "none"


def main() -> int:
    parser = argparse.ArgumentParser(description="H2 fair gate dual formulas")
    parser.add_argument("--target", default="http://127.0.0.1:19081/", help="crucible URL (non-std fair plain)")
    parser.add_argument("--baseline", default="http://127.0.0.1:19082/", help="h2o baseline URL (non-std)")
    parser.add_argument("--duration", type=int, default=10)
    parser.add_argument("--throughput-gate", type=float, default=1.2, help="h2o/ours <= gate")
    parser.add_argument("--latency-gate", type=float, default=1.2, help="ours/h2o <= gate")
    args = parser.parse_args()

    ours_rps, ours_lat, tool_o = measure(args.target, args.duration)
    base_rps, base_lat, tool_b = measure(args.baseline, args.duration)

    print(f"tool: ours={tool_o} baseline={tool_b}")
    print(f"ours     rps={ours_rps:.1f}  lat_us={ours_lat:.1f}  url={args.target}")
    print(f"baseline rps={base_rps:.1f}  lat_us={base_lat:.1f}  url={args.baseline}")

    if ours_rps <= 0 or base_rps <= 0:
        print("FAIL: missing measurements (install wrk and/or h2load)")
        return 2

    thr_ratio = base_rps / ours_rps
    lat_ratio = ours_lat / base_lat if base_lat > 0 else float("inf")
    thr_ok = thr_ratio <= args.throughput_gate
    lat_ok = lat_ratio <= args.latency_gate

    print(f"throughput gate: h2o/ours={thr_ratio:.3f} <= {args.throughput_gate} -> {'PASS' if thr_ok else 'FAIL'}")
    print(f"latency gate:    ours/h2o={lat_ratio:.3f} <= {args.latency_gate} -> {'PASS' if lat_ok else 'FAIL'}")
    return 0 if thr_ok and lat_ok else 1


if __name__ == "__main__":
    sys.exit(main())
