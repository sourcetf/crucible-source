#!/usr/bin/env python3
"""Application engine overhead vs static baseline (wrk wrappers)."""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from typing import Optional


def run_wrk(url: str, threads: int = 2, conns: int = 8, duration: str = "3s") -> Optional[str]:
    wrk = shutil.which("wrk")
    if not wrk:
        print("wrk not found in PATH", file=sys.stderr)
        return None
    cmd = [wrk, f"-t{threads}", f"-c{conns}", f"-d{duration}", "--latency", url]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, timeout=120)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        print(f"wrk failed for {url}: {e}", file=sys.stderr)
        return None
    return out


def parse_rps(out: str) -> str:
    m = re.search(r"Requests/sec:\s+([\d.]+)", out)
    return m.group(1) if m else "?"


def parse_lat(out: str) -> str:
    m = re.search(r"Latency\s+([\d.]+\w+)", out)
    return m.group(1) if m else "?"


def main() -> int:
    parser = argparse.ArgumentParser(description="App engine overhead vs static (wrk)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=19095)
    parser.add_argument("--duration", default="3s")
    parser.add_argument(
        "--engines",
        default="static,php,lua,jsp,asp,aspnet,tsx,python,ruby,perl",
        help="comma-separated labels",
    )
    args = parser.parse_args()

    base = f"http://{args.host}:{args.port}"
    paths = {
        "static": "/",
        "php": "/php/",
        "lua": "/lua/",
        "jsp": "/jsp/",
        "asp": "/asp/",
        "aspnet": "/aspnet/",
        "tsx": "/tsx/",
        "python": "/python/",
        "ruby": "/ruby/",
        "perl": "/perl/",
        "rust": "/rust/",
        "c": "/c/",
        "go": "/go/",
        "wsgi": "/wsgi/",
    }

    rows = []
    for name in [x.strip() for x in args.engines.split(",") if x.strip()]:
        path = paths.get(name, f"/{name}")
        url = base + path
        out = run_wrk(url, duration=args.duration)
        if out is None:
            rows.append((name, url, "SKIP", "SKIP"))
        else:
            rows.append((name, url, parse_rps(out), parse_lat(out)))

    print(f"{'engine':<12} {'rps':>12} {'latency':>12}  url")
    print("-" * 72)
    for name, url, rps, lat in rows:
        print(f"{name:<12} {rps:>12} {lat:>12}  {url}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
