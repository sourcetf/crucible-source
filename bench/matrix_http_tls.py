#!/usr/bin/env python3
"""HTTP/TLS benchmark matrix — iterate ports and print wrk results."""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from typing import List, Optional, Tuple


MATRIX: List[Tuple[str, int, bool]] = [
    # name, default_port, https — defaults = config-test.toml non-std ports
    ("plain-h1", 19081, False),
    ("plain-h2", 19081, False),
    ("tls12-h1", 19445, True),
    ("tls12-h2", 19445, True),
    ("tls13-h1", 19446, True),
    ("tls13-h2", 19446, True),
]


def run_wrk(url: str, duration: str = "3s") -> Optional[str]:
    wrk = shutil.which("wrk")
    if not wrk:
        print("wrk not found", file=sys.stderr)
        return None
    cmd = [wrk, "-t2", "-c8", f"-d{duration}", "--latency", url]
    try:
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, timeout=120)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        return f"ERROR: {e}"


def parse_rps(out: str) -> str:
    m = re.search(r"Requests/sec:\s+([\d.]+)", out or "")
    return m.group(1) if m else "n/a"


def main() -> int:
    parser = argparse.ArgumentParser(description="HTTP/TLS benchmark matrix")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--duration", default="3s")
    parser.add_argument("--port-plain", type=int, default=19081)
    parser.add_argument("--port-tls12", type=int, default=19445)
    parser.add_argument("--port-tls13", type=int, default=19446)
    args = parser.parse_args()

    ports = {
        "plain-h1": args.port_plain,
        "plain-h2": args.port_plain,
        "tls12-h1": args.port_tls12,
        "tls12-h2": args.port_tls12,
        "tls13-h1": args.port_tls13,
        "tls13-h2": args.port_tls13,
    }

    print(f"{'case':<12} {'port':>6} {'rps':>12}  url")
    print("-" * 64)
    for name, _default, https in MATRIX:
        port = ports[name]
        scheme = "https" if https else "http"
        url = f"{scheme}://{args.host}:{port}/"
        out = run_wrk(url, args.duration)
        if out is None:
            rps = "SKIP"
        elif out.startswith("ERROR"):
            rps = "ERR"
            print(f"{name:<12} {port:>6} {rps:>12}  {url}  ({out.strip()})")
            continue
        else:
            rps = parse_rps(out)
        print(f"{name:<12} {port:>6} {rps:>12}  {url}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
