#!/usr/bin/env python3
"""Application engine overhead vs static baseline (wrk wrappers).

同一 listener、同一 wrk 参数（-t2 -c8 -d3s，keep-alive，TLS off）下比较
static / rust / c / go / 解释器引擎的 RPS 与延迟（§7.10 / §14 / §19 / §22.4.4）。

输出列：
  engine  rps  latency  p50  p99  non2xx  lat/static  rps/static  url

`lat/static` 是规格的延迟门禁口径（rust < 1.1），`rps/static` 供参考。
static 自身在 `/`（或 `--static-path`）；若服务端根目录没有静态首页，可用
`--static-path /index.html` 指到实际文件。
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import urllib.request
from typing import Optional

_UNIT_MS = {"us": 0.001, "ms": 1.0, "s": 1000.0}


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


def _num(out: str, pat: str) -> Optional[float]:
    m = re.search(pat, out)
    return float(m.group(1)) if m else None


def _ms(out: str, pat: str) -> Optional[float]:
    m = re.search(pat, out)
    if not m:
        return None
    return float(m.group(1)) * _UNIT_MS[m.group(2)]


def parse(out: str) -> dict:
    return {
        "rps": _num(out, r"Requests/sec:\s+([\d.]+)"),
        "lat_ms": _ms(out, r"Latency\s+([\d.]+)(us|ms|s)"),
        "p50_ms": _ms(out, r"50%\s+([\d.]+)(us|ms|s)"),
        "p99_ms": _ms(out, r"99%\s+([\d.]+)(us|ms|s)"),
        "non2xx": int(_num(out, r"Non-2xx or 3xx responses:\s+([\d]+)") or 0),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="App engine overhead vs static (wrk)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=19095)
    parser.add_argument("--duration", default="3s")
    parser.add_argument("--static-path", default="/", help="static baseline URL path")
    parser.add_argument(
        "--engines",
        default="static,rust,c,go,php,lua,jsp,asp,aspnet,tsx,python,ruby,perl",
        help="comma-separated labels",
    )
    parser.add_argument("--json", default="", help="write machine-readable results here")
    parser.add_argument(
        "--warmup",
        type=int,
        default=1,
        help=(
            "发多少次预热请求再计时（默认 1）。首次请求要 dlopen 引擎，Go c-shared 的 "
            "runtime 初始化实测 ~0.6s；不预热会把这段冷启动算进 wrk，稳态开销被淹没。"
        ),
    )
    args = parser.parse_args()

    base = f"http://{args.host}:{args.port}"
    paths = {
        "static": args.static_path,
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

    rows = {}
    order = [x.strip() for x in args.engines.split(",") if x.strip()]
    for name in order:
        path = paths.get(name, f"/{name}")
        url = base + path
        for _ in range(max(0, args.warmup)):
            try:
                with urllib.request.urlopen(url, timeout=30) as resp:
                    resp.read()
            except Exception as e:  # noqa: BLE001 - 预热失败让下面的 wrk 如实反映
                print(f"warmup failed for {url}: {e}", file=sys.stderr)
        out = run_wrk(url, duration=args.duration)
        if out is None:
            rows[name] = {"url": url, "error": "wrk failed"}
        else:
            r = parse(out)
            r["url"] = url
            rows[name] = r

    base_lat = rows.get("static", {}).get("lat_ms")
    base_rps = rows.get("static", {}).get("rps")

    def fmt(v, spec):
        return "?" if v is None else format(v, spec)

    print(
        f"{'engine':<10} {'rps':>10} {'latency':>10} {'p50':>9} {'p99':>9} "
        f"{'non2xx':>7} {'lat/static':>10} {'rps/static':>10}  url"
    )
    print("-" * 110)
    for name in order:
        r = rows[name]
        if "error" in r:
            print(f"{name:<10} SKIP  ({r['error']})")
            continue
        lat_ratio = (
            f"{r['lat_ms'] / base_lat:.3f}" if r["lat_ms"] is not None and base_lat else "?"
        )
        rps_ratio = f"{r['rps'] / base_rps:.3f}" if r["rps"] is not None and base_rps else "?"
        print(
            f"{name:<10} {fmt(r['rps'], '.0f'):>10} {fmt(r['lat_ms'], '.3f') + 'ms':>10} "
            f"{fmt(r['p50_ms'], '.3f'):>9} {fmt(r['p99_ms'], '.3f'):>9} "
            f"{r['non2xx']:>7} {lat_ratio:>10} {rps_ratio:>10}  {r['url']}"
        )
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(rows, f, indent=2)
        print(f"wrote {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
