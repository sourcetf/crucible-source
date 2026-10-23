#!/usr/bin/env python3
"""Crucible 应用引擎真机矩阵（h1 + h2c / 可选 TLS）。

对 `config.toml` §3.4 的 19 个样例路由逐个请求，校验：
  * HTTP 状态 == 200
  * body 含该样例的特征串（证明响应来自对应引擎，而不是通用错误页）
  * 打印引擎标签头（x-crucible-engine / x-engine，若有）

用法：
  # 明文 h1 + h2c（同一个 listener）
  python3 scripts/verify_app_engines.py --port 9095

  # 只测 h1
  python3 scripts/verify_app_engines.py --port 9095 --no-h2c

  # TLS listener（curl -k；证书自签）
  python3 scripts/verify_app_engines.py --port 8443 --tls

  # 自定义 host / 路径前缀（部署在反向代理后）
  python3 scripts/verify_app_engines.py --host 127.0.0.1 --port 9095 --prefix /apps

依赖：python3 标准库；h2c/TLS 分支需要 PATH 里有 curl（`--http2-prior-knowledge`）。
退出码：0 全部通过；1 有失败（逐条打印失败原因）。
"""
from __future__ import annotations

import argparse
import http.client
import subprocess
import sys

# (引擎名, URL 路径, body 特征串)
ROUTES = [
    ("php", "/php/", "hello from php sample"),
    ("c", "/c/", "hello from c"),
    ("rust", "/rust/", "hello from rust"),
    ("go", "/go/", "hello from go"),
    ("lua", "/lua/", "hello from lua"),
    ("python", "/python/", "hello from python"),
    ("ruby", "/ruby/", "hello from ruby"),
    ("perl", "/perl/", "hello from perl"),
    ("wsgi", "/wsgi/", "hello from wsgi"),
    ("asgi", "/asgi/", "hello from asgi"),
    ("psgi", "/psgi/", "hello from psgi"),
    ("rack", "/rack/", "hello from rack"),
    ("cgi", "/cgi/", "hello from cgi"),
    ("uwsgi", "/uwsgi/", "hello from uwsgi"),
    ("tsx", "/tsx/", "hello from tsx"),
    ("asp", "/asp/", "hello from asp"),
    ("aspnet", "/aspnet/", "hello from aspnet index.aspx"),
    ("jsp", "/jsp/", "hello from jsp"),
    ("do", "/do/", "hello from jsp"),
]


def h1(host: str, port: int, tls: bool, path: str, timeout: float):
    if tls:
        import ssl

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request("GET", path)
        r = conn.getresponse()
        body = r.read().decode("utf-8", "replace")
        hdrs = {k.lower(): v for k, v in r.getheaders()}
        return r.status, body, hdrs
    finally:
        conn.close()


def h2c(host: str, port: int, tls: bool, path: str, timeout: float):
    scheme = "https" if tls else "http"
    cmd = ["curl", "-sS", "--http2" if tls else "--http2-prior-knowledge"]
    if tls:
        cmd.append("-k")
    cmd += ["-D", "-", "-o", "-", "--max-time", str(int(timeout)),
            f"{scheme}://{host}:{port}{path}"]
    p = subprocess.run(cmd, capture_output=True, timeout=timeout + 10)
    raw = p.stdout.decode("utf-8", "replace")
    head, _, body = raw.partition("\r\n\r\n")
    lines = head.split("\r\n") if head else []
    status = 0
    if lines:
        try:
            status = int(lines[0].split()[1])
        except (IndexError, ValueError):
            status = 0
    hdrs = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            hdrs[k.strip().lower()] = v.strip()
    if status == 0 and p.stderr:
        body = f"<curl failed: {p.stderr.decode('utf-8', 'replace')[:200]}>"
    return status, body, hdrs


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9095)
    ap.add_argument("--prefix", default="", help="路由前缀（默认空；用于反代后的部署）")
    ap.add_argument("--tls", action="store_true", help="用 https（curl -k）")
    ap.add_argument("--no-h2c", action="store_true", help="只测 h1")
    ap.add_argument("--timeout", type=float, default=60.0)
    args = ap.parse_args()

    prefix = args.prefix.rstrip("/")
    fails = []
    checks = 0
    print(f"target: {'https' if args.tls else 'http'}://{args.host}:{args.port}{prefix or '/'}")
    for name, path, needle in ROUTES:
        url = prefix + path
        for proto, fn in (("h1", h1), ("h2c", h2c)):
            if proto == "h2c" and args.no_h2c:
                continue
            checks += 1
            try:
                status, body, hdrs = fn(args.host, args.port, args.tls, url, args.timeout)
            except Exception as e:  # noqa: BLE001 - 报告每一条失败
                status, body, hdrs = 0, f"<exception {e!r}>", {}
            eng = hdrs.get("x-crucible-engine") or hdrs.get("x-engine") or ""
            ok = status == 200 and needle in body
            first = body.strip().splitlines()[0][:70] if body.strip() else ""
            print(
                f"{'PASS' if ok else 'FAIL'} {proto:3} {name:7} {status:3} "
                f"eng={eng:18} bytes={len(body):5} {first!r}"
            )
            if not ok:
                fails.append((proto, name, status, body[:200]))

    print(f"\n{checks} checks, {len(fails)} failed")
    for proto, name, status, body in fails:
        print(f"  - {proto} {name}: status={status} body={body!r}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
