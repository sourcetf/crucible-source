#!/usr/bin/env python3
"""Lua app-engine self-test: state isolation, resource limits, timeout, errors.

Runs against a live Crucible instance whose Lua app docroot contains
``tests/`` (this directory). Default target is the sample route:

    python3 www-apps/lua/selftest.py --base http://127.0.0.1:19095/lua
    python3 www-apps/lua/selftest.py --base http://127.0.0.1:27010/lua \
        --alt http://127.0.0.1:27010/lua2 --pid 1234 --stress 10000

What it proves (each item prints PASS/FAIL, exit code 1 on any FAIL):
  * per-request header/env isolation under 32-way concurrency (0 bleed);
  * _G / package.loaded pollution invisible to the next request;
  * 1MiB POST body round-trips byte-for-byte (ngx.req.get_body_data);
  * uncaught error after output => 500 fixed text (not 200 + partial);
  * ngx.exit(403) keeps body/status; ngx.exit(404) with no body => 404;
  * os.exit() does not kill the webserver (500 + next request 200);
  * Lua heap cap: 64MiB allocation => clean 500; RSS bounded;
  * timeout hook: pure-Lua loop / coroutine / coroutine.wrap => 500 in ~N s,
    then a healthy request still 200 (engine NOT quarantined);
  * response-body cap: 65MiB of ngx.say => clean 500;
  * raw UTF-8 path routes to the file;
  * keep-alive: 1000 requests on one connection;
  * optional --stress N with --pid: N requests, 0 errors, RSS change <10%.

Requires only the Python 3 standard library.
"""
from __future__ import annotations

import argparse
import concurrent.futures as futures
import http.client
import json
import os
import socket
import sys
import threading
import time
import urllib.parse

RESULTS = []


def record(name: str, ok: bool, detail: str) -> None:
    RESULTS.append({"name": name, "ok": bool(ok), "detail": detail})
    print(f"{'PASS' if ok else 'FAIL'}  {name}: {detail}")


def _split_base(base: str):
    u = urllib.parse.urlsplit(base)
    if u.scheme != "http":
        raise SystemExit(f"only http:// bases are supported (got {base})")
    return u.hostname or "127.0.0.1", u.port or 80, u.path.rstrip("/")


def _one(base: str, path: str = "", method: str = "GET", body: bytes | None = None,
         headers: dict | None = None, timeout: float = 30.0):
    """`base` is the full app URL (origin + prefix); `path` is an optional suffix."""
    u = urllib.parse.urlsplit(base)
    host = u.hostname or "127.0.0.1"
    port = u.port or 80
    target = u.path.rstrip("/") + path
    if u.query:
        target += "?" + u.query
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        hdrs = {"Host": host}
        if headers:
            hdrs.update(headers)
        conn.request(method, target or "/", body=body, headers=hdrs)
        r = conn.getresponse()
        data = r.read()
        return r.status, {k.lower(): v for k, v in r.getheaders()}, data
    finally:
        conn.close()


def _lines(body: bytes) -> dict:
    out = {}
    for ln in body.decode("utf-8", "replace").splitlines():
        if "=" in ln:
            k, v = ln.split("=", 1)
            out[k] = v
    return out


class KeepAlive:
    """One reused connection; reconnects transparently if the server closes."""

    def __init__(self, base: str, timeout: float = 30.0):
        self.host, self.port, self.prefix = _split_base(base)
        self.timeout = timeout
        self.conn = None

    def close(self):
        if self.conn is not None:
            try:
                self.conn.close()
            except Exception:
                pass
            self.conn = None

    def request(self, path: str, headers: dict | None = None, body: bytes | None = None,
                method: str = "GET"):
        for attempt in (0, 1):
            try:
                if self.conn is None:
                    self.conn = http.client.HTTPConnection(
                        self.host, self.port, timeout=self.timeout)
                hdrs = {"Host": self.host}
                if headers:
                    hdrs.update(headers)
                self.conn.request(method, self.prefix + path, body=body, headers=hdrs)
                r = self.conn.getresponse()
                data = r.read()
                return r.status, {k.lower(): v for k, v in r.getheaders()}, data
            except (http.client.HTTPException, OSError):
                self.close()
                if attempt:
                    raise
        raise AssertionError("unreachable")


def rss_kb(pid: int) -> int:
    try:
        with open(f"/proc/{pid}/status", "r", encoding="ascii") as f:
            for ln in f:
                if ln.startswith("VmRSS:"):
                    return int(ln.split()[1])
    except OSError:
        pass
    return 0


class RssSampler(threading.Thread):
    def __init__(self, pid: int):
        super().__init__(daemon=True)
        self.pid = pid
        self.stop = threading.Event()
        self.peak = 0

    def run(self):
        while not self.stop.is_set():
            self.peak = max(self.peak, rss_kb(self.pid))
            self.stop.wait(0.02)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--base", default="http://127.0.0.1:19095/lua")
    ap.add_argument("--alt", default="", help="second Lua app prefix (different .env)")
    ap.add_argument("--pid", type=int, default=0, help="webserver pid for RSS checks")
    ap.add_argument("--stress", type=int, default=0, help="extra N requests with RSS gate")
    ap.add_argument("--concurrency", type=int, default=32)
    ap.add_argument("--timeout-sec", type=float, default=5.0,
                    help="expected CRUCIBLE_LUA_TIMEOUT_MS (default 5000)")
    ap.add_argument("--skip-timeout", action="store_true")
    ap.add_argument("--json", action="store_true", help="dump machine-readable results")
    args = ap.parse_args()

    # 0. liveness
    try:
        st, _, body = _one(args.base + "/")
        record("hello", st == 200 and b"hello from lua" in body,
               f"status={st} body={body[:48]!r}")
    except Exception as e:  # noqa: BLE001
        record("hello", False, f"exception {e!r}")
        print(json.dumps(RESULTS, indent=2))
        return 1

    # 1. per-request header isolation: 200 concurrent unique tokens
    n = 200
    tokens = [f"tok-{i:04d}-{os.getpid()}" for i in range(n)]

    def env_req(tok):
        st, _, b = _one(args.base + "/tests/env.lua", headers={"x-crucible-env-probe": tok})
        got = _lines(b).get("HDR", "")
        # any foreign token in the body is also a bleed
        foreign = any(t in b.decode("utf-8", "replace") for t in tokens if t != tok)
        return st, got == tok and not foreign, got

    bad = []
    with futures.ThreadPoolExecutor(max_workers=args.concurrency) as ex:
        for tok, (st, ok, got) in zip(tokens, ex.map(env_req, tokens)):
            if st != 200 or not ok:
                bad.append((tok, st, got))
    record("header-isolation", not bad, f"n={n} bad={len(bad)} sample={bad[:3]}")

    if args.alt:
        # concurrent cross-app .env reads: each app must only see its own values
        def alt_req(i):
            base = args.base if i % 2 == 0 else args.alt
            st, _, b = _one(base + "/tests/env.lua",
                            headers={"x-crucible-env-probe": f"alt-{i}"})
            d = _lines(b)
            return base, st, d

        # The invariant is "never see the OTHER app's request .env value", not
        # "nil": the startup base environment may legitimately define the same
        # key (and then both apps see the base value).
        cross_bad = []
        with futures.ThreadPoolExecutor(max_workers=args.concurrency) as ex:
            for base, st, d in ex.map(alt_req, range(64)):
                side = "main" if base == args.base else "alt"
                a, bb = d.get("SECRET_A"), d.get("SECRET_B")
                wm = d.get("WINDOWMARK")
                if side == "main" and (a != "lua-alpha" or bb == "lua-beta"
                                       or wm != "from-lua-main"):
                    cross_bad.append((side, st, wm, a, bb))
                if side == "alt" and (bb != "lua-beta" or a == "lua-alpha"
                                      or wm != "from-lua-alt"):
                    cross_bad.append((side, st, wm, a, bb))
        record("cross-app-env", not cross_bad, f"bad={len(cross_bad)} {cross_bad[:3]}")

    # 2. _G/package.loaded pollution
    st, _, b = _one(args.base + "/tests/globals.lua?op=set&token=LEAKTOKEN1")
    set_ok = st == 200 and b"SET=" in b
    st2, _, b2 = _one(args.base + "/tests/globals.lua?op=get")
    d2 = _lines(b2)
    clean = d2.get("LEAK") == "nil" and d2.get("LOADED") == "nil"
    record("global-isolation", set_ok and st2 == 200 and clean,
           f"set={st}/{b[:20]!r} get={st2} LEAK={d2.get('LEAK')} LOADED={d2.get('LOADED')}")

    # 2b. require() resolves app-local modules (package.path starts at docroot)
    st, _, b = _one(args.base + "/tests/require_test.lua")
    record("require-docroot", st == 200 and b"MODULE=probe-module" in b,
           f"status={st} body={b[:64]!r}")

    # 3. 1MiB POST round-trip
    payload = bytes((i * 31 + 7) & 0xFF for i in range(1024 * 1024))
    st, _, b = _one(args.base + "/tests/body.lua", method="POST", body=payload,
                    headers={"Content-Type": "application/octet-stream"}, timeout=60)
    head, _, echoed = b.partition(b"\n")
    ok = st == 200 and head == b"len=1048576" and echoed == payload
    record("post-1mib", ok, f"status={st} head={head!r} echoed={len(echoed)} exact={echoed == payload}")

    # 4. error after output => 500 fixed text
    st, _, b = _one(args.base + "/tests/error.lua")
    record("error-after-output", st == 500 and b == b"lua: application error\n",
           f"status={st} body={b[:48]!r}")

    # 5. ngx.exit semantics
    st, _, b = _one(args.base + "/tests/exit.lua")
    record("ngx-exit-with-body", st == 403 and b == b"denied-body\n",
           f"status={st} body={b!r}")
    st, _, b = _one(args.base + "/tests/exit_empty.lua")
    record("ngx-exit-no-body", st == 404 and b == b"", f"status={st} len={len(b)}")

    # 6. os.exit must not kill the process
    try:
        st, _, b = _one(args.base + "/tests/os_exit.lua", timeout=10)
        os_exit_ok = st == 500 and b == b"lua: application error\n"
        detail = f"status={st} body={b[:40]!r}"
    except Exception as e:  # noqa: BLE001
        os_exit_ok, detail = False, f"exception {e!r}"
    st, _, b = _one(args.base + "/", timeout=10)
    alive = st == 200 and b"hello from lua" in b
    record("os-exit-contained", os_exit_ok and alive, f"{detail} alive_after={alive}")

    # 7. Lua heap cap: 4MiB is under the 32MiB default, 64MiB is over it.
    st, _, b = _one(args.base + "/tests/mem.lua?mb=4", timeout=30)
    record("lua-heap-under-cap", st == 200 and b"allocated=4194304" in b,
           f"status={st} body={b[:40]!r}")
    st, _, b = _one(args.base + "/tests/mem.lua?mb=64", timeout=30)
    record("lua-heap-cap", st == 500 and b == b"lua: application error\n",
           f"status={st} body={b[:40]!r}")

    # 8. response-body cap (65MiB > 64MiB)
    st, _, b = _one(args.base + "/tests/bigsay.lua?mb=65", timeout=60)
    record("response-body-cap", st == 500 and b == b"lua: application error\n",
           f"status={st} body={b[:40]!r}")

    # 9. syntax error / missing script
    st, _, b = _one(args.base + "/tests/syntax_error.lua")
    record("syntax-error", st == 500 and b == b"lua: application error\n",
           f"status={st} body={b[:40]!r}")
    st, _, b = _one(args.base + "/tests/does_not_exist.lua")
    record("missing-script", st == 404 and b == b"lua: script not found\n",
           f"status={st} body={b!r}")

    # 10. raw UTF-8 path (percent-encoded paths are routing's job; this checks
    #     the engine can open a non-ASCII script path when it is passed through)
    host, port, prefix = _split_base(args.base)
    raw = (f"GET {prefix}/tests/测试.lua HTTP/1.1\r\nHost: {host}\r\n"
           "Connection: close\r\n\r\n").encode("utf-8")
    try:
        s = socket.create_connection((host, port), timeout=10)
        s.sendall(raw)
        data = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
        s.close()
        status_line = data.split(b"\r\n", 1)[0]
        ok = b" 200 " in status_line and b"unicode-path-ok" in data
        record("unicode-path", ok, f"{status_line!r} tail={data[-32:]!r}")
    except Exception as e:  # noqa: BLE001
        record("unicode-path", False, f"exception {e!r}")

    # 10a. process-global locale cannot be changed by a request
    st, _, b = _one(args.base + "/tests/locale.lua")
    record("locale-global", st == 200 and b"SETLOCALE_OK=false" in b
           and b"LOCALE_SAME=true" in b, f"status={st} body={b[:80]!r}")

    # 10b. normal coroutine semantics preserved by the guards
    st, _, b = _one(args.base + "/tests/coroutine_ok.lua")
    record("coroutine-normal", st == 200 and b"create=true,2,true,15" in b
           and b"wrap=8,21" in b, f"status={st} body={b[:96]!r}")

    # 11. timeout hook (pure Lua / coroutine / coroutine.wrap), then healthy
    if not args.skip_timeout:
        expect = args.timeout_sec
        for name, path in (("timeout-loop", "/tests/loop.lua"),
                           ("timeout-coroutine", "/tests/coroutine.lua"),
                           ("timeout-coroutine-wrap", "/tests/coroutine_wrap.lua")):
            try:
                t0 = time.monotonic()
                st, _, b = _one(args.base + path, timeout=expect + 15)
                dt = time.monotonic() - t0
                ok = (st == 500 and dt >= expect * 0.8 and dt <= expect + 6
                      and b == b"lua: application error\n")
                record(name, ok, f"status={st} elapsed={dt:.2f}s body={b[:32]!r}")
            except Exception as e:  # noqa: BLE001
                record(name, False, f"exception {e!r}")
        t0 = time.monotonic()
        st, _, b = _one(args.base + "/", timeout=5)
        dt = time.monotonic() - t0
        record("healthy-after-timeout", st == 200 and dt < 1.0,
               f"status={st} elapsed={dt:.3f}s")

    # 12. 1000 keep-alive requests
    ka = KeepAlive(args.base)
    ka_bad = 0
    try:
        for i in range(1000):
            st, _, b = ka.request("/tests/env.lua",
                                  headers={"x-crucible-env-probe": f"ka-{i}"})
            if st != 200 or _lines(b).get("HDR") != f"ka-{i}":
                ka_bad += 1
    except Exception as e:  # noqa: BLE001
        ka_bad += 1
        print(f"keep-alive exception: {e!r}")
    finally:
        ka.close()
    record("keep-alive-1000", ka_bad == 0, f"bad={ka_bad}")

    # 13. optional stress + RSS gate
    if args.stress > 0:
        sampler = None
        before = rss_kb(args.pid) if args.pid else 0
        if args.pid:
            sampler = RssSampler(args.pid)
            sampler.start()
        t0 = time.monotonic()
        stress_bad = 0

        def one(i):
            try:
                st, _, b = _one(args.base + "/tests/env.lua",
                                headers={"x-crucible-env-probe": f"st-{i}"})
                return st == 200 and _lines(b).get("HDR") == f"st-{i}"
            except Exception:  # noqa: BLE001
                return False
        with futures.ThreadPoolExecutor(max_workers=args.concurrency) as ex:
            for ok in ex.map(one, range(args.stress)):
                if not ok:
                    stress_bad += 1
        dt = time.monotonic() - t0
        if sampler is not None:
            sampler.stop.set()
            sampler.join()
            after = rss_kb(args.pid)
            peak = sampler.peak
            delta = (after - before) / before * 100 if before else 0.0
            ok = stress_bad == 0 and delta < 10.0
            record("stress", ok,
                   f"n={args.stress} bad={stress_bad} {dt:.1f}s rss {before}->{after}kB "
                   f"peak={peak}kB delta={delta:+.1f}%")
        else:
            record("stress", stress_bad == 0,
                   f"n={args.stress} bad={stress_bad} {dt:.1f}s")

    failed = [r for r in RESULTS if not r["ok"]]
    print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} checks passed")
    if args.json:
        print(json.dumps(RESULTS, indent=2))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
