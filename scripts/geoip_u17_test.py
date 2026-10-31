#!/usr/bin/env python3
"""U-17: IPv4-mapped country hit + country-cache pressure / TTL / memory / hot IP.

Builds an isolated GeoIP DB + config in a scratch dir, starts the real
`webserver`, and drives real TCP requests (never X-Forwarded-For):

  * listener `127.0.0.1:27900` — 5000 distinct source IPs from 127.0.0.0/8
    (each connection binds a unique 127.x.y.z), page rule `country = CN` blocks;
  * listener `[::]:27901`     — connect over IPv4 so the peer is
    `::ffff:127.x.y.z` (single v6 socket keeps Linux v6only=0), page rule must
    still resolve CN via `unmap_v4_mapped`;
  * hot IP: 2000 requests from one source IP (cache hit path);
  * TTL: in-place DB update to JP must stay cached until 60s TTL expires;
  * atomic rename: replace the DB file with a different-country DB; report
    whether the cached connection sees the new inode after TTL (known issue if
    still stale — page_rules.rs is outside this agent's scope);
  * RSS sampled before / after 5000 / after 20000 unique IPs (bounded cache).

Usage:
  python3 scripts/geoip_u17_test.py [--server PATH] [--work DIR]
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from geoip_common import init_panel_schema, init_schema, upsert_range  # noqa: E402

ADMIN_HASH = (
    "$argon2id$v=19$m=19456,t=2,p=1$E/RLobwgix2BWMRMT++urA$"
    "yEympjJtiDh0ezwSQsnkbsfYAoSzeDAHYw3EsUMBsj4"
)
DEFAULT_WORK = Path.home() / "scratch-geoipdata" / "u17"
PORT_V4 = 27900
PORT_V6 = 27901


def build_db(path: Path, country_127: str = "CN") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        path.unlink()
    conn = sqlite3.connect(path)
    try:
        init_schema(conn)
        init_panel_schema(conn)
        upsert_range(
            conn, "127.0.0.0", "127.255.255.255",
            {"country": country_127, "city": "Loopback", "isp": "U17"},
            weight=100, source="u17", commit_unix=1000,
        )
        upsert_range(
            conn, "1.2.4.0", "1.2.4.255",
            {"country": country_127, "city": "Docs"},
            weight=100, source="u17", commit_unix=1000,
        )
        upsert_range(
            conn, "2001:db8::", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff",
            {"country": "JP", "city": "DocV6"},
            weight=100, source="u17", commit_unix=1000,
        )
        conn.commit()
    finally:
        conn.close()


def write_config(work: Path, db: Path) -> Path:
    www_v4 = work / "www-v4"
    www_v6 = work / "www-v6"
    for d in (www_v4, www_v6):
        d.mkdir(parents=True, exist_ok=True)
        (d / "index.html").write_text("u17-ok\n", encoding="utf-8")
    cfg = f"""
[access_log]
enable = false

[admin]
realm = "u17"
path = "/__admin"
[[admin.users]]
username = "admin"
password_hash = "{ADMIN_HASH}"

[geoip]
enabled = true
db_path = "{db}"

[ip_access]
allow = []
deny = []

[[listeners]]
address = "127.0.0.1"
port = {PORT_V4}
root = "{www_v4}"
server_name = "u17.test"
autoindex = true
http_versions = ["h1"]

[[listeners.page_rules]]
match_url = "/*"
action = "block"
country = "CN"
priority = 100

[[listeners]]
address = "::"
port = {PORT_V6}
root = "{www_v6}"
server_name = "u17mapped.test"
autoindex = true
http_versions = ["h1"]

[[listeners.page_rules]]
match_url = "/*"
action = "block"
country = "CN"
priority = 100
"""
    path = work / "config-u17.toml"
    path.write_text(cfg, encoding="utf-8")
    return path


def wait_port(host: str, port: int, deadline: float = 15.0) -> None:
    end = time.time() + deadline
    last = None
    while time.time() < end:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return
        except OSError as e:
            last = e
            time.sleep(0.1)
    raise RuntimeError(f"server did not listen on {host}:{port}: {last}")


def http_get(port: int, host_header: str, source_ip: str | None = None,
             path: str = "/", host: str = "127.0.0.1", timeout: float = 5.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        if source_ip:
            s.bind((source_ip, 0))
        s.connect((host, port))
        req = (
            f"GET {path} HTTP/1.1\r\nHost: {host_header}\r\n"
            "Connection: close\r\n\r\n"
        ).encode()
        s.sendall(req)
        data = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
            if len(data) > 1024 * 1024:
                break
        line = data.split(b"\r\n", 1)[0]
        code = int(line.split()[1]) if len(line.split()) >= 2 else 0
        return code, data
    finally:
        s.close()


def http_mapped(port: int, path: str = "/") -> tuple[int, bytes]:
    """Connect from IPv4 client to a [::] listener → peer is ::ffff:a.b.c.d."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5.0)
    try:
        s.connect(("127.0.0.1", port))
        s.sendall(
            f"GET {path} HTTP/1.1\r\nHost: u17mapped.test\r\n"
            "Connection: close\r\n\r\n".encode()
        )
        data = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
        code = int(data.split(b"\r\n", 1)[0].split()[1])
        return code, data
    finally:
        s.close()


def rss_kb(pid: int) -> int:
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    except OSError:
        pass
    return 0


def pct(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    v = sorted(values)
    return v[min(len(v) - 1, int(len(v) * p))]


def tcp_source_ips(n: int) -> list[str]:
    out = []
    a = 1
    while len(out) < n:
        b = 0
        while len(out) < n and b < 256:
            c = 0
            while len(out) < n and c < 256:
                out.append(f"127.{a}.{b}.{max(1, c)}")
                c += 1
            b += 1
        a += 1
    return out


def db_set_country(db: Path, country: str) -> None:
    conn = sqlite3.connect(db)
    try:
        conn.execute("UPDATE geoip SET country=? WHERE ip_start='127.0.0.0'", (country,))
        conn.execute("UPDATE geoip SET country=? WHERE ip_start='1.2.4.0'", (country,))
        conn.commit()
    finally:
        conn.close()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--server",
        default=str(Path.home() / "scratch-geoipdata/target/release/webserver"),
    )
    ap.add_argument("--work", default=str(DEFAULT_WORK))
    ap.add_argument("--keep", action="store_true", help="keep server/process files")
    ap.add_argument("--skip-tests", action="store_true", help="only build DB/config")
    args = ap.parse_args()
    work = Path(args.work)
    work.mkdir(parents=True, exist_ok=True)
    run = work / "run"
    run.mkdir(exist_ok=True)
    db = work / "geoip.sqlite"
    build_db(db, "CN")
    cfg = write_config(work, db)
    if args.skip_tests:
        print(f"built {db} and {cfg}")
        return 0

    env = dict(os.environ)
    env["CRUCIBLE_GEOIP_PANEL_DB"] = str(work / "panel.sqlite")
    env["CRUCIBLE_GEOIP_PANEL"] = str(work / "panel.toml")
    env["CRUCIBLE_DNS_STATE_ROOT"] = str(work / "state-dns")
    log = (work / "server.log").open("wb")
    srv = subprocess.Popen(
        [args.server, "--config", str(cfg)],
        cwd=str(run),
        env=env,
        stdout=log,
        stderr=subprocess.STDOUT,
    )
    results: dict = {"server_pid": srv.pid, "ports": [PORT_V4, PORT_V6]}
    try:
        wait_port("127.0.0.1", PORT_V4)
        wait_port("127.0.0.1", PORT_V6)
        # ---- mapped peer ----
        code_mapped, body_mapped = http_mapped(PORT_V6)
        code_v4, _ = http_get(PORT_V4, "u17.test")
        results["mapped_peer_status"] = code_mapped
        results["v4_peer_status"] = code_v4
        print(f"mapped ::ffff:127.0.0.1 -> {code_mapped} (want 403)")
        print(f"plain 127.0.0.1        -> {code_v4} (want 403)")

        # ---- 5000 distinct IPs (cold-ish) ----
        ips = tcp_source_ips(5000)
        rss0 = rss_kb(srv.pid)
        lat1: list[float] = []
        bad1 = 0
        t0 = time.time()
        for ip in ips:
            a = time.perf_counter()
            code, _ = http_get(PORT_V4, "u17.test", source_ip=ip)
            lat1.append((time.perf_counter() - a) * 1000)
            if code != 403:
                bad1 += 1
        d1 = time.time() - t0
        rss1 = rss_kb(srv.pid)
        # ---- repeat same 5000 (cache pressure + hit rate proxy) ----
        lat2: list[float] = []
        bad2 = 0
        t0 = time.time()
        for ip in ips:
            a = time.perf_counter()
            code, _ = http_get(PORT_V4, "u17.test", source_ip=ip)
            lat2.append((time.perf_counter() - a) * 1000)
            if code != 403:
                bad2 += 1
        d2 = time.time() - t0
        rss2 = rss_kb(srv.pid)
        results.update(
            {
                "pass1": {
                    "n": len(ips), "bad": bad1, "elapsed_s": round(d1, 3),
                    "p50_ms": round(pct(lat1, 0.50), 3),
                    "p95_ms": round(pct(lat1, 0.95), 3),
                    "p99_ms": round(pct(lat1, 0.99), 3),
                },
                "pass2": {
                    "n": len(ips), "bad": bad2, "elapsed_s": round(d2, 3),
                    "p50_ms": round(pct(lat2, 0.50), 3),
                    "p95_ms": round(pct(lat2, 0.95), 3),
                    "p99_ms": round(pct(lat2, 0.99), 3),
                },
                "rss_kb": {"before": rss0, "after_5000": rss1, "after_10000": rss2},
            }
        )
        print(
            f"5000 unique: pass1 {d1:.2f}s p50={pct(lat1,0.5):.3f}ms "
            f"p95={pct(lat1,0.95):.3f}ms bad={bad1}; "
            f"pass2 {d2:.2f}s p50={pct(lat2,0.5):.3f}ms bad={bad2}"
        )

        # ---- 20000 unique (cap should keep RSS bounded) ----
        ips20 = tcp_source_ips(20000)
        bad3 = 0
        for ip in ips20:
            code, _ = http_get(PORT_V4, "u17.test", source_ip=ip)
            if code != 403:
                bad3 += 1
        rss3 = rss_kb(srv.pid)
        results["rss_kb"]["after_20000"] = rss3
        results["pass20000_bad"] = bad3
        print(f"20000 unique: bad={bad3} rss={rss3}KB")

        # ---- hot IP ----
        hot_lat: list[float] = []
        for _ in range(2000):
            a = time.perf_counter()
            code, _ = http_get(PORT_V4, "u17.test", source_ip="127.200.0.1")
            hot_lat.append((time.perf_counter() - a) * 1000)
            if code != 403:
                bad3 += 1
        results["hot_ip"] = {
            "n": len(hot_lat),
            "p50_ms": round(pct(hot_lat, 0.5), 3),
            "p95_ms": round(pct(hot_lat, 0.95), 3),
            "p99_ms": round(pct(hot_lat, 0.99), 3),
        }
        print(
            f"hot IP x2000: p50={pct(hot_lat,0.5):.3f}ms "
            f"p95={pct(hot_lat,0.95):.3f}ms"
        )

        # ---- TTL: in-place DB update ----
        ttl_ip = "127.9.9.9"
        c_before, _ = http_get(PORT_V4, "u17.test", source_ip=ttl_ip)
        db_set_country(db, "JP")
        c_now, _ = http_get(PORT_V4, "u17.test", source_ip=ttl_ip)
        print(f"ttl: before={c_before} immediately_after_db_update={c_now} (want 403,403)")
        time.sleep(61.5)
        c_after, _ = http_get(PORT_V4, "u17.test", source_ip=ttl_ip)
        results["ttl"] = {"before": c_before, "immediate": c_now, "after_61s": c_after}
        print(f"ttl: after 61.5s={c_after} (want 200, cache expired)")
        db_set_country(db, "CN")
        time.sleep(61.5)  # let the TTL pick CN back up before the rename test

        # ---- atomic rename: cached connection vs new inode ----
        rename_ip = "127.8.8.8"
        c_old, _ = http_get(PORT_V4, "u17.test", source_ip=rename_ip)
        newdb = work / "geoip-jp.sqlite"
        build_db(newdb, "JP")
        os.replace(newdb, db)
        c_new_now, _ = http_get(PORT_V4, "u17.test", source_ip=rename_ip)
        time.sleep(61.5)
        c_new_after, _ = http_get(PORT_V4, "u17.test", source_ip=rename_ip)
        results["atomic_rename"] = {
            "before": c_old,
            "immediate_after_rename": c_new_now,
            "after_61s": c_new_after,
        }
        print(
            f"atomic rename: before={c_old} immediate={c_new_now} "
            f"after61s={c_new_after} (403 after61s = stale cached inode; "
            "page_rules.rs out of scope)"
        )
        # restore CN in place for any later checks
        db_set_country(db, "CN")
        results["ok"] = True
    finally:
        if not args.keep:
            srv.terminate()
            try:
                srv.wait(timeout=10)
            except subprocess.TimeoutExpired:
                srv.kill()
        log.close()
        out = work / "u17-results.json"
        out.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"results -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
