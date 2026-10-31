#!/usr/bin/env python3
"""End-to-end: real pipeline DB → Rust runtime load → page-rule country hit,
plus Python offline lookup vs Rust panel lookup field parity.

Uses the DB produced by `geoip_update.sh` (default ~/scratch-geoipdata/...),
copies it, adds a 127.0.0.0/8=CN row so a loopback client can exercise the
page-rule country dimension (the real DB has 127/8 as IANA ZZ, which the merge
intentionally ignores), then starts the real webserver.

Usage:
  python3 scripts/geoip_runtime_e2e_test.py --db PATH --server PATH
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import shutil
import socket
import sqlite3
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from geoip_common import init_panel_schema, init_schema, upsert_range  # noqa: E402
from geoip_u17_test import ADMIN_HASH, http_get, wait_port  # noqa: E402

PORT = 27930
ROOT = Path(__file__).resolve().parent.parent
FAILS = 0


def check(name: str, cond: bool, detail="") -> None:
    global FAILS
    if cond:
        print(f"PASS {name}")
    else:
        FAILS += 1
        print(f"FAIL {name} {detail}")


def prepare_db(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    conn = sqlite3.connect(dst)
    try:
        init_schema(conn)
        init_panel_schema(conn)
        upsert_range(
            conn, "127.0.0.0", "127.255.255.255",
            {"country": "CN", "city": "Loopback", "isp": "RuntimeTest"},
            weight=100, source="runtime-test", commit_unix=2000,
        )
        conn.commit()
    finally:
        conn.close()


def write_cfg(work: Path, db: Path) -> Path:
    www = work / "www"
    www.mkdir(parents=True, exist_ok=True)
    (www / "index.html").write_text("e2e-ok\n", encoding="utf-8")
    cfg = f"""
[access_log]
enable = false

[admin]
realm = "e2e"
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
port = {PORT}
root = "{www}"
server_name = "e2e.test"
autoindex = true
http_versions = ["h1"]

[[listeners.page_rules]]
match_url = "/*"
action = "block"
country = "CN"
priority = 100
"""
    p = work / "config-e2e.toml"
    p.write_text(cfg, encoding="utf-8")
    return p


def panel_lookup(ip: str) -> dict:
    token = base64.b64encode(b"admin:admin").decode()
    url = f"http://127.0.0.1:{PORT}/__admin/api/geoip/lookup?ip={urllib.parse.quote(ip)}"
    req = urllib.request.Request(url, headers={"Authorization": f"Basic {token}"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def python_lookup(db: Path, ip: str, env: dict) -> dict | None:
    p = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "geoip_lookup.py"), ip, "--db", str(db), "--json"],
        capture_output=True, text=True, env=env, timeout=120,
    )
    if p.returncode not in (0, 3):
        return None
    try:
        return json.loads(p.stdout)
    except json.JSONDecodeError:
        return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--db",
        default=str(Path.home() / "scratch-geoipdata/data/geoip/current/geoip.sqlite"),
    )
    ap.add_argument(
        "--server",
        default=str(Path.home() / "scratch-geoipdata/target/release/webserver"),
    )
    ap.add_argument("--work", default=str(Path.home() / "scratch-geoipdata/e2e"))
    args = ap.parse_args()
    src = Path(args.db)
    if not src.is_file():
        print(f"missing DB {src}", file=sys.stderr)
        return 2
    work = Path(args.work)
    work.mkdir(parents=True, exist_ok=True)
    db = work / "geoip.sqlite"
    prepare_db(src, db)
    cfg = write_cfg(work, db)
    env = dict(os.environ)
    env["CRUCIBLE_GEOIP_PANEL_DB"] = str(work / "panel.sqlite")
    env["CRUCIBLE_GEOIP_PANEL"] = str(work / "panel.toml")
    env["CRUCIBLE_DNS_STATE_ROOT"] = str(work / "state-dns")
    env["CRUCIBLE_GEOIP_DATA_ROOT"] = str(src.parent.parent)
    log = (work / "server.log").open("wb")
    srv = subprocess.Popen(
        [args.server, "--config", str(cfg)], cwd=str(work), env=env,
        stdout=log, stderr=subprocess.STDOUT,
    )
    try:
        wait_port("127.0.0.1", PORT)
        # ---- Rust runtime loads the real DB ----
        for ip, want_country in [
            ("8.8.8.8", "US"),
            ("1.48.0.1", "CN"),
        ]:
            r = panel_lookup(ip)
            check(f"rust_lookup_{ip}_ok", r.get("status") == "ok", r)
            check(
                f"rust_lookup_{ip}_country",
                r.get("country") == want_country,
                r.get("country"),
            )
        v6 = panel_lookup("2001:4860:4860::8888")
        check("rust_lookup_v6_ok", v6.get("status") == "ok", v6)
        check("rust_lookup_v6_asn", bool(v6.get("asn")), v6)
        mapped = panel_lookup("::ffff:8.8.8.8")
        check("rust_lookup_mapped_country", mapped.get("country") == "US", mapped)

        # ---- page rule country hit on the real DB (127/8 test row) ----
        code, _ = http_get(PORT, "e2e.test", source_ip="127.0.0.5")
        check("page_rule_country_hit", code == 403, code)

        # ---- Python offline vs Rust panel field parity ----
        compare = [
            "country", "city", "asn", "as_org", "cloud_provider",
            "cloud_region", "bits", "prefixes_merged",
        ]
        for ip in ("8.8.8.8", "1.48.0.1", "2001:4860:4860::8888",
                   "::ffff:8.8.8.8"):
            rust = panel_lookup(ip)
            py = python_lookup(db, ip, env)
            if py is None:
                check(f"parity_{ip}_python_ok", False, "python lookup failed")
                continue
            mism = {
                k: (rust.get(k), py.get(k))
                for k in compare
                if str(rust.get(k) or "") != str(py.get(k) or "")
            }
            # Python's output calls the region column "province".
            if str(rust.get("region") or "") != str(py.get("province") or ""):
                mism["region/province"] = (rust.get("region"), py.get("province"))
            check(f"parity_{ip}", not mism, mism)
    finally:
        srv.terminate()
        try:
            srv.wait(timeout=10)
        except subprocess.TimeoutExpired:
            srv.kill()
        log.close()
    print(f"geoip_runtime_e2e_test: {'OK' if FAILS == 0 else f'{FAILS} FAILURES'}")
    return 0 if FAILS == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
