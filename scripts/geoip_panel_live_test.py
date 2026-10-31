#!/usr/bin/env python3
"""Live regression: panel filter family/prefix + panel.toml hot reload (G-17/G-18).

Starts a real webserver on an isolated DB/config, then:
  * `GET /__admin/api/geoip/filter?family=v6&prefix=2001:db8` returns only the
    IPv6 row (and `family=v4` only IPv4 rows; prefix containment works);
  * `POST /__admin/api/geoip/settings {"path_priority_gain":50}` hot-reloads and
    flips the merged `city` selection (wide/heavy row vs long-prefix row);
    gain 0/10/50 produce the expected Wide/Wide/Narrow sequence;
  * the saved `data/geoip/panel.toml` contains the gain, and a corrupt
    panel.toml makes the POST fail cleanly without killing the server.

Usage: python3 scripts/geoip_panel_live_test.py [--server PATH]
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import socket
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from geoip_common import init_schema, upsert_range  # noqa: E402
from geoip_u17_test import ADMIN_HASH, wait_port  # noqa: E402

PORT = 27920
FAILS = 0


def check(name: str, cond: bool, detail="") -> None:
    global FAILS
    if cond:
        print(f"PASS {name}")
    else:
        FAILS += 1
        print(f"FAIL {name} {detail}")


def build_db(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        path.unlink()
    conn = sqlite3.connect(path)
    try:
        init_schema(conn)
        # gain-sensitive pair for the panel lookup: same IP covered by a heavy
        # wide /8 and a zero-weight /24 (city differs).
        upsert_range(
            conn, "1.0.0.0", "1.255.255.255",
            {"city": "Wide", "isp": "WideISP"}, weight=700, source="t", commit_unix=10,
        )
        upsert_range(
            conn, "1.2.4.0", "1.2.4.255",
            {"city": "Narrow", "isp": "NarrowISP"}, weight=0, source="t", commit_unix=10,
        )
        upsert_range(
            conn, "8.8.8.0", "8.8.8.255",
            {"country": "US", "city": "MV"}, weight=80, source="t", commit_unix=10,
        )
        # v6 goes into the ipv6 range table (upsert_range family split).
        upsert_range(
            conn, "2001:db8::", "2001:db8::ffff",
            {"country": "JP", "city": "DocV6"}, weight=50, source="t", commit_unix=10,
        )
        # A row directly in the ipv4 range table (dual-schema coverage).
        conn.execute(
            """INSERT INTO ipv4(start,end,bits,weight,country,city,prefix,start_i,end_i)
               VALUES('9.9.9.0','9.9.9.255',24,60,'AU','Sydney','9.9.9.0/24',
                      151587840,151587327)""",
        )
        conn.commit()
    finally:
        conn.close()


def write_cfg(work: Path, db: Path) -> Path:
    www = work / "www"
    www.mkdir(parents=True, exist_ok=True)
    (www / "index.html").write_text("panel-ok\n", encoding="utf-8")
    cfg = f"""
[access_log]
enable = false

[admin]
realm = "panel"
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
server_name = "panel.test"
autoindex = true
http_versions = ["h1"]
"""
    p = work / "config-panel.toml"
    p.write_text(cfg, encoding="utf-8")
    return p


def req(method: str, path: str, body: bytes | None = None) -> dict:
    token = base64.b64encode(b"admin:admin").decode()
    r = urllib.request.Request(
        f"http://127.0.0.1:{PORT}{path}",
        data=body,
        method=method,
        headers={"Authorization": f"Basic {token}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(r, timeout=5) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {"error": raw.decode("utf-8", "replace"), "http_status": e.code}


def lookup(ip: str) -> dict:
    return req("GET", f"/__admin/api/geoip/lookup?ip={ip}")


def filter_rows(**kw) -> list[dict]:
    q = urllib.parse.urlencode({k: v for k, v in kw.items() if v is not None})
    return req("GET", f"/__admin/api/geoip/filter?{q}")["rows"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--server",
        default=str(Path.home() / "scratch-geoipdata/target/release/webserver"),
    )
    ap.add_argument("--work", default=str(Path.home() / "scratch-geoipdata/panel-live"))
    args = ap.parse_args()
    work = Path(args.work)
    work.mkdir(parents=True, exist_ok=True)
    db = work / "geoip.sqlite"
    build_db(db)
    cfg = write_cfg(work, db)
    # 上一次失败可能留下非法 panel.toml（config 加载会直接失败），先清掉。
    stale_panel = work / "panel.toml"
    if stale_panel.exists():
        stale_panel.unlink()
    env = dict(os.environ)
    env["CRUCIBLE_GEOIP_PANEL_DB"] = str(work / "panel.sqlite")
    env["CRUCIBLE_GEOIP_PANEL"] = str(work / "panel.toml")
    env["CRUCIBLE_DNS_STATE_ROOT"] = str(work / "state-dns")
    log = (work / "server.log").open("wb")
    srv = subprocess.Popen(
        [args.server, "--config", str(cfg)], cwd=str(work), env=env,
        stdout=log, stderr=subprocess.STDOUT,
    )
    try:
        wait_port("127.0.0.1", PORT)
        # ---- filter family/prefix ----
        v6 = filter_rows(family="v6", prefix="2001:db8")
        check("filter_v6_prefix", len(v6) == 1 and ":" in v6[0]["prefix"], v6)
        v4 = filter_rows(family="IPv4")
        check(
            "filter_v4_no_v6",
            all(":" not in r["prefix"] for r in v4),
            [r["prefix"] for r in v4],
        )
        check(
            "filter_v4_has_range_table_row",
            any(r["prefix"] == "9.9.9.0/24" for r in v4),
            [r["prefix"] for r in v4],
        )
        pref = filter_rows(prefix="1.2.4")
        check(
            "filter_prefix_contains",
            len(pref) == 1 and pref[0]["prefix"] == "1.2.4.0/24",
            pref,
        )
        all_rows = filter_rows()
        check(
            "filter_unknown_family_no_filter",
            len(filter_rows(family="v5")) == len(all_rows),
            f"v5={len(filter_rows(family='v5'))} all={len(all_rows)}",
        )

        # ---- panel.toml hot reload: gain 0/10/50 ----
        base = lookup("1.2.4.8")
        check("lookup_gain_default_wide", base.get("city") == "Wide", base)
        r = req("POST", "/__admin/api/geoip/settings", b'{"path_priority_gain":50}')
        check("settings_post_50_ok", r.get("ok") is True, r)
        m50 = lookup("1.2.4.8")
        check("lookup_gain50_narrow", m50.get("city") == "Narrow", m50)
        r = req("POST", "/__admin/api/geoip/settings", b'{"path_priority_gain":0}')
        check("settings_post_0_ok", r.get("ok") is True, r)
        m0 = lookup("1.2.4.8")
        check("lookup_gain0_wide", m0.get("city") == "Wide", m0)
        r = req("POST", "/__admin/api/geoip/settings", b'{"path_priority_gain":10}')
        check("settings_post_10_ok", r.get("ok") is True, r)
        m10 = lookup("1.2.4.8")
        check("lookup_gain10_wide", m10.get("city") == "Wide", m10)
        settings = req("GET", "/__admin/api/geoip/settings")
        check("settings_get_gain10", settings.get("path_priority_gain") == 10, settings)
        panel_toml = (work / "panel.toml").read_text(encoding="utf-8")
        check("panel_toml_saved_gain", "path_priority_gain = 10" in panel_toml, panel_toml)

        # ---- corrupt panel.toml is rejected, server survives ----
        (work / "panel.toml").write_text("path_priority_gain = [\n", encoding="utf-8")
        bad = req("POST", "/__admin/api/geoip/settings", b'{"path_priority_gain":20}')
        check("corrupt_panel_rejected", "error" in bad, bad)
        alive = lookup("8.8.8.8")
        check("server_alive_after_corrupt_panel", alive.get("country") == "US", alive)
        # restore a valid panel file by POSTing after deleting the broken one
        (work / "panel.toml").unlink()
        ok = req("POST", "/__admin/api/geoip/settings", b'{"path_priority_gain":10}')
        check("panel_restored", ok.get("ok") is True, ok)
    finally:
        srv.terminate()
        try:
            srv.wait(timeout=10)
        except subprocess.TimeoutExpired:
            srv.kill()
        log.close()
    print(f"geoip_panel_live_test: {'OK' if FAILS == 0 else f'{FAILS} FAILURES'}")
    return 0 if FAILS == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
