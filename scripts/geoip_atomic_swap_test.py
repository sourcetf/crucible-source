#!/usr/bin/env python3
"""Atomic GeoIP DB swap + failed-update rollback (U-17 / task 5).

Part A: real server, 16 concurrent panel-lookup threads while `geoip.sqlite` is
        atomically replaced (`os.replace`). Every response must be a complete
        old-or-new country (CN or JP), never an error / empty / mixed result.
Part B: `geoip_update.sh --only merge` on an isolated data root:
        * empty layer dir → staging has 0 rows → integrity gate fails → old DB
          bytes untouched, staging removed (`--only merge` rollback);
        * corrupt layer JSON → same rollback;
        * valid layer → staging swapped atomically, DB content changes once.

Usage: python3 scripts/geoip_atomic_swap_test.py [--server PATH]
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from geoip_u17_test import ADMIN_HASH, build_db, http_get, wait_port  # noqa: E402

PORT = 27910
ROOT = Path(__file__).resolve().parent.parent
FAILS = 0


def check(name: str, cond: bool, detail="") -> None:
    global FAILS
    if cond:
        print(f"PASS {name}")
    else:
        FAILS += 1
        print(f"FAIL {name} {detail}")


def write_cfg(work: Path, db: Path) -> Path:
    www = work / "www"
    www.mkdir(parents=True, exist_ok=True)
    (www / "index.html").write_text("atomic-ok\n", encoding="utf-8")
    cfg = f"""
[access_log]
enable = false

[admin]
realm = "atomic"
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
server_name = "atomic.test"
autoindex = true
http_versions = ["h1"]
"""
    p = work / "config-atomic.toml"
    p.write_text(cfg, encoding="utf-8")
    return p


def admin_lookup(ip: str = "1.2.4.8") -> dict:
    url = f"http://127.0.0.1:{PORT}/__admin/api/geoip/lookup?ip={ip}"
    token = base64.b64encode(b"admin:admin").decode()
    req = urllib.request.Request(url, headers={"Authorization": f"Basic {token}"})
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.loads(r.read())


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_update(root: Path) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["CRUCIBLE_GEOIP_DATA_ROOT"] = str(root)
    env["CRUCIBLE_GEOIP_LOG"] = str(root / "logs" / "update.log")
    return subprocess.run(
        ["bash", str(ROOT / "scripts" / "geoip_update.sh"), "--only", "merge"],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
    )


def part_a(work: Path, server: str) -> None:
    db = work / "geoip.sqlite"
    build_db(db, "CN")
    cfg = write_cfg(work, db)
    env = dict(os.environ)
    env["CRUCIBLE_GEOIP_PANEL_DB"] = str(work / "panel.sqlite")
    env["CRUCIBLE_GEOIP_PANEL"] = str(work / "panel.toml")
    env["CRUCIBLE_DNS_STATE_ROOT"] = str(work / "state-dns")
    log = (work / "server.log").open("wb")
    srv = subprocess.Popen(
        [server, "--config", str(cfg)], cwd=str(work), env=env,
        stdout=log, stderr=subprocess.STDOUT,
    )
    stop = threading.Event()
    results: list[dict] = []
    errors: list[str] = []
    lock = threading.Lock()

    def worker() -> None:
        while not stop.is_set():
            try:
                r = admin_lookup()
                with lock:
                    results.append(r)
            except Exception as e:  # noqa: BLE001
                with lock:
                    errors.append(f"{type(e).__name__}: {e}")
                return

    try:
        wait_port("127.0.0.1", PORT)
        base = admin_lookup()
        check("partA_baseline_cn", base.get("country") == "CN", base)
        threads = [threading.Thread(target=worker, daemon=True) for _ in range(16)]
        for t in threads:
            t.start()
        time.sleep(0.4)
        newdb = work / "geoip-jp.sqlite"
        build_db(newdb, "JP")
        os.replace(newdb, db)  # atomic inode swap under live queries
        time.sleep(2.0)
        stop.set()
        for t in threads:
            t.join(timeout=5)
    finally:
        srv.terminate()
        try:
            srv.wait(timeout=10)
        except subprocess.TimeoutExpired:
            srv.kill()
        log.close()

    countries = [r.get("country") for r in results]
    statuses = [r.get("status") for r in results]
    check("partA_no_transport_errors", not errors, errors[:3])
    check("partA_all_status_ok", all(s == "ok" for s in statuses), set(statuses))
    check(
        "partA_only_old_or_new",
        set(countries) <= {"CN", "JP"},
        {c: countries.count(c) for c in set(countries)},
    )
    check(
        "partA_saw_both_sides",
        "CN" in countries and "JP" in countries,
        {c: countries.count(c) for c in set(countries)},
    )
    print(
        f"partA: {len(results)} lookups, countries="
        f"{ {c: countries.count(c) for c in set(countries)} }"
    )


def part_b(work: Path) -> None:
    root = work / "root"
    if root.exists():
        shutil.rmtree(root)
    (root / "current").mkdir(parents=True)
    (root / "sources").mkdir()
    (root / "logs").mkdir()
    db = root / "current" / "geoip.sqlite"
    build_db(db, "CN")
    old = sha(db)

    # 1) empty layers -> staging 0 rows -> rollback.
    p = run_update(root)
    check("partB_empty_merge_rc", p.returncode == 0, p.returncode)
    check("partB_empty_db_unchanged", sha(db) == old)
    check("partB_empty_no_stage", not (root / "current" / "geoip.sqlite.next").exists())
    logtext = (root / "logs" / "update.log").read_text(encoding="utf-8", errors="replace")
    check("partB_empty_rollback_log", "staging 校验失败" in logtext, logtext[-400:])

    # 2) corrupt layer JSON -> merge succeeds (skips line) but 0 rows -> rollback.
    layer = root / "current" / "01-cloud"
    layer.mkdir(exist_ok=True)
    (layer / "bad.jsonl").write_text("{not json\n", encoding="utf-8")
    p = run_update(root)
    check("partB_bad_json_db_unchanged", sha(db) == old)

    # 3) valid layer -> atomic swap to DE.
    (layer / "bad.jsonl").unlink()
    (layer / "good.jsonl").write_text(
        '{"ip_start":"1.2.4.0","ip_end":"1.2.4.255","country":"DE"}\n',
        encoding="utf-8",
    )
    p = run_update(root)
    check("partB_valid_merge_rc", p.returncode == 0, p.returncode)
    check("partB_valid_db_changed", sha(db) != old)
    check("partB_no_stage_left", not (root / "current" / "geoip.sqlite.next").exists())
    import sqlite3

    conn = sqlite3.connect(db)
    try:
        cc = conn.execute(
            "SELECT country FROM geoip WHERE ip_start='1.2.4.0'"
        ).fetchone()
    finally:
        conn.close()
    check("partB_valid_new_country", cc is not None and cc[0] == "DE", cc)
    logtext = (root / "logs" / "update.log").read_text(encoding="utf-8", errors="replace")
    check("partB_swap_log", "swapped staged db" in logtext, logtext[-400:])


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--server",
        default=str(Path.home() / "scratch-geoipdata/target/release/webserver"),
    )
    ap.add_argument("--work", default=str(Path.home() / "scratch-geoipdata/atomic"))
    args = ap.parse_args()
    work = Path(args.work)
    work.mkdir(parents=True, exist_ok=True)
    part_a(work, args.server)
    part_b(work)
    print(f"geoip_atomic_swap_test: {'OK' if FAILS == 0 else f'{FAILS} FAILURES'}")
    return 0 if FAILS == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
