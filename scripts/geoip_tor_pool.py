#!/usr/bin/env python3
"""§B.2 GeoIP 多 tor 守护进程池（LACNIC RDAP 专用；查询路径零网络）。

一 worker 一 tor 实例 = 一 SOCKS + 一 ControlPort，各自独立出口：
  GEOIP_TOR_POOL_DIR   默认 /tmp/geoip-tor-pool
  GEOIP_TOR_POOL_BASE  默认 9150   → SocksPort 127.0.0.1:9150+i
  GEOIP_TOR_POOL_CTRL  默认 9250   → ControlPort 127.0.0.1:9250+i
实例目录 <dir>/w{i}/；torrc 要点：CookieAuthentication 1、AvoidDiskWrites 1、
MaxCircuitDirtiness 120、NewCircuitPeriod 30、CircuitBuildTimeout 10。

API：
  ensure_tor_pool(n)         → ["127.0.0.1:9150", …]（端口已开则复用）
  tor_newnym_port("127.0.0.1:9150")   # cookie 认证 + SIGNAL NEWNYM，成功 sleep 2s
  stop_tor_pool()            # 按 pidfile SIGTERM
池空/失败回退系统 127.0.0.1:9050（ControlPort 未必开——NEWNYM 可能失败）。
"""
from __future__ import annotations

import os
import signal
import socket
import sqlite3  # noqa: F401  (保持与 geoip_common 同构的 import 风格)
import subprocess
import sys
import time
from pathlib import Path

POOL_DIR = os.environ.get("GEOIP_TOR_POOL_DIR", "/tmp/geoip-tor-pool")
SOCKS_BASE = int(os.environ.get("GEOIP_TOR_POOL_BASE", "9150"))
CTRL_BASE = int(os.environ.get("GEOIP_TOR_POOL_CTRL_BASE", "9250"))
MAX_POOL = 25
FALLBACK = "127.0.0.1:9050"


def _socks_alive(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.sendall(b"\x05\x01\x00")
        resp = s.recv(2)
        s.close()
        return resp == b"\x05\x00"
    except OSError:
        return False


def _torrc_path(i: int) -> Path:
    return Path(POOL_DIR) / f"w{i}" / "torrc"


def _write_torrc(i: int) -> Path:
    wdir = Path(POOL_DIR) / f"w{i}"
    (wdir / "data").mkdir(parents=True, exist_ok=True)
    torrc = wdir / "torrc"
    torrc.write_text(
        f"DataDirectory {wdir}/data\n"
        f"SocksPort 127.0.0.1:{SOCKS_BASE + i}\n"
        f"ControlPort 127.0.0.1:{CTRL_BASE + i}\n"
        "CookieAuthentication 1\n"
        "AvoidDiskWrites 1\n"
        "MaxCircuitDirtiness 120\n"
        "NewCircuitPeriod 30\n"
        "CircuitBuildTimeout 10\n",
        encoding="utf-8",
    )
    return torrc


def _spawn_instance(i: int) -> bool:
    torrc = _write_torrc(i)
    pidfile = Path(POOL_DIR) / f"w{i}" / "tor.pid"
    if pidfile.is_file():
        try:
            pid = int(pidfile.read_text().strip())
            os.kill(pid, 0)
            return True  # 仍在跑
        except (ValueError, ProcessLookupError, PermissionError):
            pidfile.unlink(missing_ok=True)
    try:
        proc = subprocess.Popen(
            ["tor", "-f", str(torrc), "--RunAsDaemon", "1",
             "--PidFile", str(pidfile)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        print(f"tor_pool: spawned w{i} pid={proc.pid} socks={SOCKS_BASE + i}",
              file=sys.stderr)
        return True
    except FileNotFoundError:
        print("tor_pool: tor binary not found; pool disabled", file=sys.stderr)
        return False


def ensure_tor_pool(n: int) -> list[str]:
    """确保 n 个实例就绪（n 上限 MAX_POOL）；返回可用 SOCKS 端点列表。"""
    n = max(1, min(n, MAX_POOL))
    ports: list[str] = []
    for i in range(n):
        socks = f"127.0.0.1:{SOCKS_BASE + i}"
        if _socks_alive("127.0.0.1", SOCKS_BASE + i):
            ports.append(socks)
            continue
        if _spawn_instance(i):
            # 等待 bootstrap 出 SOCKS 口（最多 ~20s；未就绪也先记录，后续重试）
            deadline = time.time() + 20
            while time.time() < deadline:
                if _socks_alive("127.0.0.1", SOCKS_BASE + i):
                    ports.append(socks)
                    break
                time.sleep(0.5)
            else:
                print(f"tor_pool: w{i} socks not ready", file=sys.stderr)
    if not ports:
        print(f"tor_pool: empty; fallback {FALLBACK}", file=sys.stderr)
        return [FALLBACK]
    return ports


def _cookie_hex(ctrl_port: int) -> str | None:
    """cookie 文件按端口定位：<dir>/w{i}/data/control_auth_cookie。"""
    i = ctrl_port - CTRL_BASE
    if i < 0:
        return None
    cookie = Path(POOL_DIR) / f"w{i}" / "data" / "control_auth_cookie"
    if not cookie.is_file():
        return None
    return cookie.read_bytes().hex()


def tor_newnym_port(socks: str) -> bool:
    """对池内实例发 SIGNAL NEWNYM（cookie 认证）；成功后 sleep ~2s。"""
    host, _, port_s = socks.partition(":")
    ctrl_port = int(port_s or 0) + (CTRL_BASE - SOCKS_BASE)
    hexcookie = _cookie_hex(int(port_s) if port_s else 0)
    try:
        s = socket.create_connection((host, ctrl_port), timeout=10)
        if hexcookie:
            s.sendall(f"AUTHENTICATE {hexcookie}\r\n".encode())
        else:
            s.sendall(b"AUTHENTICATE\r\n")
        resp = s.recv(256)
        if b"250" not in resp:
            s.close()
            return False
        s.sendall(b"SIGNAL NEWNYM\r\n")
        resp = s.recv(256)
        s.close()
        ok = b"250" in resp
        if ok:
            time.sleep(2)  # 单实例换路
        return ok
    except OSError:
        return False


def stop_tor_pool() -> None:
    root = Path(POOL_DIR)
    if not root.is_dir():
        return
    for pidfile in root.glob("w*/tor.pid"):
        try:
            pid = int(pidfile.read_text().strip())
            os.kill(pid, signal.SIGTERM)
            print(f"tor_pool: SIGTERM {pid}")
        except (ValueError, ProcessLookupError, PermissionError):
            pass
        pidfile.unlink(missing_ok=True)


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 5
    eps = ensure_tor_pool(n)
    print("pool:", eps)
