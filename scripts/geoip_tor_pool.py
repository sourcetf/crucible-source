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


def _pid_alive(i: int) -> bool:
    """实例 i 是否已有存活进程（pidfile 有效）；过期 pidfile 顺手删掉。"""
    pidfile = Path(POOL_DIR) / f"w{i}" / "tor.pid"
    if not pidfile.is_file():
        return False
    try:
        os.kill(int(pidfile.read_text().strip()), 0)
        return True
    except (ValueError, ProcessLookupError, PermissionError):
        pidfile.unlink(missing_ok=True)
        return False


def _kill_instance(i: int) -> None:
    """按 pidfile 收掉实例 i（拉起后等不到 SOCKS 口时调用）。"""
    pidfile = Path(POOL_DIR) / f"w{i}" / "tor.pid"
    if not _pid_alive(i):
        return
    try:
        pid = int(pidfile.read_text().strip())
        os.kill(pid, signal.SIGTERM)
        print(f"tor_pool: SIGTERM w{i} pid={pid} (not ready)", file=sys.stderr)
    except (ValueError, ProcessLookupError, PermissionError):
        pass
    pidfile.unlink(missing_ok=True)


def _spawn_instance(i: int) -> bool:
    torrc = _write_torrc(i)
    pidfile = Path(POOL_DIR) / f"w{i}" / "tor.pid"
    if _pid_alive(i):
        return True  # 仍在跑
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
    """确保 n 个实例就绪（n 上限 MAX_POOL）；返回可用 SOCKS 端点列表。

    起不来或等不到 SOCKS 口的实例一律收掉。此前只打印一行「socks not ready」
    就继续下一个：一次失败就在机器上留下最多 MAX_POOL 个常驻 tor（各带自己的
    DataDirectory / SocksPort / ControlPort），而调用方只看得到「池为空 → 回退
    9050」—— 泄漏既不可见，也不会被 stop_tor_pool 之外的任何路径回收。
    """
    n = max(1, min(n, MAX_POOL))
    ports: list[str] = []
    for i in range(n):
        socks = f"127.0.0.1:{SOCKS_BASE + i}"
        if _socks_alive("127.0.0.1", SOCKS_BASE + i):
            ports.append(socks)
            continue
        was_running = _pid_alive(i)
        if not _spawn_instance(i):
            # _spawn_instance 只在 tor 二进制缺失时返回 False：后面每个 i 都会
            # 以同样的方式失败，重复 24 次只会刷 24 行同样的错误。
            break
        # 等待 bootstrap 出 SOCKS 口（最多 ~20s；未就绪也先记录，后续重试）
        deadline = time.time() + 20
        while time.time() < deadline:
            if _socks_alive("127.0.0.1", SOCKS_BASE + i):
                ports.append(socks)
                break
            time.sleep(0.5)
        else:
            print(f"tor_pool: w{i} socks not ready", file=sys.stderr)
            # 只收掉本次新拉起的：既有实例可能只是这一瞬间忙，杀错了要等它重新
            # bootstrap 才能补回来。
            if not was_running:
                _kill_instance(i)
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
    """对池内实例发 SIGNAL NEWNYM（cookie 认证）；成功后 sleep ~2s。

    只接受池内端口：非池端点（如池空时回退的 9050）按 `+（CTRL_BASE-SOCKS_BASE）`
    偏移会算出**另一个实例**的 ControlPort，而那个实例的 cookie 又读不到
    （`_cookie_hex` 用 ctrl 端口反查目录），AUTHENTICATE 必然失败；端口巧合时
    更糟 —— 会给别人的出口发 NEWNYM，把别人正在用的电路换掉。
    """
    host, _, port_s = socks.partition(":")
    if not port_s.isdigit():
        return False
    idx = int(port_s) - SOCKS_BASE
    if idx < 0 or idx >= MAX_POOL:
        return False
    ctrl_port = CTRL_BASE + idx
    hexcookie = _cookie_hex(ctrl_port)
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
    # `stop` 子命令：显式收掉池里所有 tor worker。
    # 为什么需要：tor 是 `--RunAsDaemon 1` 自我守护化的，脚本退出后它们照跑 ——
    # 实测一次采集后**25 个 tor 进程残留了一天**（连带几十 MB 数据目录），
    # 因为没有任何人调用下面这个 stop_tor_pool()。更新链（geoip_update.sh）现在会在
    # 结束时自动调用它；手工/独立运行时可以用这个子命令收尾。
    if len(sys.argv) > 1 and sys.argv[1] in ("stop", "--stop"):
        stop_tor_pool()
        print("tor pool stopped")
        sys.exit(0)
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 5
    eps = ensure_tor_pool(n)
    print("pool:", eps)
