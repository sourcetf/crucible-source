#!/usr/bin/env python3
"""SSLv2 ClientHello probe against NON-STANDARD prod TLS port.

Sends a crafted SSLv2-style ClientHello to 18443 (never 8443/9445/9446) and
checks the server process (or port) is still alive afterward. Used by
debug_tls.sh / test_tls_stacks.sh / acceptance_test_ports.sh.
"""
from __future__ import annotations

import argparse
import binascii
import os
import socket
import sys
import time
from typing import Optional

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 18443  # config-test.toml prod-tls — NEVER 8443
FORBIDDEN_PORTS = {8443, 9445, 9446, 9081, 9095}
PIDFILE = "/tmp/crucible-test.pid"

# High-bit length SSLv2 ClientHello-ish blob (reject-path / tomcrypt route coverage).
# Layout: len_hi|len_lo | mt=1 | ver=0x0002 | cipher_spec_len | session_id_len | challenge_len | ...
HELLO = binascii.unhexlify(
    "80120100020000000000100000000000000000000000"
)


def probe(host: str, port: int) -> bool:
    s = socket.socket()
    s.settimeout(3.0)
    try:
        s.connect((host, port))
        s.sendall(HELLO)
        try:
            data = s.recv(64)
            print(f"sslv2_probe_recv {len(data)} bytes")
        except (socket.timeout, ConnectionResetError, BrokenPipeError, OSError):
            print("sslv2_probe_timeout_or_reset (ok — server closed/ignored)")
        print(f"sslv2_probe_ok host={host} port={port}")
        return True
    except Exception as e:
        print(f"sslv2_probe_err {e}", file=sys.stderr)
        return False
    finally:
        s.close()


def pid_alive(pidfile: str) -> Optional[bool]:
    """True/False if pidfile present; None if missing."""
    if not os.path.isfile(pidfile):
        return None
    try:
        with open(pidfile, encoding="utf-8") as f:
            pid = int(f.read().strip())
    except (OSError, ValueError):
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def port_open(host: str, port: int) -> bool:
    s = socket.socket()
    s.settimeout(2.0)
    try:
        s.connect((host, port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--host", default=DEFAULT_HOST)
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--pidfile", default=PIDFILE)
    ap.add_argument(
        "--settle-ms",
        type=int,
        default=1500,
        help="wait after probe before liveness check (ms)",
    )
    args = ap.parse_args()

    if args.port in FORBIDDEN_PORTS:
        print(
            f"refusing port {args.port}; use NON-STANDARD 18443/19445/19446 only",
            file=sys.stderr,
        )
        return 2

    probe(args.host, args.port)
    # Give soft-drop / spawn_blocking paths time to finish without racing pid check.
    settle = max(args.settle_ms, 500)
    time.sleep(settle / 1000.0)

    # Prefer explicit PID from acceptance (more reliable than pidfile races).
    env_pid = os.environ.get("CRUCIBLE_TEST_PID", "").strip()
    if env_pid.isdigit():
        try:
            os.kill(int(env_pid), 0)
            print(f"server_alive_ok pid={env_pid}")
            return 0
        except OSError:
            print(f"FAIL: server dead after sslv2 probe (pid={env_pid})", file=sys.stderr)
            return 1

    alive = pid_alive(args.pidfile)
    if alive is True:
        print("server_alive_ok")
        return 0
    if alive is False:
        print("FAIL: server dead after sslv2 probe", file=sys.stderr)
        return 1

    if port_open(args.host, args.port):
        print("server_port_open_ok")
        return 0
    print("FAIL: server unreachable after sslv2 probe", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
