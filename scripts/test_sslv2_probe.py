#!/usr/bin/env python3
"""SSLv2 ClientHello probe (and optional full handshake) against a NON-STANDARD TLS port.

Default mode sends a truncated SSLv2-style ClientHello to the given port
(default 18443, never 8443/9445/9446) and checks the server process/port is
still alive afterward (robustness: incomplete probes must not kill the
webserver / must not trip libtomcrypt ARGCHK).

``--handshake`` performs the complete SSLv2 exchange the hand-written
libtomcrypt stack (libs/tls-tomcrypt/tc_shim.c) implements:

  CLIENT-HELLO (cipher 0x010080 = RC4_128_WITH_MD5, 16-byte challenge)
  SERVER-HELLO (certificate + connection id)
  CLIENT-MASTER-KEY (16-byte master, RSA PKCS#1 v1.5, clear_len=0)
  application data (RC4 + 16-byte MD5 trailer)

Pure stdlib: RSA via DER parsing + pow(), RC4 inlined in scripts/tls_probe.py.
Exit code 0 only when the handshake completes *and* an HTTP 200 comes back.
"""
from __future__ import annotations

import argparse
import binascii
import hashlib
import os
import socket
import struct
import sys
import time
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tls_probe import RC4, cert_rsa_pubkey, rsa_encrypt_pkcs1v15  # noqa: E402

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 18443  # config-test.toml prod-tls — NEVER 8443
FORBIDDEN_PORTS = {8443, 9445, 9446, 9081, 9095}
PIDFILE = "/tmp/crucible-test.pid"

# High-bit length SSLv2 ClientHello-ish blob (reject-path / tomcrypt route coverage).
# Layout: len_hi|len_lo | mt=1 | ver=0x0002 | cipher_spec_len | session_id_len | challenge_len | ...
HELLO = binascii.unhexlify(
    "80120100020000000000100000000000000000000000"
)

# Real SSLv2 cipher kind: SSL_CK_RC4_128_WITH_MD5.
CIPHER_RC4_128_MD5 = b"\x01\x00\x80"


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError(f"EOF after {len(buf)}/{n} bytes")
        buf += chunk
    return buf


def _send_record(sock: socket.socket, body: bytes) -> None:
    ln = len(body)
    sock.sendall(bytes([0x80 | ((ln >> 8) & 0x7F), ln & 0xFF]) + body)


def _recv_record(sock: socket.socket) -> bytes:
    hdr = _recv_exact(sock, 2)
    if not (hdr[0] & 0x80):
        raise ValueError(f"not an SSLv2 record: {hdr.hex()}")
    return _recv_exact(sock, ((hdr[0] & 0x7F) << 8) | hdr[1])


def full_handshake(host: str, port: int, timeout: float = 8.0) -> int:
    challenge = os.urandom(16)
    hello = (b"\x01" + struct.pack("!H", 0x0002)
             + struct.pack("!H", len(CIPHER_RC4_128_MD5))
             + struct.pack("!H", 0) + struct.pack("!H", len(challenge))
             + CIPHER_RC4_128_MD5 + challenge)
    sock = socket.create_connection((host, port), timeout=timeout)
    _send_record(sock, hello)

    body = _recv_record(sock)
    if body[0] != 0x04:
        print(f"FAIL sslv2: expected SERVER-HELLO (4), got msg type {body[0]}")
        sock.close()
        return 1
    version = struct.unpack("!H", body[3:5])[0]
    cert_len, cipher_len, conn_id_len = struct.unpack("!HHH", body[5:11])
    cert_der = body[11:11 + cert_len]
    cipher = body[11 + cert_len:11 + cert_len + cipher_len]
    conn_id = body[11 + cert_len + cipher_len:11 + cert_len + cipher_len + conn_id_len]
    if cipher != CIPHER_RC4_128_MD5:
        print(f"FAIL sslv2: server picked cipher {cipher.hex()}, want 010080")
        sock.close()
        return 1

    master = os.urandom(16)
    n, e = cert_rsa_pubkey(cert_der)
    enc = rsa_encrypt_pkcs1v15(n, e, master)
    # clear_len = 0: the whole 16-byte master key is RSA-encrypted.
    _send_record(sock, b"\x02" + CIPHER_RC4_128_MD5 + b"\x00" + struct.pack("!H", len(enc)) + enc)

    # SSLv2 key schedule (§1.2): CLIENT-WRITE-KEY = MD5(master || "1" || ...),
    # SERVER-WRITE-KEY = CLIENT-READ-KEY = MD5(master || "0" || ...).
    client_write = hashlib.md5(master + b"1" + challenge + conn_id).digest()
    server_write = hashlib.md5(master + b"0" + challenge + conn_id).digest()
    req = b"GET / HTTP/1.1\r\nHost: crucible.local\r\nConnection: close\r\n\r\n"
    # The shim strips this 16-byte trailer (it does not verify it).
    trailer = hashlib.md5(client_write + req).digest()
    _send_record(sock, RC4(client_write).crypt(req + trailer))

    rc4_in = RC4(server_write)
    resp = b""
    try:
        while True:
            plain = rc4_in.crypt(_recv_record(sock))
            resp += plain[:-16] if len(plain) >= 16 else plain
    except (EOFError, ConnectionResetError, socket.timeout, ValueError, OSError):
        pass
    sock.close()
    text = resp.decode("latin-1", "replace")
    first = text.split("\r\n")[0] if text else "<empty>"
    ok = text.startswith("HTTP/1.1 200")
    print(f"{'OK' if ok else 'FAIL'} sslv2 full handshake version=0x{version:04x} "
          f"cipher={cipher.hex()} response_bytes={len(resp)} http={first!r}")
    return 0 if ok else 1


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
    ap.add_argument(
        "--handshake",
        action="store_true",
        help="run the complete SSLv2 handshake (libtomcrypt stack) instead of the "
             "truncated robustness probe",
    )
    args = ap.parse_args()

    if args.port in FORBIDDEN_PORTS:
        print(
            f"refusing port {args.port}; use NON-STANDARD 18443/19445/19446 only",
            file=sys.stderr,
        )
        return 2

    if args.handshake:
        try:
            return full_handshake(args.host, args.port, timeout=args.settle_ms / 1000.0 + 5.0)
        except Exception as e:  # noqa: BLE001 - 探针要如实报告任何失败
            print(f"FAIL sslv2 full handshake: {type(e).__name__}: {e}")
            return 1

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
