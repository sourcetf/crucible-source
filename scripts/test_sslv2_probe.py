#!/usr/bin/env python3
"""SSLv2 ClientHello probe (and optional full handshake) against a NON-STANDARD TLS port.

Default mode sends a truncated SSLv2-style ClientHello to the given port
(default 18443, never 8443/9445/9446) and checks the server process/port is
still alive afterward (robustness: incomplete probes must not kill the
webserver / must not trip libtomcrypt ARGCHK).

``--handshake`` performs the **complete SSLv2 (SSL 2.0) handshake** implemented
by libs/tls-tomcrypt/tc_shim.c:

  CLIENT-HELLO        (cipher 0x010080 = RC4_128_WITH_MD5, 16-byte challenge)
  SERVER-HELLO        (certificate + cipher spec + random connection id)
  CLIENT-MASTER-KEY   (type(1) cipher(3) clear_len(2) enc_len(2) keyarg_len(2)
                       + RSA PKCS#1 v1.5 encrypted 16-byte master key)
  SERVER-VERIFY       (encrypted: type 5 + echoed challenge)
  CLIENT-FINISHED     (encrypted: type 3 + connection-id echo)
  SERVER-FINISHED     (encrypted: type 6 + session-id)
  application data    (encrypted records, HTTP request/response)

Record layer follows the SSL 2.0 spec / OpenSSL s2_pkt.c + s2_enc.c:
payload = MD5-MAC(16) || data, MAC = MD5(write_key || data(+padding) || seq_be32).
Each direction has its own 32-bit sequence that counts **every** record,
including the cleartext ones (OpenSSL INC32 runs unconditionally):
CLIENT-HELLO=0, CLIENT-MASTER-KEY=1, CLIENT-FINISHED=2, app data=3...
SERVER-HELLO=0, SERVER-VERIFY=1, SERVER-FINISHED=2, response=3...
A 2-byte record header is used because RC4 has no padding.

The server's SERVER-VERIFY challenge echo, its MAC, the CLIENT-FINISHED
connection-id echo (MAC-verified by the server; a wrong echo makes it abort),
and SERVER-FINISHED are all verified here; exit code 0 only when the whole
handshake completes *and* an HTTP 200 comes back. `-v` dumps every record at
byte level (wire hex + decrypted plaintext), which is the evidence that this is
a state machine and not a single CLIENT-HELLO probe.
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


def _record_bytes(body: bytes) -> bytes:
    ln = len(body)
    return bytes([0x80 | ((ln >> 8) & 0x7F), ln & 0xFF]) + body


def _send_record(sock: socket.socket, body: bytes) -> None:
    sock.sendall(_record_bytes(body))


def _recv_record_wire(sock: socket.socket):
    """Return (2-byte header + payload, payload) for one SSLv2 record."""
    hdr = _recv_exact(sock, 2)
    if not (hdr[0] & 0x80):
        raise ValueError(f"not an SSLv2 record: {hdr.hex()}")
    body = _recv_exact(sock, ((hdr[0] & 0x7F) << 8) | hdr[1])
    return hdr + body, body


def _recv_record(sock: socket.socket) -> bytes:
    return _recv_record_wire(sock)[1]


def _sslv2_mac(key: bytes, data: bytes, seq: int) -> bytes:
    """SSLv2 record MAC (OpenSSL ssl2_mac): MD5(key || data(+pad) || seq_be32)."""
    return hashlib.md5(key + data + struct.pack("!I", seq & 0xFFFFFFFF)).digest()


def _send_encrypted(sock: socket.socket, rc4: RC4, key: bytes, seq: int, body: bytes,
                    dump: bool = False) -> int:
    """Send one encrypted SSLv2 record; returns the next write sequence."""
    mac = _sslv2_mac(key, body, seq)
    payload = rc4.crypt(mac + body)
    if dump:
        print(f"  c->s seq={seq} plain={body.hex()} MAC={mac.hex()} wire={payload.hex()}")
    _send_record(sock, payload)
    return seq + 1


def _recv_encrypted(sock: socket.socket, rc4: RC4, key: bytes, seq: int,
                    dump: bool = False):
    """Read+decrypt+verify one SSLv2 record; returns (data, next_read_seq)."""
    wire, payload = _recv_record_wire(sock)
    payload = rc4.crypt(payload)
    if len(payload) < 16:
        raise ValueError(f"encrypted record too short: {len(payload)}")
    mac, body = payload[:16], payload[16:]
    want = _sslv2_mac(key, body, seq)
    if dump:
        print(f"  s->c seq={seq} wire={wire.hex()} plain={body.hex()} "
              f"MAC={mac.hex()} (want {want.hex()})")
    if mac != want:
        raise ValueError(
            f"record MAC mismatch at seq={seq}: got {mac.hex()} want {want.hex()} "
            f"(data {len(body)}B)"
        )
    return body, seq + 1


def full_handshake(host: str, port: int, timeout: float = 8.0, verbose: bool = False,
                   delay_ms: int = 0) -> int:
    challenge = os.urandom(16)
    hello = (b"\x01" + struct.pack("!H", 0x0002)
             + struct.pack("!H", len(CIPHER_RC4_128_MD5))
             + struct.pack("!H", 0) + struct.pack("!H", len(challenge))
             + CIPHER_RC4_128_MD5 + challenge)
    sock = socket.create_connection((host, port), timeout=timeout)
    # SSLv2 sequence numbers count **every** record in a direction, not only
    # the encrypted ones (OpenSSL s2_pkt.c INC32 runs for cleartext records
    # too): HELLO=0, CMK=1, CLIENT-FINISHED=2, app data=3; SERVER-HELLO=0,
    # SERVER-VERIFY=1, SERVER-FINISHED=2, response=3...
    cseq = 0
    sseq = 0
    _send_record(sock, hello)
    cseq += 1
    if verbose:
        print(f"client_hello wire={_record_bytes(hello).hex()} "
              f"({len(hello)}B payload, challenge={challenge.hex()})")

    server_hello_wire, body = _recv_record_wire(sock)
    sseq += 1
    if verbose:
        print(f"server_hello wire={server_hello_wire.hex()}")
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
    if conn_id_len != 16:
        print(f"FAIL sslv2: connection-id length {conn_id_len}, want 16")
        sock.close()
        return 1

    master = os.urandom(16)
    n, e = cert_rsa_pubkey(cert_der)
    enc = rsa_encrypt_pkcs1v15(n, e, master)
    # SSLv2 CLIENT-MASTER-KEY header is type(1) cipher(3) clear_len(2)
    # enc_len(2) key_arg_len(2) — clear/keyarg are 2-byte fields. The old
    # 1-byte-clear_len layout never matched a real client or OpenSSL.
    cmk = (b"\x02" + CIPHER_RC4_128_MD5 + struct.pack("!H", 0)
           + struct.pack("!H", len(enc)) + struct.pack("!H", 0) + enc)
    # A legitimate client may be slow to produce CLIENT-MASTER-KEY (RSA on an
    # old CPU, slow link). The server deadline must not kill it prematurely;
    # --handshake-delay-ms exercises exactly that window.
    if delay_ms > 0:
        time.sleep(delay_ms / 1000.0)
    _send_record(sock, cmk)
    cseq += 1
    if verbose:
        print(f"client_master_key wire={_record_bytes(cmk).hex()} "
              f"(enc_len={len(enc)}, master=REDACTED)")

    # SSLv2 key schedule: CLIENT-WRITE-KEY = MD5(master || "1" || challenge ||
    # conn_id), SERVER-WRITE-KEY = MD5(master || "0" || ...).
    client_write = hashlib.md5(master + b"1" + challenge + conn_id).digest()
    server_write = hashlib.md5(master + b"0" + challenge + conn_id).digest()

    # CLIENT-FINISHED (client sequence 2): echo the server connection id.
    # RC4 is a *stream* across records: keep one instance per direction.
    rc4_out = RC4(client_write)
    rc4_in = RC4(server_write)
    cseq = _send_encrypted(sock, rc4_out, client_write, cseq, b"\x03" + conn_id,
                           dump=verbose)

    # SERVER-VERIFY (server sequence 1, after the cleartext SERVER-HELLO):
    # must echo our challenge byte-for-byte.
    verify, sseq = _recv_encrypted(sock, rc4_in, server_write, sseq, dump=verbose)
    if verify[0] != 0x05 or verify[1:] != challenge:
        print(f"FAIL sslv2: bad SERVER-VERIFY type={verify[0]:#x} "
              f"challenge={verify[1:].hex()} want={challenge.hex()}")
        sock.close()
        return 1

    # SERVER-FINISHED (server sequence 2): 16-byte session id.
    finished, sseq = _recv_encrypted(sock, rc4_in, server_write, sseq, dump=verbose)
    if finished[0] != 0x06 or len(finished) != 17:
        print(f"FAIL sslv2: bad SERVER-FINISHED type={finished[0]:#x} len={len(finished)}")
        sock.close()
        return 1
    session_id = finished[1:]

    req = b"GET / HTTP/1.1\r\nHost: crucible.local\r\nConnection: close\r\n\r\n"
    cseq = _send_encrypted(sock, rc4_out, client_write, cseq, req, dump=verbose)

    resp = b""
    records = 0
    macs = 0
    try:
        while True:
            plain, sseq = _recv_encrypted(sock, rc4_in, server_write, sseq)
            if verbose and records == 0:
                print(f"  first http response record plain={plain[:48].hex()}…")
            records += 1
            macs += 1
            resp += plain
    except (EOFError, ConnectionResetError, socket.timeout, ValueError, OSError):
        pass
    sock.close()
    text = resp.decode("latin-1", "replace")
    first = text.split("\r\n")[0] if text else "<empty>"
    ok = text.startswith("HTTP/1.1 200")
    if verbose:
        print(f"sslv2 handshake details: conn_id={conn_id.hex()} "
              f"session_id={session_id.hex()} client_seq={cseq} server_seq={sseq} "
              f"response_records={records} mac_verified={macs}")
    print(f"{'OK' if ok else 'FAIL'} sslv2 full handshake version=0x{version:04x} "
          f"cipher={cipher.hex()} verify=ok finished=ok session_id={session_id.hex()[:8]}… "
          f"response_bytes={len(resp)} mac_verified={macs} http={first!r}")
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


def _build_sslv2_hello() -> bytes:
    challenge = os.urandom(16)
    body = (b"\x01" + struct.pack("!H", 0x0002)
            + struct.pack("!H", len(CIPHER_RC4_128_MD5))
            + struct.pack("!H", 0) + struct.pack("!H", len(challenge))
            + CIPHER_RC4_128_MD5 + challenge)
    return bytes([0x80 | ((len(body) >> 8) & 0x7F), len(body) & 0xFF]) + body


def _build_ie6_v2compat_hello() -> bytes:
    """IE6-style SSL_ENABLE_V2_COMPATIBLE_HELLO: v2 framing, version 0x0300,
    SSLv2 3-byte cipher spec `00 || suite` (suite 0x0004 = RC4_128_MD5)."""
    challenge = os.urandom(16)
    suites = b"\x00" + struct.pack("!H", 0x0004)
    body = (b"\x01" + struct.pack("!H", 0x0300)
            + struct.pack("!H", len(suites)) + struct.pack("!H", 0)
            + struct.pack("!H", len(challenge)) + suites + challenge)
    return bytes([0x80 | ((len(body) >> 8) & 0x7F), len(body) & 0xFF]) + body


def _server_metrics(pid: Optional[int]):
    """(threads, VmRSS kB, open fds) from /proc, or None."""
    if not pid:
        return None
    try:
        with open(f"/proc/{pid}/status", encoding="utf-8") as f:
            text = f.read()
        threads = int(next(line.split()[1] for line in text.splitlines()
                           if line.startswith("Threads:")))
        rss = int(next(line.split()[1] for line in text.splitlines()
                       if line.startswith("VmRSS:")))
        try:
            fds = len(os.listdir(f"/proc/{pid}/fd"))
        except OSError:
            fds = -1
        return threads, rss, fds
    except (OSError, StopIteration, ValueError):
        return None


def stress_slow_handshakes(host: str, port: int, count: int, kind: str, hold: float,
                           pid: Optional[int], verbose: bool) -> int:
    """Open `count` legacy handshakes, send the ClientHello, then stall.

    Server must release every connection within its 10s handshake deadline and
    keep thread/RSS growth bounded (O8). Also checks the sockets are closed.
    """
    hello = _build_sslv2_hello() if kind == "sslv2" else _build_ie6_v2compat_hello()
    base = _server_metrics(pid)
    socks = []
    for _ in range(count):
        s = socket.socket()
        s.settimeout(5.0)
        s.connect((host, port))
        s.sendall(hello)
        socks.append(s)
    time.sleep(1.0)
    peak = _server_metrics(pid)
    time.sleep(max(0.0, hold - 1.0))
    during = _server_metrics(pid)
    # 10s deadline + shutdown + C unwind grace.
    time.sleep(2.0)
    after = _server_metrics(pid)

    released = 0
    for s in socks:
        # The server sent SERVER-HELLO before stalling, so a single recv(1)
        # would return buffered data. Drain until EOF/reset (deadline release)
        # rather than treating the first byte as "still alive".
        try:
            s.settimeout(2.0)
            while True:
                data = s.recv(4096)
                if data == b"":
                    released += 1
                    break
        except socket.timeout:
            pass  # still open → not released
        except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError, OSError):
            released += 1
        finally:
            s.close()

    # Tokio keeps idle blocking-pool threads for a keep-alive period; measure
    # again after they expire so "bounded" is separated from "immediately 0".
    time.sleep(12.0)
    settled = _server_metrics(pid)

    def fmt(m):
        return f"threads={m[0]},rss_kb={m[1]},fds={m[2]}" if m else "threads=?,rss_kb=?,fds=?"

    print(f"stress kind={kind} n={count} hold={hold:.0f}s baseline[{fmt(base)}] "
          f"peak[{fmt(peak)}] at_hold[{fmt(during)}] after[{fmt(after)}] "
          f"settled[{fmt(settled)}] released={released}/{count}")
    if verbose:
        print(f"stress hello ({len(hello)}B) hex={hello.hex()}")
    return 0 if released == count else 1


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
    ap.add_argument(
        "--handshake-delay-ms",
        type=int,
        default=0,
        metavar="MS",
        help="sleep MS after SERVER-HELLO before sending CLIENT-MASTER-KEY "
             "(models a slow but legitimate client; must stay below the server's "
             "10s legacy handshake deadline)",
    )
    ap.add_argument("-v", "--verbose", action="store_true", help="print per-record details")
    ap.add_argument(
        "--stress",
        type=int,
        default=0,
        metavar="N",
        help="O8: open N legacy handshakes, send only the ClientHello, hold and "
             "verify the server releases them within its handshake deadline",
    )
    ap.add_argument("--stress-kind", choices=("sslv2", "ie6"), default="sslv2",
                    help="which ClientHello to send in --stress mode")
    ap.add_argument("--stress-hold", type=float, default=14.0,
                    help="seconds to hold the stalled handshakes (default 14)")
    ap.add_argument("--server-pid", type=int, default=0,
                    help="server pid for thread/RSS metrics in --stress mode "
                         "(default: $CRUCIBLE_TEST_PID or --pidfile)")
    args = ap.parse_args()

    if args.port in FORBIDDEN_PORTS:
        print(
            f"refusing port {args.port}; use NON-STANDARD 18443/19445/19446 only",
            file=sys.stderr,
        )
        return 2

    if args.stress:
        pid = args.server_pid
        if not pid:
            env_pid = os.environ.get("CRUCIBLE_TEST_PID", "").strip()
            if env_pid.isdigit():
                pid = int(env_pid)
        if not pid:
            try:
                with open(args.pidfile, encoding="utf-8") as f:
                    pid = int(f.read().strip())
            except (OSError, ValueError):
                pid = None
        try:
            return stress_slow_handshakes(args.host, args.port, args.stress,
                                          args.stress_kind, args.stress_hold,
                                          pid, args.verbose)
        except Exception as e:  # noqa: BLE001
            print(f"FAIL sslv2 stress: {type(e).__name__}: {e}")
            return 1

    if args.handshake:
        try:
            return full_handshake(args.host, args.port,
                                  timeout=args.settle_ms / 1000.0 + 5.0 +
                                  args.handshake_delay_ms / 1000.0,
                                  verbose=args.verbose,
                                  delay_ms=args.handshake_delay_ms)
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
