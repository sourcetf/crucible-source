#!/usr/bin/env python3
"""interop_h3_udp.py — U-06: end-to-end CONNECT-UDP (RFC 9298) round-trip tests.

Runs a real UDP echo service (``interop_h3_echo.py``) behind our H3 listener and
drives it through an actual CONNECT-UDP tunnel with aioquic.  Both framing modes
are exercised:

  * ``capsule``       — RFC 9297 capsules (``Capsule-Protocol: ?1``);
  * ``lengthprefix``  — RFC 9298 §4.3 varint length-prefixed datagrams.

Each mode sends N datagrams of 1 B / 1 KiB / 32 KiB through the tunnel; every
reply is checked for byte-for-byte integrity and strict sequence order, and RTT
percentiles are reported.  Additional cases cover downlink-only push, target
refusal (ICMP port unreachable), no-route targets, framing limits (oversized
datagrams), the IPv4 UDP payload boundary, CLOSE capsules, and 10 concurrent
tunnels.

NOTE: our CONNECT-UDP admission policy rejects loopback/private targets
(anti-SSRF, see ``src/server/connect_udp.rs::is_disallowed_ip``).  To test a
local echo service through the *unmodified* product code, run the whole stack
inside a user network namespace and assign the echo service a public-looking
address, e.g. ``ip addr add 1.1.1.1/32 dev lo`` (see ``scripts/interop_h3.sh``).

Usage:
    python3 scripts/interop_h3_udp.py --port 27143 --target 1.1.1.1:9000 \
        [--count 1000] [--sizes 1,1024,32768] [--window 8] [--json out.json]
"""
import argparse
import asyncio
import json
import os
import ssl
import struct
import sys
import time

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated, StreamDataReceived, StreamReset

FILLER = bytes(((i * 31 + 7) & 0xFF) for i in range(65536))
MAX_UDP_PAYLOAD_V4 = 65507  # 65535 - 20 (IPv4) - 8 (UDP)
H3_MESSAGE_ERROR = 0x10E  # RFC 9114 §8.1

RESULTS = []


def make_payload(seq: int, size: int) -> bytes:
    if size < 12:
        return bytes([(seq + i) & 0xFF for i in range(size)])
    return struct.pack(">QI", seq, size) + FILLER[: size - 12]


def encode_varint(v: int) -> bytes:
    if v < (1 << 6):
        return bytes([v])
    if v < (1 << 14):
        return bytes([0x40 | (v >> 8), v & 0xFF])
    if v < (1 << 30):
        return bytes([0x80 | (v >> 24), (v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF])
    return b"\xc0" + v.to_bytes(8, "big")


def decode_varint(buf: bytes):
    if not buf:
        return None
    n = 1 << (buf[0] >> 6)
    if len(buf) < n:
        return None
    v = buf[0] & 0x3F
    for b in buf[1:n]:
        v = (v << 8) | b
    return v, n


def frame(framing: str, payload: bytes) -> bytes:
    if framing == "capsule":
        return encode_varint(0x00) + encode_varint(len(payload) + 1) + b"\x00" + payload
    return encode_varint(len(payload)) + payload


class Assembler:
    """Client-side datagram reassembly (mirrors src/server/connect_udp.rs)."""

    def __init__(self, framing: str):
        self.buf = bytearray()
        self.framing = framing

    def push(self, data: bytes) -> None:
        self.buf += data

    def next_event(self):
        if self.framing == "capsule":
            while True:
                h = decode_varint(bytes(self.buf))
                if h is None:
                    return None
                ty, used = h
                h2 = decode_varint(bytes(self.buf[used:]))
                if h2 is None:
                    return None
                ln, used2 = h2
                if ln > 65535:
                    raise ValueError(f"capsule payload {ln} exceeds limit")
                total = used + used2 + ln
                if len(self.buf) < total:
                    return None
                payload = bytes(self.buf[used + used2 : total])
                del self.buf[:total]
                if ty == 0x00:
                    cid = decode_varint(payload)
                    if cid is None:
                        raise ValueError("DATAGRAM capsule missing Context ID")
                    cid_v, cid_len = cid
                    if cid_v != 0:
                        continue  # unknown context: RFC 9298 §5 says drop
                    return ("dg", payload[cid_len:])
                if ty == 0x01:
                    return ("close", None)
                continue
        h = decode_varint(bytes(self.buf))
        if h is None:
            return None
        ln, used = h
        if ln > 65527:
            raise ValueError(f"datagram length {ln} exceeds 65527")
        if len(self.buf) < used + ln:
            return None
        payload = bytes(self.buf[used : used + ln])
        del self.buf[: used + ln]
        return ("dg", payload)


class UdpClient(QuicConnectionProtocol):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.h3 = H3Connection(self._quic)
        self.queues = {}
        self.next_stream = 0

    def quic_event_received(self, event):
        if isinstance(event, StreamDataReceived):
            q = self.queues.get(event.stream_id)
            if q is None:
                return
            try:
                evs = self.h3.handle_event(event)
            except Exception as e:  # noqa: BLE001 - report, do not crash the client
                q.put_nowait(("error", repr(e)))
                return
            for ev in evs:
                if isinstance(ev, HeadersReceived):
                    q.put_nowait(("headers", ev.headers))
                elif isinstance(ev, DataReceived):
                    q.put_nowait(("data", ev.data))
            if event.end_stream:
                q.put_nowait(("fin", None))
        elif isinstance(event, StreamReset):
            q = self.queues.get(event.stream_id)
            if q is not None:
                q.put_nowait(("reset", event.error_code))
        elif isinstance(event, ConnectionTerminated):
            for q in self.queues.values():
                q.put_nowait(("conn_close", event.error_code))
        else:
            try:
                self.h3.handle_event(event)
            except Exception:
                pass

    def new_queue(self):
        self.next_stream += 1
        return asyncio.Queue()

    async def open_tunnel(self, authority: str, path: str, framing: str,
                          extra_headers=None, timeout=10.0):
        sid = self._quic.get_next_available_stream_id()
        q = asyncio.Queue()
        self.queues[sid] = q
        headers = [
            (b":method", b"CONNECT"),
            (b":protocol", b"connect-udp"),
            (b":scheme", b"https"),
            (b":authority", authority.encode()),
            (b":path", path.encode()),
        ]
        if framing == "capsule":
            headers.append((b"capsule-protocol", b"?1"))
        if extra_headers:
            headers.extend(extra_headers)
        self.h3.send_headers(sid, headers, end_stream=False)
        self.transmit()
        deadline = time.monotonic() + timeout
        while True:
            left = deadline - time.monotonic()
            ev = await asyncio.wait_for(q.get(), timeout=max(0.01, left))
            if ev[0] == "headers":
                status = None
                hdrs = {}
                for k, v in ev[1]:
                    if k == b":status":
                        status = int(v)
                    else:
                        hdrs[k.decode()] = v.decode()
                return sid, q, status, hdrs
            if ev[0] in ("fin", "reset", "conn_close"):
                return sid, q, None, {"closed": ev[0]}
            if ev[0] == "error":
                raise RuntimeError(ev[1])

    def send(self, sid: int, data: bytes) -> None:
        self.h3.send_data(sid, data, False)
        self.transmit()

    def close_stream(self, sid: int) -> None:
        try:
            self.h3.send_data(sid, b"", True)
        except Exception:
            pass
        self.transmit()


def pct(vals, p):
    if not vals:
        return None
    s = sorted(vals)
    k = min(len(s) - 1, max(0, int(round((p / 100.0) * (len(s) - 1)))))
    return s[k]


def rec(name, ok, detail, extra=None, sev="P1"):
    RESULTS.append({"name": name, "status": "PASS" if ok else "FAIL",
                    "severity": sev, "detail": str(detail), "extra": extra or {}})
    print(f"[{'PASS' if ok else 'FAIL'}] {name}: {detail}", flush=True)


async def wait_event(q, kinds, timeout):
    """Wait for one of ``kinds``; other events are skipped."""
    deadline = time.monotonic() + timeout
    while True:
        left = deadline - time.monotonic()
        ev = await asyncio.wait_for(q.get(), timeout=max(0.01, left))
        if ev[0] in kinds:
            return ev
        if ev[0] == "error":
            return ("error", ev[1])


async def echo_roundtrip(cli, authority, target_path, framing, size, count, window):
    sid, q, status, hdrs = await cli.open_tunnel(authority, target_path, framing)
    label = f"{framing} size={size} count={count}"
    if status != 200:
        rec(f"tunnel open ({label})", False, f"status={status} hdrs={hdrs}")
        return None
    if framing == "capsule" and hdrs.get("capsule-protocol") != "?1":
        rec(f"tunnel open ({label})", False,
            f"200 without capsule-protocol: ?1 (hdrs={hdrs})")
        return None
    asm = Assembler(framing)
    send_times = {}
    lat = []
    sent = recv = outstanding = next_seq = 0
    t0 = time.monotonic()
    try:
        while recv < count:
            while sent < count and outstanding < window:
                send_times[sent] = time.monotonic()
                cli.send(sid, frame(framing, make_payload(sent, size)))
                sent += 1
                outstanding += 1
            ev = await wait_event(q, ("data", "fin", "reset", "conn_close"), 15.0)
            if ev[0] != "data":
                rec(f"echo {label}", False,
                    f"stream ended early after {recv}/{count} replies (event={ev[0]})")
                return None
            asm.push(ev[1])
            while True:
                try:
                    item = asm.next_event()
                except ValueError as e:
                    rec(f"echo {label}", False, f"client framing error: {e}")
                    return None
                if item is None:
                    break
                kind, payload = item
                if kind == "close":
                    rec(f"echo {label}", False, f"peer CLOSE before all replies ({recv}/{count})")
                    return None
                if size < 12:
                    expect = make_payload(next_seq, size)
                    seq = next_seq
                else:
                    if len(payload) < 12:
                        rec(f"echo {label}", False, f"short payload {len(payload)}")
                        return None
                    seq = struct.unpack(">Q", payload[:8])[0]
                    expect = make_payload(seq, size)
                if len(payload) != size or payload != expect:
                    rec(f"echo {label}", False,
                        f"integrity mismatch at seq {seq} (len={len(payload)})")
                    return None
                if seq != next_seq:
                    rec(f"echo {label}", False,
                        f"ordering violation: got seq {seq}, expected {next_seq}")
                    return None
                lat.append(time.monotonic() - send_times.pop(seq))
                next_seq += 1
                recv += 1
                outstanding -= 1
        elapsed = time.monotonic() - t0
        # Normal close: capsule mode uses a CLOSE capsule, length-prefix uses FIN.
        if framing == "capsule":
            cli.send(sid, encode_varint(0x01) + encode_varint(0))
        else:
            cli.close_stream(sid)
        ev = await wait_event(q, ("fin", "reset", "conn_close"), 5.0)
        closed_ok = ev[0] == "fin"
        stats = {
            "framing": framing, "size": size, "count": count,
            "rtt_ms": {
                "min": round(min(lat) * 1000, 3),
                "p50": round(pct(lat, 50) * 1000, 3),
                "p95": round(pct(lat, 95) * 1000, 3),
                "p99": round(pct(lat, 99) * 1000, 3),
                "max": round(max(lat) * 1000, 3),
                "mean": round(sum(lat) / len(lat) * 1000, 3),
            },
            "elapsed_s": round(elapsed, 3),
            "throughput_mib_s": round((size * count * 2) / elapsed / 1048576, 2),
            "close": ev[0],
        }
        rec(f"echo {label}", True,
            f"{count}/{count} integrity+order OK, RTT p50={stats['rtt_ms']['p50']}ms "
            f"p95={stats['rtt_ms']['p95']}ms, {stats['throughput_mib_s']} MiB/s, "
            f"close={ev[0]}", stats, sev="P0")
        return stats
    finally:
        cli.queues.pop(sid, None)


async def push_downlink(cli, authority, target_path, framing, count=1000, size=1024):
    """Downlink-only: ask the echo service to push `count` datagrams unsolicited.

    This is a *best-effort* datagram test.  A CONNECT-UDP tunnel relays UDP
    datagrams, which are allowed to be lost (RFC 9298 §1); and a 1 MiB burst
    from the echo can overflow the receiving UDP socket buffer even without any
    proxy in the path (verified with ``echo_direct_test.py``: the default
    ~208 KiB SO_RCVBUF loses packets, an 8 MiB buffer delivers all 1000).  We
    therefore require every *delivered* datagram to be integrity-correct and
    strictly ordered, and report the upstream loss instead of demanding zero
    loss."""
    sid, q, status, _ = await cli.open_tunnel(authority, target_path, framing)
    if status != 200:
        rec("downlink push", False, f"status={status}")
        return None
    cli.send(sid, frame(framing, f"PUSH {count} {size}".encode()))
    asm = Assembler(framing)
    prev_seq = -1
    delivered = corrupted = out_of_order = 0
    last_event = "?"
    t0 = time.monotonic()
    last_rx = time.monotonic()
    while delivered < count and time.monotonic() - last_rx < 3.0:
        try:
            ev = await wait_event(q, ("data", "fin", "reset"), 3.0)
        except asyncio.TimeoutError:
            break
        last_event = ev[0]
        if ev[0] != "data":
            break
        last_rx = time.monotonic()
        asm.push(ev[1])
        while True:
            item = asm.next_event()
            if item is None:
                break
            kind, payload = item
            if kind == "close":
                last_event = "close"
                break
            if len(payload) < 12:
                corrupted += 1
                continue
            seq = struct.unpack(">Q", payload[:8])[0]
            if payload != make_payload(seq, size):
                corrupted += 1
            elif seq <= prev_seq:
                out_of_order += 1
            else:
                prev_seq = seq
            delivered += 1
    elapsed = time.monotonic() - t0
    # Normal close so the tunnel does not linger.
    cli.send(sid, encode_varint(0x01) + encode_varint(0) if framing == "capsule" else b"")
    if framing != "capsule":
        cli.close_stream(sid)
    loss_pct = round(100.0 * (count - delivered) / count, 2)
    ok = corrupted == 0 and out_of_order == 0 and delivered > 0
    stats = {"framing": framing, "count": count, "size": size,
             "delivered": delivered, "lost": count - delivered, "loss_pct": loss_pct,
             "corrupted": corrupted, "out_of_order": out_of_order,
             "elapsed_s": round(elapsed, 3), "end": last_event}
    rec("downlink push", ok,
        f"{delivered}/{count} unsolicited datagrams integrity+order OK "
        f"(corrupted={corrupted} out_of_order={out_of_order}, "
        f"upstream UDP loss={loss_pct}%), end={last_event}", stats)
    cli.queues.pop(sid, None)
    return stats


async def open_expect_status(cli, authority, target_path, framing, want):
    sid, q, status, hdrs = await cli.open_tunnel(authority, target_path, framing)
    ok = status == want
    rec(f"admission {target_path} ({framing})", ok,
        f"status={status} (want {want}) hdrs={hdrs}", {"status": status})
    # Drain the response so the stream does not linger.
    try:
        while True:
            ev = await asyncio.wait_for(q.get(), timeout=1.0)
            if ev[0] in ("fin", "reset", "conn_close"):
                break
    except asyncio.TimeoutError:
        pass
    cli.queues.pop(sid, None)
    return status


async def expect_tunnel_close(cli, authority, path, framing, payloads, want_event,
                              timeout=6.0):
    sid, q, status, hdrs = await cli.open_tunnel(authority, path, framing)
    if status != 200:
        cli.queues.pop(sid, None)
        return ("no_tunnel", status)
    for p in payloads:
        try:
            cli.send(sid, frame(framing, p))
        except Exception as e:  # noqa: BLE001
            cli.queues.pop(sid, None)
            return ("send_error", repr(e))
    ev = await wait_event(q, ("fin", "reset", "conn_close"), timeout)
    cli.queues.pop(sid, None)
    return ev


async def concurrent_tunnels(cli, authority, target_path, framing, n_tunnels=10,
                             n_pkts=50, size=1024, window=4):
    async def one(idx):
        sid, q, status, _ = await cli.open_tunnel(authority, target_path, framing)
        if status != 200:
            return f"tunnel {idx}: status {status}"
        asm = Assembler(framing)
        sent = recv = outstanding = next_seq = 0
        try:
            while recv < n_pkts:
                while sent < n_pkts and outstanding < window:
                    cli.send(sid, frame(framing, make_payload(sent, size)))
                    sent += 1
                    outstanding += 1
                ev = await wait_event(q, ("data", "fin", "reset"), 15.0)
                if ev[0] != "data":
                    return f"tunnel {idx}: early {ev[0]} at {recv}/{n_pkts}"
                asm.push(ev[1])
                while True:
                    item = asm.next_event()
                    if item is None:
                        break
                    kind, payload = item
                    if kind != "dg":
                        return f"tunnel {idx}: unexpected {kind}"
                    seq = struct.unpack(">Q", payload[:8])[0]
                    if payload != make_payload(seq, size) or seq != next_seq:
                        return f"tunnel {idx}: bad payload/order at {seq}/{next_seq}"
                    next_seq += 1
                    recv += 1
                    outstanding -= 1
            cli.send(sid, encode_varint(0x01) + encode_varint(0)
                     if framing == "capsule" else b"")
            if framing != "capsule":
                cli.close_stream(sid)
            return None
        finally:
            cli.queues.pop(sid, None)

    t0 = time.monotonic()
    errs = await asyncio.gather(*(one(i) for i in range(n_tunnels)))
    bad = [e for e in errs if e]
    stats = {"tunnels": n_tunnels, "packets_each": n_pkts, "size": size,
             "elapsed_s": round(time.monotonic() - t0, 3), "errors": bad}
    rec("concurrent 10 tunnels", not bad,
        f"{n_tunnels} tunnels x {n_pkts} x {size}B: "
        + ("all integrity+order OK" if not bad else f"{len(bad)} failed: {bad[:3]}"),
        stats, sev="P0")


async def run(args):
    target_host, target_port = args.target.rsplit(":", 1)
    target_path = f"/{target_host}:{target_port}"
    authority = f"127.0.0.1:{args.port}"
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"],
                            verify_mode=ssl.CERT_NONE)
    # Deliberately do NOT enable H3_DATAGRAM: forces the two stream framings.
    sizes = [int(x) for x in args.sizes.split(",") if x]
    async with connect("127.0.0.1", args.port, configuration=cfg,
                       create_protocol=UdpClient) as cli:
        await cli.wait_connected()
        print(f"connected: {authority}, target {target_host}:{target_port}", flush=True)

        # 0) admission policy sanity (documents why the echo needs a public alias).
        await open_expect_status(cli, authority, "/127.0.0.1:9", "capsule", 403)
        await open_expect_status(cli, authority, "/1.1.1.1:0", "capsule", 400)
        await open_expect_status(cli, authority, "/.well-known/masque/udp/a%zzb/53/",
                                 "capsule", 400)
        # Default-template form must work too.
        template = f"/.well-known/masque/udp/{target_host}/{target_port}/"
        await open_expect_status(cli, authority, template, "capsule", 200)

        # 1) echo round-trips: 2 framings x 3 sizes x N packets.
        for framing in ("capsule", "lengthprefix"):
            for size in sizes:
                await echo_roundtrip(cli, authority, target_path, framing,
                                     size, args.count, args.window)

        # 2) downlink-only push (unsolicited 1000 datagrams).
        await push_downlink(cli, authority, target_path, "capsule",
                            count=args.count, size=1024)

        # 3) target refused: 8.8.8.8 is on lo but nobody listens on 19999.
        ev = await expect_tunnel_close(cli, authority, "/8.8.8.8:19999", "capsule",
                                       [b"x" * 16] * 5, "fin")
        rec("target refused (ICMP port unreachable)", ev[0] in ("fin", "reset"),
            f"tunnel closed with {ev[0]}{'' if ev[0] != 'reset' else f' code={ev[1]}'}",
            {"event": ev[0]}, sev="P1")

        # 4) target unreachable: 9.9.9.9 has no route in the namespace.  Linux
        #    resolves the route during UDP connect(), so the proxy answers 502
        #    instead of establishing a tunnel that can never carry a datagram.
        st = await open_expect_status(cli, authority, "/9.9.9.9:9000", "capsule", 502)
        rec("target unreachable (no route)", st == 502,
            f"status={st} (want 502 Bad Gateway)", {"status": st}, sev="P1")

        # 5) oversized datagram (framing limit): must reset with H3_MESSAGE_ERROR.
        for framing in ("capsule", "lengthprefix"):
            ev = await expect_tunnel_close(cli, authority, target_path, framing,
                                           [b"z" * 70000], "reset", timeout=8.0)
            ok = ev[0] == "reset" and ev[1] == H3_MESSAGE_ERROR
            rec(f"oversized 70000B ({framing})", ok,
                f"event={ev[0]} code={ev[1] if ev[0] == 'reset' else '-'} "
                f"(want reset {H3_MESSAGE_ERROR})", {"event": ev[0],
                                                     "code": ev[1] if ev[0] == 'reset' else None})

        # 6) IPv4 UDP payload boundary: 65507 fits, 65508 cannot be sent by the
        #    kernel (EMSGSIZE) and the proxy closes the tunnel.
        sid, q, status, _ = await cli.open_tunnel(authority, target_path, "capsule")
        if status == 200:
            payload = bytes((i * 7 + 3) & 0xFF for i in range(MAX_UDP_PAYLOAD_V4))
            asm = Assembler("capsule")
            cli.send(sid, frame("capsule", payload))
            got = b""
            end = "timeout"
            deadline = time.monotonic() + 10.0
            while time.monotonic() < deadline and not got:
                ev = await wait_event(q, ("data", "fin", "reset"), 10.0)
                if ev[0] != "data":
                    end = ev[0]
                    break
                # aioquic delivers H3 DATA payload in chunks, not one event per
                # DATA frame; keep feeding the assembler until a datagram appears.
                asm.push(ev[1])
                while True:
                    item = asm.next_event()
                    if item is None:
                        break
                    if item[0] == "dg":
                        got = item[1]
                        end = "datagram"
                        break
            if got and got != payload:
                end = "payload mismatch"
            rec(f"65507B datagram (IPv4 max UDP payload)", len(got) == MAX_UDP_PAYLOAD_V4
                and got == payload, f"reply {len(got)}B, end={end}",
                {"reply_len": len(got)}, sev="P2")
            cli.send(sid, encode_varint(0x01) + encode_varint(0))
            cli.queues.pop(sid, None)
        ev = await expect_tunnel_close(cli, authority, target_path, "capsule",
                                       [bytes(65508)], "fin", timeout=8.0)
        rec("65508B datagram (> IPv4 max, < RFC 9298 limit)", ev[0] in ("fin", "reset"),
            f"proxy closed tunnel with {ev[0]}{'' if ev[0] != 'reset' else f' code={ev[1]}'}",
            {"event": ev[0]}, sev="P2")

        # 7) CLOSE capsule ends the tunnel normally.
        sid, q, status, _ = await cli.open_tunnel(authority, target_path, "capsule")
        if status == 200:
            cli.send(sid, encode_varint(0x01) + encode_varint(0))
            ev = await wait_event(q, ("fin", "reset", "conn_close"), 5.0)
            rec("CLOSE capsule", ev[0] == "fin", f"server closed with {ev[0]}",
                {"event": ev[0]}, sev="P2")
            cli.queues.pop(sid, None)

        # 8) 10 concurrent tunnels on one QUIC connection.
        await concurrent_tunnels(cli, authority, target_path, "capsule")

    return RESULTS


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=27143)
    ap.add_argument("--target", default="1.1.1.1:9000",
                    help="UDP echo target host:port (must be admitted as public unicast)")
    ap.add_argument("--count", type=int, default=1000)
    ap.add_argument("--sizes", default="1,1024,32768")
    ap.add_argument("--window", type=int, default=8)
    ap.add_argument("--json", default="")
    ap.add_argument("--timeout", type=float, default=600.0)
    args = ap.parse_args()
    t0 = time.monotonic()
    try:
        asyncio.run(asyncio.wait_for(run(args), args.timeout))
    except Exception as e:  # noqa: BLE001
        RESULTS.append({"name": "fatal", "status": "FAIL", "severity": "P0",
                        "detail": repr(e), "extra": {}})
        print(f"[FAIL] fatal: {e!r}", flush=True)
    summary = {
        "suite": "U-06 CONNECT-UDP",
        "host": args.host, "port": args.port, "target": args.target,
        "count": args.count, "sizes": args.sizes, "window": args.window,
        "elapsed_s": round(time.monotonic() - t0, 2),
        "results": RESULTS,
        "failures": [r["name"] for r in RESULTS if r["status"] == "FAIL"],
    }
    if args.json:
        with open(args.json, "w") as f:
            json.dump(summary, f, indent=2, default=str)
        print(f"json: {args.json}", flush=True)
    print(f"summary: {len(RESULTS) - len(summary['failures'])} passed, "
          f"{len(summary['failures'])} failed, {summary['elapsed_s']}s", flush=True)
    return 1 if summary["failures"] else 0


if __name__ == "__main__":
    sys.exit(main())
