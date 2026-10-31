#!/usr/bin/env python3
"""interop_h3_http.py — aioquic HTTP/3 baseline client for U-11 comparisons.

Runs N GET requests at a given concurrency over one or more QUIC connections,
optionally verifying the body SHA-256 (large-file integrity), and prints
machine-readable JSON.

Usage:
    python3 scripts/interop_h3_http.py --port 27143 --paths / --n 1
    python3 scripts/interop_h3_http.py --port 27143 --paths /blob-8m.bin \
        --n 4 --c 2 --expect-sha256 <hex> --json out.json
"""
import argparse
import asyncio
import hashlib
import json
import ssl
import sys
import time

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated, StreamDataReceived, StreamReset


class HttpClient(QuicConnectionProtocol):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.h3 = H3Connection(self._quic)
        self.queues = {}

    def quic_event_received(self, event):
        if isinstance(event, StreamDataReceived):
            q = self.queues.get(event.stream_id)
            if q is None:
                return
            try:
                evs = self.h3.handle_event(event)
            except Exception as e:  # noqa: BLE001
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

    async def request(self, authority, path, timeout=60.0):
        sid = self._quic.get_next_available_stream_id()
        q = asyncio.Queue()
        self.queues[sid] = q
        self.h3.send_headers(sid, [
            (b":method", b"GET"), (b":scheme", b"https"),
            (b":authority", authority.encode()), (b":path", path.encode()),
        ], end_stream=True)
        self.transmit()
        status = None
        headers = {}
        body = bytearray()
        deadline = time.monotonic() + timeout
        t0 = time.monotonic()
        try:
            while True:
                left = deadline - time.monotonic()
                if left <= 0:
                    raise TimeoutError(f"request {path} timed out")
                ev = await asyncio.wait_for(q.get(), timeout=left)
                if ev[0] == "headers":
                    for k, v in ev[1]:
                        if k == b":status":
                            status = int(v)
                        else:
                            headers.setdefault(k.decode(), v.decode())
                elif ev[0] == "data":
                    body += ev[1]
                elif ev[0] == "fin":
                    break
                elif ev[0] == "reset":
                    raise RuntimeError(f"stream reset 0x{ev[1]:x}")
                elif ev[0] == "conn_close":
                    raise ConnectionError(f"connection closed 0x{ev[1]:x}")
                elif ev[0] == "error":
                    raise RuntimeError(ev[1])
        finally:
            self.queues.pop(sid, None)
        return status, headers, bytes(body), time.monotonic() - t0


def pct(vals, p):
    if not vals:
        return None
    s = sorted(vals)
    return s[min(len(s) - 1, int(round((p / 100.0) * (len(s) - 1))))]


async def run(args):
    paths = args.paths.split(",")
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"],
                            verify_mode=ssl.CERT_NONE)
    cfg.max_datagram_frame_size = None
    authority = f"127.0.0.1:{args.port}"
    sem = asyncio.Semaphore(args.c)
    results = []

    clients = []
    for _ in range(args.connections):
        ctx = connect("127.0.0.1", args.port, configuration=cfg,
                      create_protocol=HttpClient)
        cli = await ctx.__aenter__()
        clients.append((ctx, cli))
    try:
        async def one(i):
            async with sem:
                path = paths[i % len(paths)]
                ctx, cli = clients[i % len(clients)]
                try:
                    st, hdrs, body, dt = await cli.request(authority, path)
                    sha = hashlib.sha256(body).hexdigest()
                    ok = st == 200 and (not args.expect_sha256
                                        or sha == args.expect_sha256)
                    return {"i": i, "path": path, "status": st,
                            "bytes": len(body), "sha256": sha,
                            "elapsed_ms": round(dt * 1000, 3),
                            "ok": ok, "error": None,
                            "headers": hdrs if i == 0 else None}
                except Exception as e:  # noqa: BLE001
                    return {"i": i, "path": path, "status": None, "bytes": 0,
                            "sha256": None, "elapsed_ms": None, "ok": False,
                            "error": repr(e), "headers": None}

        t0 = time.monotonic()
        results = await asyncio.gather(*(one(i) for i in range(args.n)))
        wall = time.monotonic() - t0
    finally:
        for ctx, cli in clients:
            try:
                await ctx.__aexit__(None, None, None)
            except Exception:
                pass

    lat = [r["elapsed_ms"] for r in results if r["ok"]]
    total_bytes = sum(r["bytes"] for r in results if r["ok"])
    summary = {
        "client": "aioquic",
        "aioquic_version": __import__("aioquic").__version__,
        "authority": authority,
        "paths": paths,
        "requests": args.n,
        "concurrency": args.c,
        "connections": args.connections,
        "failures": [r for r in results if not r["ok"]],
        "wall_s": round(wall, 3),
        "throughput_mib_s": round(total_bytes / wall / 1048576, 2) if wall else None,
        "latency_ms": {
            "min": round(min(lat), 3) if lat else None,
            "p50": round(pct(lat, 50), 3) if lat else None,
            "p95": round(pct(lat, 95), 3) if lat else None,
            "max": round(max(lat), 3) if lat else None,
        },
        "bytes_ok": total_bytes,
        "results": results,
    }
    return summary


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=27143)
    ap.add_argument("--paths", default="/")
    ap.add_argument("--n", type=int, default=1)
    ap.add_argument("--c", type=int, default=1)
    ap.add_argument("--connections", type=int, default=1)
    ap.add_argument("--expect-sha256", default="")
    ap.add_argument("--json", default="")
    args = ap.parse_args()
    try:
        summary = asyncio.run(asyncio.wait_for(run(args), 300))
    except Exception as e:  # noqa: BLE001
        summary = {"client": "aioquic", "fatal": repr(e), "failures": [{"error": repr(e)}]}
    if args.json:
        with open(args.json, "w") as f:
            json.dump(summary, f, indent=2, default=str)
    print(json.dumps({k: v for k, v in summary.items() if k != "results"},
                     indent=2, default=str))
    bad = summary.get("failures") or summary.get("fatal")
    if bad:
        print(f"FAIL: {bad}")
        return 1
    print(f"PASS: {summary['requests']} requests, {summary['bytes_ok']} bytes, "
          f"p50={summary['latency_ms']['p50']}ms")
    return 0


if __name__ == "__main__":
    sys.exit(main())
