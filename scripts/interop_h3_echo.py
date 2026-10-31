#!/usr/bin/env python3
"""interop_h3_echo.py — UDP echo / push service used by the CONNECT-UDP (U-06) tests.

Ordinary datagrams are echoed byte-for-byte.  Two control datagrams are special:

    PUSH <n> <size>   send <n> datagrams of <size> bytes, unsolicited, to the sender
    STATS             reply with one JSON datagram of counters

Payloads generated here and by ``interop_h3_udp.py`` must be identical; the
layout is ``seq (u64 BE) || size (u32 BE) || filler`` where filler is
``(i * 31 + 7) & 0xff``.  That lets the client verify integrity and ordering
without keeping 1000 x 32 KiB copies in memory.

Usage:
    python3 scripts/interop_h3_echo.py [--host 127.0.0.1] [--port 9000]
"""
import argparse
import asyncio
import json
import struct
import sys

FILLER = bytes(((i * 31 + 7) & 0xFF) for i in range(65536))


def make_payload(seq: int, size: int) -> bytes:
    """Deterministic payload shared with interop_h3_udp.py (see module docstring)."""
    if size < 12:
        return bytes([(seq + i) & 0xFF for i in range(size)])
    return struct.pack(">QI", seq, size) + FILLER[: size - 12]


class EchoProtocol(asyncio.DatagramProtocol):
    def __init__(self, verbose: bool = False) -> None:
        self.transport = None
        self.verbose = verbose
        self.rx = 0
        self.tx = 0
        self.bytes_rx = 0
        self.bytes_tx = 0
        self.push_tasks = set()

    def connection_made(self, transport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr) -> None:
        self.rx += 1
        self.bytes_rx += len(data)
        if data.startswith(b"PUSH "):
            try:
                _, n_s, size_s = data.split(b" ")[:3]
                n, size = int(n_s), int(size_s)
            except ValueError:
                return
            if 0 < n <= 100_000 and 0 < size <= 65507:
                t = asyncio.create_task(self._push(addr, n, size))
                self.push_tasks.add(t)
                t.add_done_callback(self.push_tasks.discard)
            return
        if data == b"STATS":
            self._send(addr, json.dumps({
                "rx": self.rx, "tx": self.tx,
                "bytes_rx": self.bytes_rx, "bytes_tx": self.bytes_tx,
            }).encode())
            return
        # Echo (the default): integrity is verified by the client.
        self._send(addr, data)

    def _send(self, addr, payload: bytes) -> None:
        try:
            self.transport.sendto(payload, addr)
        except OSError as e:
            if self.verbose:
                print(f"echo: sendto {addr}: {e}", file=sys.stderr)
            return
        self.tx += 1
        self.bytes_tx += len(payload)

    async def _push(self, addr, n: int, size: int) -> None:
        for seq in range(n):
            self._send(addr, make_payload(seq, size))
            # Yield every 16 datagrams so the receive path keeps draining.
            if seq % 16 == 15:
                await asyncio.sleep(0)


async def main_async(host: str, port: int, verbose: bool) -> None:
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: EchoProtocol(verbose), local_addr=(host, port)
    )
    sock = transport.get_extra_info("socket")
    print(f"echo: listening on {host}:{port} (sock={sock.getsockname()})", flush=True)
    try:
        await asyncio.Future()
    finally:
        transport.close()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9000)
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    try:
        asyncio.run(main_async(args.host, args.port, args.verbose))
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
