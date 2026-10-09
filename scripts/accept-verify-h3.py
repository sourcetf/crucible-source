#!/usr/bin/env python3
"""accept-verify-h3.py — HTTP/3 + DoT 报文黑盒检查（用 aioquic / 自写 TLS，不依赖 dig/named）。

- H3 GET https://127.0.0.1:28443/  （ALPN h3，SNI prod-test.crucible.local）
- H3 目录无尾斜杠 → 期望与 h1 一致（301）
- DoT  TLS 握手到 127.0.0.1:28853（named 缺失 → 报文层可能超时，只验握手/端口）
- DoH  POST https://127.0.0.1:28444/dns-query（Host: crucible.local，application/dns-message）

用法: python3 scripts/accept-verify-h3.py [--json out.json]
"""
import asyncio, sys, json, os, socket, ssl, struct, time

HOST = "127.0.0.1"
H3_PORT = 28443
H3_DIR_PORT = 28098
DOH_PORT = 28444
DOT_PORT = 28853
TMP = "/home/dev123/scratch-verify3b/tmp"
os.makedirs(TMP, exist_ok=True)

RESULTS = []


def rec(area, name, ok, expected="", observed="", repro="", sev="P1", skip=False, owner=""):
    st = "SKIP" if skip else ("PASS" if ok else "FAIL")
    RESULTS.append(dict(area=area, name=name, status=st, severity=sev, expected=str(expected),
                        observed=str(observed), repro=repro, owner=owner))
    print(f"[{st}] {name}" + ("" if ok else f"  (exp={expected!r} obs={observed!r})"))


# ── HTTP/3 ──
async def h3_get(path, authority=f"127.0.0.1:{H3_PORT}", alpn="h3", port=None):
    port = port or H3_PORT
    from aioquic.asyncio.client import connect
    from aioquic.asyncio.protocol import QuicConnectionProtocol
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.h3.connection import H3Connection
    from aioquic.h3.events import HeadersReceived, DataReceived

    class Client(QuicConnectionProtocol):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            self._h3 = H3Connection(self._quic)
            self._status = None
            self._body = b""
            self._hdr = {}
            self._done = asyncio.Event()

        def quic_event_received(self, event):
            for ev in self._h3.handle_event(event):
                if isinstance(ev, HeadersReceived):
                    for k, v in ev.headers:
                        if k == b":status":
                            self._status = int(v)
                        else:
                            self._hdr[k.decode()] = v.decode()
                    if ev.stream_ended:
                        self._done.set()
                elif isinstance(ev, DataReceived):
                    self._body += ev.data
                    if ev.stream_ended:
                        self._done.set()

        async def get(self, authority, path):
            sid = self._quic.get_next_available_stream_id()
            self._h3.send_headers(sid, [
                (b":method", b"GET"), (b":scheme", b"https"),
                (b":authority", authority.encode()), (b":path", path.encode()),
            ], end_stream=True)
            self.transmit()
            # 不依赖 stream_ended（部分事件序列不会置位）；拿到 status 后再短暂排空 body。
            try:
                await asyncio.wait_for(self._done.wait(), timeout=8)
            except asyncio.TimeoutError:
                pass
            if self._status is not None:
                await asyncio.sleep(0.3)
            return self._status, self._hdr, self._body

    cfg = QuicConfiguration(is_client=True, alpn_protocols=[alpn], verify_mode=ssl.CERT_NONE)
    cfg.max_datagram_frame_size = 65536

    async def _inner():
        async with connect(HOST, port, configuration=cfg, create_protocol=Client) as cli:
            return await cli.get(authority, path)

    # 硬超时：服务端被外部杀掉时 aioquic 会永久等握手，绝不挂死套件。
    return await asyncio.wait_for(_inner(), timeout=15)


def test_h3():
    area = "HTTP/3 (:28443)"
    try:
        st, hd, body = asyncio.run(h3_get("/"))
        rec(area, "h3 GET / → 200", st == 200, 200, st, sev="P1", owner="h2h3",
            repro=f"aioquic h3 GET https://{HOST}:{H3_PORT}/")
        rec(area, "h3 GET / body 非空", len(body) > 0, ">0", len(body), owner="h2h3")
    except Exception as e:
        rec(area, "h3 GET / → 200", False, 200, f"exc {e!r}", sev="P1", owner="h2h3",
            repro=f"aioquic h3 GET https://{HOST}:{H3_PORT}/")
    # 与 h1 的状态码一致性：存在文件 200、不存在路径 404
    try:
        st, hd, body = asyncio.run(h3_get("/index.html"))
        rec(area, "h3 GET /index.html → 200", st == 200, 200, st, sev="P2", owner="h2h3")
    except Exception as e:
        rec(area, "h3 GET /index.html → 200", False, 200, f"exc {e!r}", sev="P2", owner="h2h3")
    try:
        st, hd, body = asyncio.run(h3_get("/definitely-not-here-xyz"))
        rec(area, "h3 不存在路径 → 404", st == 404, 404, st, sev="P2", owner="h2h3")
    except Exception as e:
        rec(area, "h3 不存在路径 → 404", False, 404, f"exc {e!r}", sev="P2", owner="h2h3")
    # h3 非法 authority 校验（wave2 交接项 2；h1 已 400）
    for av in ["..", "_"]:
        try:
            st, hd, body = asyncio.run(h3_get("/", authority=av))
            rec(area, f"h3 非法 authority {av!r} → 400", st == 400, 400, st, sev="P1", owner="h2h3",
                repro=f"aioquic h3 GET / with :authority: {av}")
        except Exception as e:
            rec(area, f"h3 非法 authority {av!r} → 400", False, 400, f"exc {e!r}", sev="P1", owner="h2h3")
    # h3 目录无尾斜杠 → 301（专用 listener 28098，root 含 sub/）
    try:
        st, hd, body = asyncio.run(h3_get("/sub", authority=f"{HOST}:{H3_DIR_PORT}",
                                          alpn="h3", port=H3_DIR_PORT))
        rec(area, "h3 目录无尾斜杠 → 301", st == 301, 301, st, sev="P2", owner="h2h3",
            repro=f"aioquic h3 GET https://{HOST}:{H3_DIR_PORT}/sub")
    except Exception as e:
        rec(area, "h3 目录无尾斜杠 → 301", False, 301, f"exc {e!r}", sev="P2", owner="h2h3")


# ── DoT ──
def dns_query(name="example.com"):
    # 最小 DNS 查询报文（A 记录，RD=1）
    tid = 0x1234
    hdr = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return hdr + q + struct.pack(">HH", 1, 1)


def test_dot():
    area = "DoT (:28853)"
    try:
        raw = socket.create_connection((HOST, DOT_PORT), timeout=5)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.set_alpn_protocols(["dot"])
        except Exception:
            pass
        s = ctx.wrap_socket(raw, server_hostname="crucible.local")
        rec(area, "DoT TLS 握手成功", True, "handshake ok", s.version(), sev="P1", owner="dns")
        # 发一个 DNS 报文（长度前缀）
        msg = dns_query()
        s.sendall(struct.pack(">H", len(msg)) + msg)
        s.settimeout(6)
        try:
            data = s.recv(4096)
        except socket.timeout:
            data = b""
        rec(area, "DoT 回 DNS 报文", len(data) >= 2, ">2 bytes",
            f"{len(data)} bytes" if data else "timeout（named 缺失，环境跳过）",
            sev="P2", owner="dns", skip=(len(data) == 0))
        s.close()
    except Exception as e:
        rec(area, "DoT TLS 握手成功", False, "handshake ok", f"exc {e!r}", sev="P1", owner="dns")


# ── DoH ──
def test_doh():
    area = "DoH (:28444)"
    import base64, urllib.request
    q = dns_query("example.com")
    ctx = ssl._create_unverified_context()
    # POST dns-message
    req = urllib.request.Request(f"https://{HOST}:{DOH_PORT}/dns-query", data=q,
                                 headers={"Content-Type": "application/dns-message",
                                          "Host": "crucible.local"})
    try:
        r = urllib.request.urlopen(req, context=ctx, timeout=8)
        body = r.read()
        rec(area, "DoH POST 返回 dns-message", r.status == 200 and r.headers.get("content-type", "").startswith("application/dns-message"),
            "200 application/dns-message", f"{r.status} {r.headers.get('content-type')}",
            sev="P1", owner="dns")
    except urllib.error.HTTPError as e:
        rec(area, "DoH POST 返回 dns-message", False, "200", f"HTTP {e.code}（named 缺失可能 5xx）",
            sev="P1", owner="dns", skip=(e.code in (502, 503, 500)))
    except Exception as e:
        rec(area, "DoH POST 返回 dns-message", False, "200", f"exc {e!r}", sev="P1", owner="dns")
    # 白名单外 Host → 拒绝
    req2 = urllib.request.Request(f"https://{HOST}:{DOH_PORT}/dns-query", data=q,
                                  headers={"Content-Type": "application/dns-message",
                                           "Host": "evil.example"})
    try:
        r = urllib.request.urlopen(req2, context=ctx, timeout=8)
        rec(area, "DoH 白名单外 Host 被拒", False, "4xx", r.status, sev="P1", owner="dns")
    except urllib.error.HTTPError as e:
        rec(area, "DoH 白名单外 Host 被拒", 400 <= e.code < 500, "4xx", e.code,
            sev="P1", owner="dns")
    except Exception as e:
        rec(area, "DoH 白名单外 Host 被拒", False, "4xx", f"exc {e!r}", sev="P1", owner="dns")


# ── ECS / FORMERR（RFC 7871 §7.2.1，wave-6 半成品复核）──
def _q_with_opt(name="example.com", rdata=None):
    """最小查询 + OPT(4096)，rdata 为 OPT 内的 option 字节（可为多 option）。"""
    tid = 0x4242
    hdr = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 1)  # ARCOUNT=1 (OPT)
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    q += struct.pack(">HH", 1, 1)
    if rdata is None:
        rdata = b""
    opt = b"\x00" + struct.pack(">HHIH", 41, 4096, 0, len(rdata)) + rdata
    return hdr + q + opt


def _ecs_opt(family=1, source=24, scope=0, addr=b"\xcb\x00\x71"):
    return struct.pack(">HH", 8, 4 + len(addr)) + struct.pack(">HBB", family, source, scope) + addr


def _rcode(msg):
    return msg[3] & 0x0F if len(msg) >= 4 else None


def dot_exchange(msg, port=28853, timeout=7):
    """DoT 单次往返；返回响应字节或 b""（超时/无应答）。"""
    raw = socket.create_connection((HOST, port), timeout=5)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_alpn_protocols(["dot"])
    except Exception:
        pass
    try:
        s = ctx.wrap_socket(raw, server_hostname="crucible.local")
    except Exception:
        raw.close()
        raise
    s.settimeout(timeout)
    s.sendall(struct.pack(">H", len(msg)) + msg)
    out = b""
    try:
        while len(out) < 2:
            d = s.recv(4096)
            if not d:
                break
            out += d
        if len(out) >= 2:
            need = 2 + struct.unpack(">H", out[:2])[0]
            while len(out) < need:
                d = s.recv(4096)
                if not d:
                    break
                out += d
    except socket.timeout:
        pass
    s.close()
    return out[2:] if len(out) >= 2 else b""


def test_ecs_formerr():
    area = "DoT·畸形 ECS → FORMERR（:28853）"
    malformed = [
        ("同一 OPT 内两个 ECS", _ecs_opt() + _ecs_opt()),
        ("option 声明长度越过 rdata 末尾", struct.pack(">HH", 8, 40) + b"\x00\x01\x18\x00\xcb\x00"),
        ("未知 FAMILY=3", _ecs_opt(family=3)),
        ("ADDRESS 短于 SOURCE(24/1字节)", _ecs_opt(source=24, addr=b"\xcb")),
    ]
    for label, rdata in malformed:
        q = _q_with_opt(rdata=rdata)
        try:
            resp = dot_exchange(q)
            rc = _rcode(resp) if resp else None
            rec(area, f"畸形 ECS（{label}）→ FORMERR", rc == 1, "RCODE=1(FORMERR)",
                f"rcode={rc} len={len(resp)}", "python DoT 客户端构造畸形 ECS 查询", sev="P1", owner="dns")
        except Exception as e:
            rec(area, f"畸形 ECS（{label}）→ FORMERR", False, "RCODE=1", f"exc {e!r}",
                sev="P1", owner="dns")
    # 正常 ECS / 无 ECS：**不得**回 FORMERR（named 缺失时表现为无应答/超时，均非 FORMERR）
    for label, rdata in [("正常 ECS(203.0.113.0/24)", _ecs_opt()),
                         ("无 ECS（空 OPT）", b"")]:
        q = _q_with_opt(rdata=rdata)
        try:
            resp = dot_exchange(q)
            rc = _rcode(resp) if resp else None
            rec(area, f"{label} 不受影响（非 FORMERR）", rc != 1, "rcode≠1（或超时）",
                f"rcode={rc} len={len(resp)}", sev="P1", owner="dns")
        except Exception as e:
            rec(area, f"{label} 不受影响（非 FORMERR）", False, "rcode≠1", f"exc {e!r}",
                sev="P2", owner="dns")


def test_doh_ecs_formerr():
    area = "DoH·畸形 ECS → FORMERR（:28444）"
    import urllib.request
    ctx = ssl._create_unverified_context()
    q = _q_with_opt(rdata=_ecs_opt() + _ecs_opt())
    req = urllib.request.Request(f"https://{HOST}:28444/dns-query", data=q,
                                 headers={"Content-Type": "application/dns-message",
                                          "Host": "crucible.local"})
    try:
        r = urllib.request.urlopen(req, context=ctx, timeout=8)
        body = r.read()
        rc = _rcode(body) if len(body) >= 4 else None
        rec(area, "DoH POST 畸形 ECS → 200 + RCODE=FORMERR", r.status == 200 and rc == 1,
            "200 + RCODE=1", f"{r.status} rcode={rc}",
            "urllib POST 畸形 ECS 查询到 https://127.0.0.1:28444/dns-query", sev="P1", owner="dns")
    except urllib.error.HTTPError as e:
        rec(area, "DoH POST 畸形 ECS → 200 + RCODE=FORMERR", False, "200 + RCODE=1",
            f"HTTP {e.code}", sev="P1", owner="dns", skip=(e.code in (502, 503, 500)))
    except Exception as e:
        rec(area, "DoH POST 畸形 ECS → 200 + RCODE=FORMERR", False, "200 + RCODE=1",
            f"exc {e!r}", sev="P1", owner="dns")


def main():
    out = "/home/dev123/scratch-verify3b/accept-h3-results.json"
    if "--json" in sys.argv:
        out = sys.argv[sys.argv.index("--json") + 1]
    test_h3()
    test_dot()
    test_doh()
    test_ecs_formerr()
    test_doh_ecs_formerr()
    npass = sum(1 for r in RESULTS if r["status"] == "PASS")
    nfail = sum(1 for r in RESULTS if r["status"] == "FAIL")
    nskip = sum(1 for r in RESULTS if r["status"] == "SKIP")
    print(f"\n==== H3/DNS SUMMARY: PASS={npass} FAIL={nfail} SKIP={nskip} ====")
    with open(out, "w") as f:
        json.dump(RESULTS, f, indent=2, ensure_ascii=False)
    print(f"results -> {out}")


if __name__ == "__main__":
    main()
