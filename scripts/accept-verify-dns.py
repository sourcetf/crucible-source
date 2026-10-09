#!/usr/bin/env python3
"""accept-verify-dns.py — wave-7 独立复核：DoT/DoH 的 ECS 转发与回显（不依赖本机 named）。

本机没有 `named`（缺 bind9），DoT/DoH 的正常递归路径只会超时。这里在**本进程**起一个
「假 named」UDP 应答器，绑在配置里的 named 端口（默认 29553，即 `dns::port_or_default()`
在该测试配置下的值）：本进程 DoT/DoH 层把查询 forwarding 到它，它回一条最小 A 应答，
并把**收到的查询 wire**（含/不含 ECS）逐条记到 JSON 日志。于是可以做端到端的黑盒判据：

  ecs=true（主配置）：
   1. DoT 查询带 ECS(203.0.113.0/24) → 应答 RCODE=0，且**回带 ECS**（RFC 9112 §7.2.2 语义，
      实为 RFC 7871 §7.2.2），FAMILY=1/SOURCE=24/ADDR=203.0.113.0；
   2. 假 named 侧收到的出站查询**带**该 ECS（未扩长：SOURCE 仍 24、地址截断）；
   3. DoH POST 带 ECS → HTTP 200 + 应答回带 ECS；
   4. 无 ECS 查询 → 假 named 收到按客户端 IP 注入的 ECS(127.0.0.0/24)，但**应答不添加**
      ECS（apply_response_ecs 对无 ECS 查询原样返回）。

  ecs=false（config-verify-ecsoff.toml 独立实例）：
   5. DoT 查询带 ECS → 假 named 收到的出站查询**无** ECS（开关关闭=剥离）；
   6. 应答**无** ECS（不回显，SCOPE=0 的假信息不发出）；
   7. 畸形 ECS 仍回 FORMERR（判定与开关无关，wave-6 行为不回归）。

用法: python3 scripts/accept-verify-dns.py --expect-ecs on|off [--json out.json]
"""
import argparse, asyncio, json, os, socket, ssl, struct, sys, threading, time

HOST = "127.0.0.1"
DOT_PORT = 29853
DOH_PORT = 29444
NAMED_PORT = 29553            # 配置里显式写的 named 端口（genconf: port = 29553）
SCRATCH = "/home/dev123/scratch-verify4"
NAMED_LOG = os.path.join(SCRATCH, "tmp", "fake-named.log")

RESULTS = []


def rec(area, name, ok, expected="", observed="", repro="", sev="P1", skip=False, owner="dns"):
    st = "SKIP" if skip else ("PASS" if ok else "FAIL")
    RESULTS.append(dict(area=area, name=name, status=st, severity=sev, expected=str(expected),
                        observed=str(observed), repro=repro, owner=owner))
    print(f"[{st}] {name}" + ("" if ok else f"  (exp={expected!r} obs={observed!r})"))


# ───────────── DNS wire 工具 ─────────────

def _q_with_opt(name="example.com", rdata=None, txid=0x4242):
    hdr = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 1)
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


def _skip_name(msg, off):
    while True:
        if off >= len(msg):
            return None
        l = msg[off]
        if l & 0xC0 == 0xC0:
            return off + 2
        if l == 0:
            return off + 1
        off += 1 + l


def find_ecs(msg):
    """在报文里找 OPT(41) 的 ECS option；返回 (family, source, scope, addr_bytes) 或 None。"""
    if len(msg) < 12:
        return None
    qd = struct.unpack(">H", msg[4:6])[0]
    off = 12
    for _ in range(qd):
        off = _skip_name(msg, off)
        if off is None:
            return None
        off += 4
    an = struct.unpack(">H", msg[6:8])[0]
    ns = struct.unpack(">H", msg[8:10])[0]
    ar = struct.unpack(">H", msg[10:12])[0]
    for _ in range(an + ns + ar):
        name_end = _skip_name(msg, off)
        if name_end is None or name_end + 10 > len(msg):
            return None
        rtype = struct.unpack(">H", msg[name_end:name_end + 2])[0]
        rdlen = struct.unpack(">H", msg[name_end + 8:name_end + 10])[0]
        rdata_off = name_end + 10
        end = rdata_off + rdlen
        if end > len(msg):
            return None
        if rtype == 41:
            rdata = msg[rdata_off:end]
            i = 0
            while i + 4 <= len(rdata):
                code, olen = struct.unpack(">HH", rdata[i:i + 4])
                if i + 4 + olen > len(rdata):
                    break
                if code == 8 and olen >= 4:
                    body = rdata[i + 4:i + 4 + olen]
                    fam, src, scope = struct.unpack(">HBB", body[:4])
                    return (fam, src, scope, body[4:])
                i += 4 + olen
            return None
        off = end
    return None


def _qname_of(msg):
    off = 12
    parts = []
    while off < len(msg) and msg[off] != 0:
        l = msg[off]
        parts.append(msg[off + 1:off + 1 + l].decode("latin1"))
        off += 1 + l
    return ".".join(parts)


# ───────────── 假 named（UDP 应答 + 记录出站查询） ─────────────

class FakeNamed(threading.Thread):
    def __init__(self, port=NAMED_PORT, logfile=NAMED_LOG):
        super().__init__(daemon=True)
        self.port = port
        self.logfile = logfile
        self._stop = threading.Event()

    def run(self):
        os.makedirs(os.path.dirname(self.logfile), exist_ok=True)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((HOST, self.port))
        except Exception as e:
            print(f"[fake-named] bind failed: {e}")
            return
        s.settimeout(0.5)
        print(f"[fake-named] listening on {HOST}:{self.port}")
        while not self._stop.is_set():
            try:
                data, addr = s.recvfrom(65535)
            except socket.timeout:
                continue
            except Exception:
                break
            try:
                ecs = find_ecs(data)
                with open(self.logfile, "a") as f:
                    f.write(json.dumps({
                        "ts": time.time(), "txid": struct.unpack(">H", data[:2])[0],
                        "qname": _qname_of(data), "size": len(data),
                        "ecs": None if ecs is None else {"family": ecs[0], "source": ecs[1],
                                                         "scope": ecs[2], "addr": ecs[3].hex()},
                    }) + "\n")
                s.sendto(self._response(data), addr)
            except Exception as e:
                print(f"[fake-named] handle error: {e}")
        s.close()

    @staticmethod
    def _response(query):
        txid = query[0:2]
        flags = struct.pack(">H", 0x8180)          # QR=1, RD=1, RA=1, RCODE=0
        off = 12
        while off < len(query) and query[off] != 0:
            off += 1 + query[off]
        qend = min(off + 1 + 4, len(query))
        q = query[12:qend]
        ans = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + bytes([192, 0, 2, 1])
        return txid + flags + struct.pack(">HHHH", 1, 1, 0, 0) + q + ans

    def stop(self):
        self._stop.set()


# ───────────── DoT / DoH 传输 ─────────────

def dot_exchange(msg, timeout=8):
    raw = socket.create_connection((HOST, DOT_PORT), timeout=5)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_alpn_protocols(["dot"])
    except Exception:
        pass
    s = ctx.wrap_socket(raw, server_hostname="crucible.local")
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


def doh_post(msg, host="crucible.local", timeout=8):
    import urllib.request
    ctx = ssl._create_unverified_context()
    req = urllib.request.Request(f"https://{HOST}:{DOH_PORT}/dns-query", data=msg,
                                 headers={"Content-Type": "application/dns-message", "Host": host})
    with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
        return r.status, r.read()


def named_log_tail(n=8):
    try:
        lines = open(NAMED_LOG).read().strip().splitlines()
        return [json.loads(x) for x in lines[-n:]]
    except Exception:
        return []


def wait_named_entry(txid, timeout=4.0):
    t0 = time.time()
    while time.time() - t0 < timeout:
        for e in named_log_tail(20):
            if e.get("txid") == txid:
                return e
        time.sleep(0.1)
    return None


# ───────────── 测试 ─────────────

def test_ecs_on():
    area = "DNS·ECS 转发/回显（DoT/DoH，ecs=true）"
    # 1) DoT 带 ECS：应答 RCODE=0 且回带 ECS（203.0.113.0/24, scope 0）
    txid = 0x5101
    q = _q_with_opt(rdata=_ecs_opt(addr=b"\xcb\x00\x71"), txid=txid)   # 203.0.113.0/24
    resp = dot_exchange(q)
    rc = _rcode(resp) if resp else None
    ecs = find_ecs(resp) if resp else None
    rec(area, "DoT+ECS：收到 RCODE=0 应答（假 named 转发生效）", rc == 0, "RCODE=0",
        f"rcode={rc} len={len(resp)}", "python DoT 客户端 + 假 named on :29553", sev="P1")
    ok_echo = (ecs is not None and ecs[0] == 1 and ecs[1] == 24 and ecs[2] == 0
               and ecs[3] == b"\xcb\x00\x71")
    rec(area, "DoT+ECS：应答回带 ECS(203.0.113.0/24,SCOPE=0)（RFC 7871 §7.2.2）",
        ok_echo, "family=1 source=24 scope=0 addr=cb0071(/24=3 字节)",
        f"ecs={ecs}", sev="P1")
    # 2) 出站（本进程 → named）带着该 ECS（未扩长）
    ent = wait_named_entry(txid)
    upstream_ecs = (ent or {}).get("ecs")
    rec(area, "出站到 named 的查询带 ECS(203.0.113.0/24)（不扩长客户端前缀）",
        upstream_ecs is not None and upstream_ecs.get("source") == 24
        and upstream_ecs.get("addr", "").startswith("cb0071"),
        "ECS source=24 addr=cb0071..", f"{upstream_ecs}", sev="P1")
    # 3) DoH 带 ECS：200 + 回带 ECS
    try:
        st, body = doh_post(_q_with_opt(rdata=_ecs_opt(addr=b"\xcb\x00\x71"), txid=0x5102))
        ecs2 = find_ecs(body)
        rec(area, "DoH+ECS：HTTP 200 + 应答回带 ECS", st == 200 and ecs2 is not None
            and ecs2[0] == 1 and ecs2[1] == 24,
            "200 + ECS family=1 source=24", f"{st} ecs={ecs2}", sev="P1")
    except Exception as e:
        rec(area, "DoH+ECS：HTTP 200 + 应答回带 ECS", False, "200 + ECS", f"exc {e!r}", sev="P1")
    # 4) 无 ECS 查询：出站被注入按客户端 IP 的 ECS，但**应答不加** ECS
    txid = 0x5103
    q = _q_with_opt(rdata=b"", txid=txid)
    resp = dot_exchange(q)
    rc = _rcode(resp) if resp else None
    ecs = find_ecs(resp) if resp else None
    ent = wait_named_entry(txid)
    inj = (ent or {}).get("ecs")
    rec(area, "无 ECS 查询：出站按客户端 IP 注入 ECS(127.0.0.0/24)",
        inj is not None and inj.get("source") == 24 and inj.get("addr") == "7f0000",
        "127.0.0.0/24（/24=3 字节 7f0000）", f"{inj}", sev="P2")
    rec(area, "无 ECS 查询：应答**不添加** ECS（不误加 option）", rc == 0 and ecs is None,
        "RCODE=0 且无 ECS", f"rcode={rc} ecs={ecs}", sev="P2")


def test_ecs_off():
    area = "DNS·ECS 关闭（ecs=false，DoT）"
    # 5/6) 带 ECS 的查询：出站被剥离、应答不回显
    txid = 0x5201
    q = _q_with_opt(rdata=_ecs_opt(addr=b"\xcb\x00\x71"), txid=txid)
    resp = dot_exchange(q)
    rc = _rcode(resp) if resp else None
    ecs = find_ecs(resp) if resp else None
    ent = wait_named_entry(txid)
    out_ecs = (ent or {}).get("ecs")
    rec(area, "ecs=false：出站到 named 的查询**无 ECS**（剥离客户端 option）",
        ent is not None and out_ecs is None, "named 侧无 ECS",
        f"named={ent}", sev="P1")
    rec(area, "ecs=false：应答**不回显** ECS", rc == 0 and ecs is None,
        "RCODE=0 且无 ECS option", f"rcode={rc} ecs={ecs}", sev="P1")
    # 7) 畸形 ECS 仍 FORMERR（判定不看 cfg.ecs）
    q = _q_with_opt(rdata=_ecs_opt() + _ecs_opt(), txid=0x5202)
    resp = dot_exchange(q)
    rc = _rcode(resp) if resp else None
    rec(area, "ecs=false：畸形 ECS 仍回 FORMERR（判定与开关无关）", rc == 1,
        "RCODE=1", f"rcode={rc}", sev="P1")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--expect-ecs", choices=["on", "off"], default="on")
    ap.add_argument("--json", default=None)
    args = ap.parse_args()
    out = args.json or os.path.join(SCRATCH, f"accept-dns-results-{args.expect_ecs}.json")

    fn = FakeNamed()
    fn.start()
    time.sleep(0.3)

    # 趟前探活：实例必须活着（DoT 端口可连），否则整体标记失败而不是挂死
    try:
        socket.create_connection((HOST, DOT_PORT), timeout=3).close()
    except Exception as e:
        rec("DNS·ECS", "DoT 端口可连（实例活着）", False, "connect", f"exc {e!r}", sev="P1")
        fn.stop()
    else:
        try:
            if args.expect_ecs == "on":
                test_ecs_on()
            else:
                test_ecs_off()
        finally:
            fn.stop()

    npass = sum(1 for r in RESULTS if r["status"] == "PASS")
    nfail = sum(1 for r in RESULTS if r["status"] == "FAIL")
    nskip = sum(1 for r in RESULTS if r["status"] == "SKIP")
    print(f"\n==== DNS/ECS SUMMARY ({args.expect_ecs}): PASS={npass} FAIL={nfail} SKIP={nskip} ====")
    with open(out, "w") as f:
        json.dump(RESULTS, f, indent=2, ensure_ascii=False)
    print(f"results -> {out}")
    sys.exit(1 if nfail else 0)


if __name__ == "__main__":
    main()
