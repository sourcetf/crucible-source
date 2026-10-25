#!/usr/bin/env python3
"""DNS 真机验证客户端（供 scripts/dns_verify.sh --real 使用）。

只依赖标准库。子命令：
  build NAME OUT [FAMILY ADDR SOURCE]   生成查询 wire 到文件
  doh HOST PORT CA METHOD NAME [ECS]    发 DoH 查询，打印 JSON {status,ct,rcode,an,ecs}
  dot PORT CA SNI NAME [ECS]            发 DoT 查询，打印 JSON {rcode,an,ecs}
  fake BIND PORT LOG                    伪造 UDP DNS 上游（记录收到的每条 query hex）
  decode LOG                            解析 fake 日志，打印每条查询的 {qname,ecs}

ECS 参数形态：`1:203.0.113:24` 或 `1::0`（family:address:source；地址可为空）。
"""
import base64
import http.client
import json
import socket
import ssl
import struct
import sys
import time


def name_wire(name):
    out = b""
    for lab in name.rstrip(".").split("."):
        if not lab:
            continue
        out += bytes([len(lab)]) + lab.encode()
    return out + b"\x00"


def parse_ecs_arg(s):
    if not s:
        return None
    fam_s, addr_s, src_s = s.split(":")
    fam = int(fam_s)
    src = int(src_s)
    addr = b""
    if addr_s:
        if fam == 1:
            addr = bytes(int(x) for x in addr_s.split("."))
        else:
            addr = socket.inet_pton(socket.AF_INET6, addr_s)
    return (fam, addr, src)


def build_query(name, qtype=1, ecs=None, payload=4096):
    w = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 1)
    w += name_wire(name) + struct.pack("!HH", qtype, 1)
    opts = b""
    if ecs:
        fam, addr, src = ecs
        opts = struct.pack("!HH", 8, 4 + len(addr)) + struct.pack("!HBB", fam, src, 0) + addr
    w += b"\x00" + struct.pack("!HH", 41, payload) + b"\x00\x00\x00\x00"
    w += struct.pack("!H", len(opts)) + opts
    return w


def skipname(m, o):
    while True:
        l = m[o]
        if l & 0xC0 == 0xC0:
            return o + 2
        if l == 0:
            return o + 1
        o += 1 + l


def parse(m):
    r = {
        "id": struct.unpack("!H", m[:2])[0],
        "rcode": m[3] & 0xF,
        "an": struct.unpack("!H", m[6:8])[0],
        "ns": struct.unpack("!H", m[8:10])[0],
        "ar": struct.unpack("!H", m[10:12])[0],
        "ecs": [],
        "qname": None,
    }
    qd = struct.unpack("!H", m[4:6])[0]
    o = 12
    for _ in range(qd):
        n = skipname(m, o)
        if r["qname"] is None:
            r["qname"] = m[o:n].hex()
        o = n + 4
    def rr(off):
        n = skipname(m, off)
        t, cl, ttl, rd = struct.unpack("!HHIH", m[n:n + 10])
        return n + 10 + rd, t, m[n + 10:n + 10 + rd]
    for _ in range(r["an"]):
        o, t, d = rr(o)
        r.setdefault("answers", []).append((t, d.hex()))
    for _ in range(r["ns"]):
        o, _, _ = rr(o)
    for _ in range(r["ar"]):
        n = skipname(m, o)
        t, cl, ttl, rd = struct.unpack("!HHIH", m[n:n + 10])
        data = m[n + 10:n + 10 + rd]
        o = n + 10 + rd
        if t == 41:
            i = 0
            while i + 4 <= len(data):
                code, olen = struct.unpack("!HH", data[i:i + 4])
                val = data[i + 4:i + 4 + olen]
                if code == 8 and len(val) >= 4:
                    fam, src, scope = struct.unpack("!HBB", val[:4])
                    r["ecs"].append({"family": fam, "source": src, "scope": scope,
                                     "address": val[4:].hex()})
                i += 4 + olen
    return r


def _ctx(ca):
    if ca:
        return ssl.create_default_context(cafile=ca)
    ctx = ssl._create_unverified_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def doh(host, port, wire, ca, method, path="/dns-query"):
    ctx = _ctx(ca)
    c = http.client.HTTPSConnection("127.0.0.1", port, context=ctx, timeout=10)
    if method.upper() == "POST":
        c.putrequest("POST", path, skip_host=True)
        c.putheader("Host", host)
        c.putheader("Content-Type", "application/dns-message")
        c.putheader("Content-Length", str(len(wire)))
        c.endheaders(wire)
    else:
        q = base64.urlsafe_b64encode(wire).rstrip(b"=").decode()
        c.putrequest("GET", path + "?dns=" + q, skip_host=True)
        c.putheader("Host", host)
        c.endheaders()
    resp = c.getresponse()
    body = resp.read()
    c.close()
    out = {"status": resp.status,
           "ct": resp.getheader("content-type", ""),
           "cache_control": resp.getheader("cache-control", "")}
    if body and len(body) >= 12:
        out.update(parse(body))
    else:
        out["body"] = body[:120].decode("utf-8", "replace")
    return out


def dot(port, wire, ca, sni):
    ctx = _ctx(ca)
    s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=10),
                        server_hostname=sni)
    s.sendall(struct.pack("!H", len(wire)) + wire)
    hdr = s.recv(2)
    if len(hdr) < 2:
        raise RuntimeError("short DoT length prefix")
    n = struct.unpack("!H", hdr)[0]
    data = b""
    while len(data) < n:
        chunk = s.recv(n - len(data))
        if not chunk:
            break
        data += chunk
    cert = s.getpeercert()
    s.close()
    out = parse(data)
    out["peer_issuer"] = cert.get("issuer") if cert else None
    return out


def fake_server(bind, port, log):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((bind, port))
    with open(log, "a") as f:
        f.write("START %s:%d\n" % (bind, port))
        f.flush()
    while True:
        data, addr = s.recvfrom(65535)
        with open(log, "a") as f:
            f.write(data.hex() + "\n")
            f.flush()
        # 回显 question、AN=0 的 NOERROR 应答（客户端只需要收到合法应答）
        resp = bytearray(data)
        resp[2] |= 0x80
        resp[3] = 0
        resp[6:8] = b"\x00\x00"
        resp[8:10] = b"\x00\x00"
        s.sendto(bytes(resp), addr)


def build_malformed(name, kind):
    """构造畸形 ECS 查询（RFC 7871 §6/§7.2.1 应回 FORMERR）。

    kind:
      family — FAMILY=3（未知族）
      dupe   — 同一 OPT 里两个 ECS
      olen   — ECS option 声明长度 9 但只给 7 字节
    """
    w = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 1)
    w += name_wire(name) + struct.pack("!HH", 1, 1)
    if kind == "family":
        body = struct.pack("!HBB", 3, 24, 0) + bytes([203, 0, 113, 0])
        opts = struct.pack("!HH", 8, len(body)) + body
    elif kind == "dupe":
        body = struct.pack("!HBB", 1, 24, 0) + bytes([203, 0, 113, 0])
        one = struct.pack("!HH", 8, len(body)) + body
        opts = one + one
    elif kind == "olen":
        # 声明 olen=9，实际只有 7 字节（option 越过 OPT rdata 末尾）
        opts = struct.pack("!HH", 8, 9) + struct.pack("!HBB", 1, 24, 0) + bytes([203, 0, 113])
    else:
        raise SystemExit("unknown malformed kind: %s" % kind)
    w += b"\x00" + struct.pack("!HH", 41, 4096) + b"\x00\x00\x00\x00"
    w += struct.pack("!H", len(opts)) + opts
    return w


def main():
    cmd = sys.argv[1]
    if cmd == "build":
        name, out = sys.argv[2], sys.argv[3]
        ecs = parse_ecs_arg(sys.argv[4]) if len(sys.argv) > 4 else None
        open(out, "wb").write(build_query(name, 1, ecs))
        return
    if cmd == "build-malformed":
        name, out, kind = sys.argv[2], sys.argv[3], sys.argv[4]
        open(out, "wb").write(build_malformed(name, kind))
        return
    if cmd == "doh":
        host, port, ca, method, name = sys.argv[2], int(sys.argv[3]), sys.argv[4], sys.argv[5], sys.argv[6]
        ecs = parse_ecs_arg(sys.argv[7]) if len(sys.argv) > 7 else None
        print(json.dumps(doh(host, port, build_query(name, 1, ecs), ca, method)))
        return
    if cmd == "doh-wire":
        host, port, ca, method, path = sys.argv[2], int(sys.argv[3]), sys.argv[4], sys.argv[5], sys.argv[6]
        wire = open(path, "rb").read()
        print(json.dumps(doh(host, port, wire, ca, method)))
        return
    if cmd == "dot":
        port, ca, sni, name = int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5]
        ecs = parse_ecs_arg(sys.argv[6]) if len(sys.argv) > 6 else None
        print(json.dumps(dot(port, build_query(name, 1, ecs), ca, sni)))
        return
    if cmd == "dot-wire":
        port, ca, sni, path = int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5]
        wire = open(path, "rb").read()
        print(json.dumps(dot(port, wire, ca, sni)))
        return
    if cmd == "fake":
        fake_server(sys.argv[2], int(sys.argv[3]), sys.argv[4])
        return
    if cmd == "decode":
        for line in open(sys.argv[2]):
            line = line.strip()
            if not line or line.startswith("START"):
                continue
            r = parse(bytes.fromhex(line))
            print(json.dumps({"qname": r["qname"], "ecs": r["ecs"]}))
        return
    raise SystemExit("usage: build|build-malformed|doh|doh-wire|dot|dot-wire|fake|decode")



if __name__ == "__main__":
    main()
