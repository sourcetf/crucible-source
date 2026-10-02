#!/usr/bin/env python3
"""crucible 外部 DNS 验证工具（只依赖标准库）。

**为什么必须走 TCP/TLS 而不是 UDP**：很多出口网络（含本项目的开发机）会**劫持 UDP/53** ——
向 `192.0.2.1`（TEST-NET-1，保证不可达）发查询也会返回真实 A 记录。所以在那些机器上，
UDP 得到的「外部答案」全部来自本地递归器，与目标服务器无关（= 假证据）。
TCP/53 与 DoT/853 通常不被劫持，所以外部判据一律用这两种传输。

用法：
  python dns_probe.py <server> <qname> <qtype> [rd] [do] [tcp|tls]
    rd=1 置 RD 位（默认 1）；rd=0 = 以「把对方当根服务器」的客户端身份查询
    do=1 置 DO 位（索取 RRSIG）
    tcp=纯 TCP/53；tls=DoT/853（自签证书不校链，只看能否完成交换）
输出含 header flags（qr/aa/rd/ra/ad）与 rcode，用于区分「权威回答 / 转交 / 递归答案 / REFUSED」。

判据速查（把目标当根服务器）：
  . NS rd=0     → 期望 `qr aa` + 13 条根 NS（我们是权威，不是转交）
  com. NS rd=0  → 期望转交：an=0、ns=13、ar=26(glue)
  com. DS rd=0  → 期望 `qr aa` + DS
  外部 google.com A rd=1 → 期望**没有 ra、也没有递归答案**（外部递归关闭）

Minimal external DNS client for verifying the crucible named.

Usage: python _dnsq.py <server> <qname> <qtype> [rd] [dnssec]
  rd     = 1 (default) set RD bit, 0 = clear (query as if we are a root client)
  dnssec = 1 to set DO bit (asks for RRSIG)
Prints dig-like output including header flags, so we can tell an
authoritative answer (aa) from a recursive one (ra) and see REFUSED.
"""
import socket, struct, sys

TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "DS": 43, "RRSIG": 46,
         "DNSKEY": 48, "AAAA": 28, "NSEC": 47}
RTYPES = {v: k for k, v in TYPES.items()}


def enc_name(n):
    n = n.rstrip(".")
    # 根名（"."）是单个 0x00；不能走 split('.') —— 空串 split 出 [""] 会多写一个长度 0 的标签
    # （两个 0x00 ⇒ QTYPE/QCLASS 错位，服务端按格式错处理，看起来像「服务端返回 NOTIMP」）。
    if n == "":
        return b"\x00"
    out = b""
    for lab in n.split("."):
        out += bytes([len(lab)]) + lab.encode()
    return out + b"\x00"


def dec_name(buf, off):
    labels = []
    jumped = False
    end = off
    seen = 0
    while True:
        if off >= len(buf) or seen > 128:
            return "".join(labels), end
        ln = buf[off]
        if ln == 0:
            if not jumped:
                end = off + 1
            break
        if ln & 0xC0 == 0xC0:
            ptr = struct.unpack(">H", buf[off:off + 2])[0] & 0x3FFF
            if not jumped:
                end = off + 2
            jumped = True
            off = ptr
            seen += 1
            continue
        labels.append(buf[off + 1:off + 1 + ln].decode("latin1") + ".")
        off += 1 + ln
    return "".join(labels) or ".", end


def rdata_str(buf, off, rdlen, rtype, full):
    end = off + rdlen
    if rtype == 1 and rdlen == 4:
        return socket.inet_ntoa(buf[off:end])
    if rtype == 28 and rdlen == 16:
        return socket.inet_ntop(socket.AF_INET6, buf[off:end])
    if rtype in (2, 5, 6, 47):
        nm, _ = dec_name(buf, off)
        extra = ""
        if rtype == 6:
            p = buf.index(b"\x00", off) + 1
            extra = " (serial etc. %d bytes)" % (rdlen - (p - off))
        if rtype == 47:
            extra = " [next: %s]" % dec_name(buf, off)[0]
        return nm + extra
    if rtype == 43 and rdlen > 4:
        return "keytag=%d alg=%d digest=%s" % (
            struct.unpack(">H", buf[off:off + 2])[0], buf[off + 2],
            buf[off + 4:end].hex())
    if rtype == 46:
        return "RRSIG(type=%s alg=%d labels=%d ttl=%d exp=%s inception=%s keytag=%d signer=%s)" % (
            RTYPES.get(struct.unpack(">H", buf[off:off + 2])[0], "?"),
            buf[off + 2], buf[off + 3],
            struct.unpack(">I", buf[off + 4:off + 8])[0],
            buf[off + 8:off + 12].hex(), buf[off + 12:off + 16].hex(),
            struct.unpack(">H", buf[off + 16:off + 18])[0],
            dec_name(buf, off + 18)[0])
    return "\\# %d %s" % (rdlen, buf[off:end][:24].hex())


def _recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise EOFError("short read from %s" % (s.getpeername(),))
        buf += chunk
    return buf


def query(server, qname, qtype, rd=True, do=False, timeout=6.0, tcp=False, tls=False):
    qid = 0x2A2A
    flags = 0x0100 if rd else 0x0000
    arcount = 1 if do else 0
    msg = struct.pack(">HHHHHH", qid, flags, 1, 0, 0, arcount)
    msg += enc_name(qname) + struct.pack(">HH", TYPES[qtype], 1)
    if do:
        # OPT RR: root name, type 41, class=udp size, ttl=DO bit
        msg += b"\x00" + struct.pack(">HHIH", 41, 4096, 0x8000, 0)
    if tcp or tls:
        # 本机 UDP/53 被运营商劫持（对 192.0.2.1 也回真答案），TCP/53 通常不被拦，
        # 所以外部视角一律走 TCP。这也顺带验证了 named 的 TCP 监听。
        # tls=True → DNS-over-TLS（853，自签证书 ⇒ 不校验证书链，只看能否完成 DoT 交换）。
        port = 853 if tls else 53
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((server, port))
            if tls:
                import ssl as _ssl
                ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = _ssl.CERT_NONE
                s = ctx.wrap_socket(s, server_hostname="crucible.local")
            s.sendall(struct.pack(">H", len(msg)) + msg)
            hdr = _recv_exact(s, 2)
            data = _recv_exact(s, struct.unpack(">H", hdr)[0])
        finally:
            s.close()
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            s.sendto(msg, (server, 53))
            data, _ = s.recvfrom(4096)
        finally:
            s.close()
    h = struct.unpack(">HHHHHH", data[:12])
    rid, rflags, qd, an, ns, ar = h
    if rid != qid:
        return "BAD ID"
    rcode = rflags & 0xF
    rcodes = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
              4: "NOTIMP", 5: "REFUSED"}
    fl = []
    for bit, nm in ((0x8000, "qr"), (0x0400, "aa"), (0x0200, "tc"),
                    (0x0100, "rd"), (0x0080, "ra"), (0x0020, "ad")):
        if rflags & bit:
            fl.append(nm)
    out = [";; -> %s q=%s %s rd=%d do=%d" % (server, qname, qtype, rd, do),
           ";; flags: %s ; rcode=%s ; counts: an=%d ns=%d ar=%d" % (
               " ".join(fl), rcodes.get(rcode, rcode), an, ns, ar)]
    off = 12
    for _ in range(qd):
        _, off = dec_name(data, off)
        off += 4
    for sec, cnt in (("ANSWER", an), ("AUTHORITY", ns), ("ADDITIONAL", ar)):
        for _ in range(cnt):
            nm, off = dec_name(data, off)
            rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
            off += 10
            if rtype == 41:
                out.append("%s  OPT (edns, rdlen=%d)" % (sec, rdlen))
                off += rdlen
                continue
            out.append("%s  %s %d %s %s %s" % (
                sec, nm, ttl, "IN", RTYPES.get(rtype, "T%d" % rtype),
                rdata_str(data, off, rdlen, rtype, data)))
            off += rdlen
    return "\n".join(out)


if __name__ == "__main__":
    a = sys.argv[1:]
    if len(a) < 3:
        print(__doc__)
        sys.exit(2)
    rd = not (len(a) > 3 and a[3] == "0")
    do = len(a) > 4 and a[4] == "1"
    mode = a[5] if len(a) > 5 else ""
    print(query(a[0], a[1], a[2].upper() if a[2].isalpha() else a[2], rd, do,
                tcp=mode in ("tcp", "tls"), tls=mode == "tls"))