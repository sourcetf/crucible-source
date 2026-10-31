#!/usr/bin/env python3
"""生成 fuzz corpus 种子（确定性，可重复运行）。

来源三类：
1. `scripts/accept-verify*.py|sh` 里真实黑盒套件使用的请求字节（HTTP/1.x 原文）；
2. 协议边界手工样本（超长头/裸 LF/非法 UTF-8/深嵌套 qmux/畸形 ECS…）；
3. 生产模块单测与报告中点名的形状。

用法：python3 fuzz/gen_corpus.py   # 写入 fuzz/corpus/<target>/<name>
"""
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.environ.get("FUZZ_CORPUS_DIR", os.path.join(HERE, "corpus"))


def write(target, name, data):
    d = os.path.join(CORPUS, target)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, name), "wb") as f:
        f.write(data)


# ---------------------------------------------------------------- h1fast ----

def h1fast():
    T = "h1fast"
    # —— 真实套件请求字节（accept-verify.py / -ext.py）——
    write(T, "real_get_10", b"GET / HTTP/1.0\r\n\r\n")
    write(T, "real_get_11_nohost", b"GET / HTTP/1.1\r\n\r\n")
    write(T, "real_get_11", b"GET / HTTP/1.1\r\nHost: 127.0.0.1:30081\r\n\r\n")
    write(T, "real_get_index_close",
          b"GET /index.html HTTP/1.1\r\nHost: 127.0.0.1:30081\r\nConnection: close\r\n\r\n")
    write(T, "real_head_index",
          b"HEAD /index.html HTTP/1.1\r\nHost: 127.0.0.1:30081\r\n\r\n")
    write(T, "real_range",
          b"GET /index.html HTTP/1.1\r\nHost: 127.0.0.1:30081\r\nRange: bytes=0-4\r\n\r\n")
    write(T, "real_if_none_match",
          b"GET /index.html HTTP/1.1\r\nHost: 127.0.0.1:30081\r\n"
          b'If-None-Match: "abc"\r\n\r\n')
    write(T, "real_get_big",
          b"GET /big.bin HTTP/1.1\r\nHost: 127.0.0.1:30081\r\nConnection: close\r\n\r\n")
    write(T, "real_put_cl",
          b"PUT /up-x.txt HTTP/1.1\r\nHost: 127.0.0.1:30094\r\n"
          b"Content-Length: 100\r\n\r\nabc")
    write(T, "real_put_chunked",
          b"PUT /chunked-trailer.txt HTTP/1.1\r\nHost: 127.0.0.1:30094\r\n"
          b"Transfer-Encoding: chunked\r\nTrailer: X-Sum\r\n\r\n0\r\nX-Sum: 0\r\n\r\n")
    write(T, "real_expect100",
          b"PUT /expect100.txt HTTP/1.1\r\nHost: 127.0.0.1:30094\r\n"
          b"Content-Length: 5\r\nExpect: 100-continue\r\n\r\nhello")
    write(T, "real_ws_upgrade",
          b"GET /ws HTTP/1.1\r\nHost: 127.0.0.1:30093\r\n"
          b"Upgrade: websocket\r\nConnection: Upgrade\r\n"
          b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
          b"Sec-WebSocket-Version: 13\r\n\r\n")
    write(T, "real_h2_preface",
          b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + b"\x00\x00\x00\x04\x00\x00\x00\x00\x00")
    write(T, "real_host_dotdot",
          b"GET / HTTP/1.1\r\nHost: ..\r\nConnection: close\r\n\r\n")
    write(T, "real_host_underscore",
          b"GET / HTTP/1.1\r\nHost: _\r\nConnection: close\r\n\r\n")
    # 上传/静态路径穿越形状（h1 解析层只做合法性判断）
    write(T, "real_path_traversal",
          b"GET /../../etc/passwd HTTP/1.1\r\nHost: 127.0.0.1:30081\r\n\r\n")
    write(T, "real_path_pct_traversal",
          b"GET /..%2f..%2fetc%2fpasswd HTTP/1.1\r\nHost: 127.0.0.1:30081\r\n\r\n")

    # —— 边界样本 ——
    write(T, "edge_empty", b"")
    write(T, "edge_crlfcrlf", b"\r\n\r\n")
    write(T, "edge_get_11_extra_spaces",
          b"GET  / HTTP/1.1\r\nHost: h\r\n\r\n")
    write(T, "edge_lower_method", b"get / HTTP/1.1\r\nHost: h\r\n\r\n")
    write(T, "edge_delete", b"DELETE /a HTTP/1.1\r\nHost: h\r\n\r\n")
    write(T, "edge_post_cl", b"POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\n\r\n")
    write(T, "edge_connect", b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n")
    write(T, "edge_options_star", b"OPTIONS * HTTP/1.1\r\nHost: h\r\n\r\n")
    write(T, "edge_abs_form", b"GET http://example.com/a HTTP/1.1\r\nHost: example.com\r\n\r\n")
    write(T, "edge_http12", b"GET / HTTP/1.2\r\nHost: h\r\n\r\n")
    write(T, "edge_http09", b"GET /\r\n\r\n")
    write(T, "edge_target_hash", b"GET /a#b HTTP/1.1\r\nHost: h\r\n\r\n")
    write(T, "edge_target_space", b"GET /a b HTTP/1.1\r\nHost: h\r\n\r\n")
    write(T, "edge_target_query", b"GET /a?b=c&d HTTP/1.1\r\nHost: h\r\n\r\n")
    write(T, "edge_target_pct", b"GET /a%2e%2e%2f.env HTTP/1.1\r\nHost: h\r\n\r\n")
    write(T, "edge_target_utf8", "GET /报告.pdf HTTP/1.1\r\nHost: h\r\n\r\n".encode())
    write(T, "edge_target_8192", b"GET /" + b"a" * 8190 + b" HTTP/1.1\r\nHost: h\r\n\r\n")
    write(T, "edge_host_empty", b"GET / HTTP/1.1\r\nHost: \r\n\r\n")
    write(T, "edge_host_dup", b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n")
    write(T, "edge_host_ipv6", b"GET / HTTP/1.1\r\nHost: [::1]:8080\r\n\r\n")
    write(T, "edge_host_space_colon", b"GET / HTTP/1.1\r\nHost : h\r\n\r\n")
    write(T, "edge_host_tab_value", b"GET / HTTP/1.1\r\nHost:\th\r\n\r\n")
    write(T, "edge_obs_fold", b"GET / HTTP/1.1\r\nHost: h\r\nX: a\r\n b\r\n\r\n")
    write(T, "edge_bare_lf", b"GET / HTTP/1.1\nHost: h\n\n")
    write(T, "edge_bare_lf_mixed", b"GET / HTTP/1.1\r\nHost: h\nX: y\r\n\r\n")
    write(T, "edge_leading_crlf", b"\r\nGET / HTTP/1.1\r\nHost: h\r\n\r\n")
    write(T, "edge_trailing_garbage", b"GET / HTTP/1.1\r\nHost: h\r\n\r\nXYZ")
    write(T, "edge_pipelined",
          b"GET /a HTTP/1.1\r\nHost: h\r\n\r\nGET /b HTTP/1.1\r\nHost: h\r\n\r\n")
    write(T, "edge_chunked_te",
          b"GET /a HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n")
    write(T, "edge_te_and_cl",
          b"GET /a HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n"
          b"Transfer-Encoding: chunked\r\n\r\n")
    write(T, "edge_conn_tokens",
          b"GET /a HTTP/1.1\r\nHost: h\r\nConnection: foo, close, bar\r\n\r\n")
    write(T, "edge_conn_high_byte",
          b"GET /a HTTP/1.1\r\nHost: h\r\nConnection: \xff, close\r\n\r\n")
    write(T, "edge_value_nul", b"GET /a HTTP/1.1\r\nHost: h\r\nX: a\x00b\r\n\r\n")
    write(T, "edge_value_high_utf8", b"GET /a HTTP/1.1\r\nHost: h\r\nX: \xff\xfe\r\n\r\n")
    write(T, "edge_header_no_colon", b"GET /a HTTP/1.1\r\nHost: h\r\nBroken\r\n\r\n")
    write(T, "edge_header_empty_name", b"GET /a HTTP/1.1\r\nHost: h\r\n: v\r\n\r\n")
    write(T, "edge_header_16k",
          b"GET / HTTP/1.1\r\nHost: h\r\nX: " + b"a" * 16000 + b"\r\n\r\n")
    write(T, "edge_header_16k_plus",
          b"GET / HTTP/1.1\r\nHost: h\r\nX: " + b"a" * 17000 + b"\r\n\r\n")
    write(T, "edge_headers_120",
          b"GET / HTTP/1.1\r\nHost: h\r\n" + b"".join(
              b"X-%d: v\r\n" % i for i in range(120)) + b"\r\n")
    write(T, "edge_slow_crlf", b"GET / HTTP/1.1\r\n" + b"X: v\r\n" * 50)
    write(T, "edge_high_bytes_head", b"\xff\xfe\x00GET / HTTP/1.1\r\nHost: h\r\n\r\n")


# ------------------------------------------------------------ upload_path ----
def upload_path():
    T = "upload_path"
    raw = [
        "plain.txt",                    # 不含前导 /
        "/up/plain.txt",
        "/up",                          # allows_path 边界：命中
        "/upload",                      # 边界：不命中
        "/upfoo",                       # 边界：不命中
        "/up/",
        "/up//x",
        "/./up/x",
        "/up/../.env",                  # dotdot（先于 hidden）
        "/up/%2e%2e/.env",              # 百分号编码的 ..
        "/up/%252e%252e%252f.env",      # 双重编码
        "/up/a%2520b.txt",              # 双重编码（字面 %20）
        "/up/100%25.txt",               # 合法单次编码
        "/up/shell.php",                # exec-ext
        "/up/shell.ph%70",              # 编码后 exec-ext
        "/up/x.cgi", "/up/x.pl", "/up/x.py", "/up/x.sh", "/up/x.jspx",
        "/up/.env",                     # hidden
        "/up/.git/hooks/pre-commit",
        "/up/.well-known/acme-challenge/tok",   # 允许
        "/up/...",                      # 隐藏段（以 . 开头）
        ".env",
        "%2eenv",
        "/up/a%00b",                    # NUL（decode 后）
        "/up/a%00%00%00",
        "/up/a b.txt",                  # 空格
        "/up/%20space.txt",
        "/up/%E6%8A%A5%E5%91%8A.pdf",   # 合法 UTF-8
        "/up/%ff%fe.bin",               # 非法 UTF-8
        "up/alias",                     # 符号链接别名
        "/up/alias",
        "up\\..\\..\\etc\\passwd",      # 反斜杠
        "/up\\x",
        "C:\\windows\\system32\\cmd.exe",
        "//etc/passwd",
        "/up/" + "a" * 5000,
        "/up/" + "../" * 300 + "etc/passwd",
        "",
        "/",
        "/up/%2Fetc%2Fpasswd",          # 编码的 /
        "/up/x%2e%2e%2f.env",
    ]
    for i, p in enumerate(raw):
        write(T, "path_%02d" % i, p.encode("utf-8", "surrogateescape"))
    # 任意二进制：模拟「不是合法 URL 路径」的输入（解码后含替换字符）
    write(T, "bin_random", bytes(range(256)))
    write(T, "bin_mix", b"/up/\xff\xfe\x00/../.env")


# ---------------------------------------------------------------- dns_wire ---
def _qname(name):
    out = b""
    for label in name.split("."):
        if label:
            out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def dns_header(id_, flags=0x0100, qd=1, an=0, ns=0, ar=0):
    return struct.pack(">HHHHHH", id_, flags, qd, an, ns, ar)


def question(name="example.com", qtype=1, qclass=1):
    return _qname(name) + struct.pack(">HH", qtype, qclass)


def opt_rr(rdata, payload=4096, ttl=b"\x00\x00\x00\x00"):
    return b"\x00" + struct.pack(">HH", 41, payload) + ttl + struct.pack(">H", len(rdata)) + rdata


def ecs_opt(subnet, family=1, source=24, scope=0):
    body = struct.pack(">HBB", family, source, scope) + subnet
    return struct.pack(">HH", 8, len(body)) + body


def a_response(query, answers=None):
    """把查询原样当问题段，构造 QR=1 的应答。"""
    q = query[12:]
    an = answers or []
    rrs = b"".join(
        b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 300, 4) + bytes(a) for a in an
    )
    return dns_header(0x1234, 0x8180, 1, len(an), 0, 0) + q + rrs


def with_split(query, response):
    """dns_wire 用前两字节当切分点：写入 b'\\x00'+len(query) 使 split == len(query)。"""
    if len(query) > 255:
        return b"\x00\xff" + query + response
    return b"\x00" + bytes([len(query)]) + query + response


def dns_wire():
    T = "dns_wire"
    q_plain = dns_header(0x1234) + question()
    q_a = dns_header(0xbeef, 0x0120) + question("www.example.org", 1, 1)  # AD bit
    q_opt = (dns_header(0x2222, 0x0100, 1, 0, 0, 1) + question()
             + opt_rr(b"\x00\x0a\x00\x04\xde\xad\xbe\xef"))  # COOKIE
    q_ecs = (dns_header(0x3333, 0x0100, 1, 0, 0, 1) + question()
             + opt_rr(ecs_opt(b"\xc0\x00\x02")))
    q_ecs_v6 = (dns_header(0x4444, 0x0100, 1, 0, 0, 1) + question()
                + opt_rr(ecs_opt(b"\x20\x01\x0d\xb8" + b"\x00" * 3, family=2, source=56)))
    q_ecs_src0 = (dns_header(0x5555, 0x0100, 1, 0, 0, 1) + question()
                  + opt_rr(ecs_opt(b"\x00\x00\x00", source=0)))
    q_ecs_src0_addr = (dns_header(0x5556, 0x0100, 1, 0, 0, 1) + question()
                       + opt_rr(ecs_opt(b"\xc0\x00\x02", source=0)))
    q_bad_family = (dns_header(0x6666, 0x0100, 1, 0, 0, 1) + question()
                    + opt_rr(ecs_opt(b"\xc0\x00\x02", family=3)))
    q_bad_src33 = (dns_header(0x6667, 0x0100, 1, 0, 0, 1) + question()
                   + opt_rr(ecs_opt(b"\xc0\x00\x02\x00\x00", source=33)))
    q_bad_addr_short = (dns_header(0x6668, 0x0100, 1, 0, 0, 1) + question()
                        + opt_rr(ecs_opt(b"\xc0", source=24)))
    q_bad_tail_bits = (dns_header(0x6669, 0x0100, 1, 0, 0, 1) + question()
                       + opt_rr(ecs_opt(b"\xc0\x00\x02\xff", source=24)))
    q_dup_ecs = (dns_header(0x7777, 0x0100, 1, 0, 0, 1) + question()
                 + opt_rr(ecs_opt(b"\xc0\x00\x02") + ecs_opt(b"\xcb\x00\x71\x09")))
    # option 声明长度越过 rdata 末尾（tail 非空）
    q_olen_overflow = (dns_header(0x7778, 0x0100, 1, 0, 0, 1) + question()
                       + opt_rr(b"\x00\x08\x00\x20\x00\x01\x18\x00\xc0\x00\x02"))
    # OPT rdata 只剩 1~3 字节（凑不满 option 头）
    q_opt_tail = (dns_header(0x7779, 0x0100, 1, 0, 0, 1) + question()
                  + opt_rr(b"\x00\x08\x00"))
    # 问题段截断
    q_trunc_qname = dns_header(0x8888) + b"\x07exam"
    q_trunc_qtype = dns_header(0x8889) + _qname("a.example") + b"\x00"
    # QDCOUNT=2
    q_two = (dns_header(0x9999, 0x0100, 2) + question("a.example")
             + question("b.example", 28, 1))
    # QDCOUNT 声称 100 但只给一条
    q_qd_huge = dns_header(0x9a9a, 0x0100, 100) + question()
    # 压缩指针问题名
    q_ptr = dns_header(0xaaaa) + b"\xc0\x0c" + struct.pack(">HH", 1, 1)
    # 0 长度 OPT rdata
    q_opt_empty = (dns_header(0xbbbb, 0x0100, 1, 0, 0, 1) + question()
                   + opt_rr(b""))
    # OPT 在应答段之外带 padding option
    q_opt_pad = (dns_header(0xbbbc, 0x0100, 1, 0, 0, 1) + question()
                 + opt_rr(b"\x00\x0c\x00\x04abcd" + ecs_opt(b"\xc0\x00\x02")))
    # ARCOUNT 声称 1 但 OPT 不存在 / OPT 记录被截断
    q_ar_no_opt = dns_header(0xbbbd, 0x0100, 1, 0, 0, 1) + question()
    q_opt_trunc = (dns_header(0xbbbe, 0x0100, 1, 0, 0, 1) + question()
                   + b"\x00\x00\x29\x10\x00\x00\x00")
    # 两条 OPT RR（RFC 6891 §6.1.1 MUST FORMERR）—— 第一条 RDLEN 合法。
    q_two_opt = (dns_header(0xbbbf, 0x0100, 1, 0, 0, 2) + question()
                 + opt_rr(ecs_opt(b"\xc0\x00\x02")) + opt_rr(b""))
    # OPT RR 头完整、但 RDLEN 越过报文末尾（RDATA 截断）。
    q_opt_rdlen_trunc = (dns_header(0xbbc0, 0x0100, 1, 0, 0, 1) + question()
                         + b"\x00\x00\x29\x10\x00\x00\x00\x00\x00\x28"
                         + b"\x00\x08\x00\x03\x01\x18\x00")
    # 应答
    r_plain = a_response(q_plain, [[192, 0, 2, 1]])
    r_nx = dns_header(0x1234, 0x8183) + q_plain[12:]
    r_echo_ecs = (dns_header(0x1234, 0x8180, 1, 1, 0, 1) + q_plain[12:]
                  + b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 300, 4) + b"\xc0\x00\x02\x01"
                  + opt_rr(ecs_opt(b"\xc0\x00\x02")))
    r_ecs_no_q = dns_header(0x1234, 0x8180) + question() + opt_rr(ecs_opt(b"\xcb\x00\x71\x09"))
    r_other_opt = (dns_header(0x1234, 0x8180, 1, 0, 0, 1) + q_plain[12:]
                   + opt_rr(b"\x00\x0a\x00\x04\xde\xad\xbe\xef"))

    pairs = [
        ("plain", q_plain, r_plain),
        ("plain_nx", q_plain, r_nx),
        ("opt_cookie", q_opt, r_other_opt),
        ("ecs_inject", q_ecs, r_plain),
        ("ecs_echo", q_ecs, r_echo_ecs),
        ("ecs_v6", q_ecs_v6, r_plain),
        ("ecs_src0", q_ecs_src0, r_plain),
        ("ecs_src0_addr", q_ecs_src0_addr, r_plain),
        ("bad_family", q_bad_family, r_plain),
        ("bad_src33", q_bad_src33, r_plain),
        ("bad_addr_short", q_bad_addr_short, r_plain),
        ("bad_tail_bits", q_bad_tail_bits, r_plain),
        ("dup_ecs", q_dup_ecs, r_plain),
        ("olen_overflow", q_olen_overflow, r_plain),
        ("opt_tail", q_opt_tail, r_plain),
        ("qname_trunc", q_trunc_qname, r_plain),
        ("qtype_trunc", q_trunc_qtype, r_plain),
        ("qdcount2", q_two, a_response(q_two, [[192, 0, 2, 2]])),
        ("qdcount_huge", q_qd_huge, r_plain),
        ("ptr_qname", q_ptr, r_plain),
        ("opt_empty", q_opt_empty, r_plain),
        ("opt_pad", q_opt_pad, r_plain),
        ("ar_no_opt", q_ar_no_opt, r_plain),
        ("opt_trunc", q_opt_trunc, r_plain),
        ("two_opt", q_two_opt, r_plain),
        ("opt_rdlen_trunc", q_opt_rdlen_trunc, r_plain),
        ("resp_ecs_no_q", q_plain, r_ecs_no_q),
        ("self_apply", q_ecs, q_ecs),
    ]
    for name, q, r in pairs:
        write(T, name, with_split(q, r))
    # 纯应答/纯查询（切分点 0 或 末尾）
    write(T, "query_only", b"\x00\x00" + q_ecs)
    write(T, "response_only", b"\x00\x00" + r_echo_ecs)
    # 任意二进制
    write(T, "bin_small", bytes(range(64)))
    write(T, "bin_ff", b"\xff" * 64)
    write(T, "bin_rand", bytes((i * 37 + 11) & 0xFF for i in range(256)))


# -------------------------------------------------------------- qmux_proto --
def vint(v):
    if v < 64:
        return bytes([v])
    if v < 16384:
        return struct.pack(">H", v | 0x4000)
    if v < 1073741824:
        return struct.pack(">I", v | 0x80000000)
    return struct.pack(">Q", v | 0xC000000000000000)


FRAME_PADDING = 0x00
FRAME_RESET_STREAM = 0x04
FRAME_STOP_SENDING = 0x05
FRAME_RESET_STREAM_AT = 0x24
FRAME_STREAM_BASE = 0x08
FRAME_MAX_DATA = 0x10
FRAME_MAX_STREAM_DATA = 0x11
FRAME_MAX_STREAMS_BIDI = 0x12
FRAME_MAX_STREAMS_UNI = 0x13
FRAME_DATA_BLOCKED = 0x14
FRAME_STREAM_DATA_BLOCKED = 0x15
FRAME_STREAMS_BLOCKED_BIDI = 0x16
FRAME_STREAMS_BLOCKED_UNI = 0x17
FRAME_DATAGRAM_LEN = 0x31
FRAME_DATAGRAM = 0x30
FRAME_CC_TRANSPORT = 0x1c
FRAME_CC_APP = 0x1d
QX_TP = 0x3F514D580D0A0D0A
QX_TP_DOC = 0x3F5153300D0A0D0A
QX_PING_REQ = 0x348C67529EF8C7BD
QX_PING_RESP = 0x348C67529EF8C7BE
TP_MAX_IDLE = 0x01
TP_MAX_DATA = 0x04
TP_MAX_SD_BIDI_LOCAL = 0x05
TP_MAX_SD_BIDI_REMOTE = 0x06
TP_MAX_SD_UNI = 0x07
TP_MAX_STREAMS_BIDI = 0x08
TP_MAX_STREAMS_UNI = 0x09
TP_MAX_RECORD = 0x0571C59429CD0845
TP_MAX_DGRAM = 0x20
TP_RESET_AT = 0x1F


def tp_entry(tid, val):
    body = vint(val)
    return vint(tid) + vint(len(body)) + body


def default_tp():
    return b"".join([
        tp_entry(TP_MAX_IDLE, 30000),
        tp_entry(TP_MAX_DATA, 1024 * 1024),
        tp_entry(TP_MAX_SD_BIDI_LOCAL, 256 * 1024),
        tp_entry(TP_MAX_SD_BIDI_REMOTE, 256 * 1024),
        tp_entry(TP_MAX_SD_UNI, 256 * 1024),
        tp_entry(TP_MAX_STREAMS_BIDI, 100),
        tp_entry(TP_MAX_STREAMS_UNI, 100),
        tp_entry(TP_MAX_RECORD, 16382),
        tp_entry(TP_MAX_DGRAM, 16382),
        tp_entry(TP_RESET_AT, 1),
    ])


def frame_tp(body, magic=QX_TP):
    return vint(magic) + vint(len(body)) + body


def frame_stream(sid, off, data, fin=False, length=True, off_bit=True):
    t = FRAME_STREAM_BASE | (0x01 if fin else 0) | (0x02 if length else 0) | (0x04 if off_bit else 0)
    out = vint(t) + vint(sid)
    if off_bit:
        out += vint(off)
    if length:
        out += vint(len(data))
    return out + data


def record(frames_bytes):
    return vint(len(frames_bytes)) + frames_bytes


def qmux_proto():
    T = "qmux_proto"
    tp = default_tp()
    bodies = {
        "empty": b"",
        "padding_1": b"\x00",
        "padding_64": b"\x00" * 64,
        "padding_2000": b"\x00" * 2000,
        "tp_default": frame_tp(tp),
        "tp_default_doc_magic": frame_tp(tp, QX_TP_DOC),
        "tp_empty": frame_tp(b""),
        "tp_one": frame_tp(tp_entry(TP_MAX_DATA, 7)),
        "tp_short_record": frame_tp(tp_entry(TP_MAX_RECORD, 16381)),  # 低于默认 → 解码错
        "tp_max_record_62": frame_tp(tp_entry(TP_MAX_RECORD, (1 << 62) - 1)),
        "tp_dup": frame_tp(tp_entry(TP_MAX_DATA, 1) + tp_entry(TP_MAX_DATA, 2)),
        "tp_bad_len": vint(QX_TP) + vint(500) + tp,
        "tp_forbidden": frame_tp(tp_entry(0x0A, 1)),  # QUIC 禁止的 ack_delay_exponent
        "tp_unknown": frame_tp(tp_entry(0x123456, 99)),
        "stream_0": frame_stream(0, 0, b"hello"),
        "stream_fin": frame_stream(0, 0, b"hello", fin=True),
        "stream_no_off": frame_stream(0, 0, b"x", off_bit=False),
        "stream_no_len": frame_stream(0, 0, b"x", length=False),
        "stream_off_hi": frame_stream(4, (1 << 62) - 1, b""),
        "stream_sid_odd": frame_stream(1, 0, b"x"),      # 服务端发起的流
        "stream_sid_uni": frame_stream(2, 0, b"x"),      # 单向流
        "reset_stream": vint(FRAME_RESET_STREAM) + vint(0) + vint(1) + vint(10),
        "reset_at": vint(FRAME_RESET_STREAM_AT) + vint(0) + vint(1) + vint(10) + vint(5),
        "stop_sending": vint(FRAME_STOP_SENDING) + vint(0) + vint(1),
        "max_data": vint(FRAME_MAX_DATA) + vint(1 << 40),
        "max_stream_data": vint(FRAME_MAX_STREAM_DATA) + vint(0) + vint(1 << 40),
        "max_streams_bidi": vint(FRAME_MAX_STREAMS_BIDI) + vint(100),
        "max_streams_uni": vint(FRAME_MAX_STREAMS_UNI) + vint(100),
        "data_blocked": vint(FRAME_DATA_BLOCKED) + vint(1 << 40),
        "stream_data_blocked": vint(FRAME_STREAM_DATA_BLOCKED) + vint(0) + vint(1 << 40),
        "streams_blocked_bidi": vint(FRAME_STREAMS_BLOCKED_BIDI) + vint(1 << 40),
        "streams_blocked_uni": vint(FRAME_STREAMS_BLOCKED_UNI) + vint(1 << 40),
        "datagram_len": vint(FRAME_DATAGRAM_LEN) + vint(3) + b"abc",
        "datagram_bare": vint(FRAME_DATAGRAM) + b"abc",
        "cc_transport": vint(FRAME_CC_TRANSPORT) + vint(7) + vint(8) + vint(3) + b"bad",
        "cc_app": vint(FRAME_CC_APP) + vint(7) + vint(3) + b"bad",
        "ping": vint(QX_PING_REQ) + vint(1),
        "ping_ack": vint(QX_PING_RESP) + vint(1),
        "ping_max": vint(QX_PING_REQ) + vint((1 << 62) - 1),
        "unknown_type": vint(0x1e),                      # QUIC HANDSHAKE_DONE（禁止）
        "bad_varint_ff": b"\xff" + b"\x00" * 3,           # 8 字节 varint 截断
        "trunc_stream_len": vint(FRAME_STREAM_BASE | 0x02 | 0x04) + vint(0) + vint(0) + vint(100),
        "concat_frames": (
            vint(FRAME_MAX_DATA) + vint(1) + vint(QX_PING_REQ) + vint(2)
            + vint(FRAME_MAX_STREAM_DATA) + vint(4) + vint(8)
        ),
        "deep_500_maxdata": b"".join(vint(FRAME_MAX_DATA) + vint(i) for i in range(500)),
        "stream_16k": frame_stream(0, 0, b"a" * 16000),
    }
    for name, body in bodies.items():
        write(T, name, body)
        write(T, name + ".rec", record(body))
    # 记录层边界：size 声称很大但内容不足 / 恰好默认上限 / 超上限
    write(T, "rec_truncated", vint(100) + b"abc")
    write(T, "rec_exact_max", vint(16382) + b"\x00" * 16382)
    write(T, "rec_over_max", vint(16383) + b"\x00" * 16)
    write(T, "rec_trailing_partial", vint(3) + b"\x00\x00\x00" + b"\x10")
    # 变长整数各形态（1/2/4/8 字节）与非法前缀后续
    write(T, "varint_1", b"\x3f")
    write(T, "varint_2", b"\x40\x00")
    write(T, "varint_4", b"\x80\x00\x00\x00")
    write(T, "varint_8", b"\xc0\x00\x00\x00\x00\x00\x00\x00")
    write(T, "varint_8_max", b"\xff\xff\xff\xff\xff\xff\xff\xff")
    write(T, "bin_rand", bytes((i * 37 + 11) & 0xFF for i in range(256)))


def main():
    h1fast()
    upload_path()
    dns_wire()
    qmux_proto()
    total = 0
    for target in sorted(os.listdir(CORPUS)):
        d = os.path.join(CORPUS, target)
        if os.path.isdir(d):
            n = len([x for x in os.listdir(d) if os.path.isfile(os.path.join(d, x))])
            total += n
            print(f"{target}: {n} seeds")
    print(f"total: {total}")


if __name__ == "__main__":
    sys.exit(main())
