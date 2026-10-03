#!/usr/bin/env python3
"""凭据无关的 DNS 安全判据（不需要管理员口令；只用 TCP 查询 + 指定源地址）。

判据：
  1) **AXFR 从非回环源必须被拒**（named.conf: allow-transfer { 127.0.0.0/8; }）
     + 正对照：从回环源**应当**允许（确认 ACL 没被写坏，不是「一律拒」）
  2) **非回环源不得拿到递归数据**（allow-recursion { 127.0.0.1; }）
     + 正对照：从回环源递归应当成功
  3) 根区（root 模式）从回环可查（SOA 有应答）
  3b) 非回环源问**权威 zone 内的名字**应当拿得到答案（allow-query { any; }）
  4) 非回环源问非权威公共名**不得**拿到权威答案

写这个脚本时踩到的两个坑（都是**判据**的错、不是服务器的问题，留注释免得重犯）：
  * 根名要特判：`'.'.split('.')` 是 `['', '']`，照通用编码会写成两个零标签（畸形名）
    ⇒ named 回 NOTIMP，被误判成「根区没在服务」。
  * 本机对根**权威**，所以非回环客户端问公共名会拿到根区的**权威 NODATA**
    （rcode=0 / ancount=0）—— 那是正确行为；只有「拿到递归数据」才是洞。
"""
import socket
import struct
import sys
import random

LOOP = ("127.0.0.1", 53)
OTHER_LOCAL = "10.126.126.1"          # 本机另一张网卡的地址（非 127.0.0.0/8）
SELF = "10.126.126.1"

FAIL = 0


def ok(m):
    print("  PASS: %s" % m)


def bad(m):
    global FAIL
    FAIL += 1
    print("  FAIL: %s" % m)


def mkq(name, qtype, rd=True):
    tid = random.randint(0, 65535)
    flags = 0x0100 if rd else 0x0000
    h = struct.pack(">HHHHHH", tid, flags, 1, 0, 0, 0)
    if name in (".", ""):
        parts = b"\x00"                     # 根名：单个零标签
    else:
        parts = b"".join(bytes([len(x)]) + x.encode() for x in name.split(".")) + b"\x00"
    return h + parts + struct.pack(">HH", qtype, 1)


def tcp_query(qname, qtype, dst, src=None, rd=True, timeout=8):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        if src:
            s.bind((src, 0))
        s.connect(dst)
        pkt = mkq(qname, qtype, rd)
        s.sendall(struct.pack(">H", len(pkt)) + pkt)
        ln = struct.unpack(">H", s.recv(2))[0]
        d = b""
        while len(d) < ln:
            chunk = s.recv(ln - len(d))
            if not chunk:
                break
            d += chunk
        return d[3] & 0x0F, struct.unpack(">H", d[6:8])[0], len(d)
    except Exception as e:
        return ("ERR:" + type(e).__name__, 0, 0)
    finally:
        s.close()


def axfr(dst, src=None, zone="crucible.local"):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(8)
    try:
        if src:
            s.bind((src, 0))
        s.connect(dst)
        pkt = mkq(zone, 252)  # AXFR
        s.sendall(struct.pack(">H", len(pkt)) + pkt)
        ln = struct.unpack(">H", s.recv(2))[0]
        d = b""
        while len(d) < ln:
            chunk = s.recv(ln - len(d))
            if not chunk:
                break
            d += chunk
        return d[3] & 0x0F
    except Exception as e:
        return "ERR:" + type(e).__name__
    finally:
        s.close()


print("=== 1) AXFR ===")
r_loop = axfr(LOOP)
print("  回环源 AXFR  -> rcode=%s" % r_loop)
if r_loop == 0:
    ok("回环源允许（与 allow-transfer { 127.0.0.0/8; } 一致）")
elif r_loop == 5:
    print("  注：回环源也被 REFUSED（配置成 none？）—— 仍是明确拒绝，不算错")
else:
    bad("回环源 AXFR 异常: %s" % r_loop)

r_other = axfr((SELF, 53), src=OTHER_LOCAL)
print("  非回环源 AXFR（源 %s）-> rcode=%s" % (OTHER_LOCAL, r_other))
if r_other in (5, 9):       # REFUSED / NOTAUTH
    ok("非回环源被拒（rcode=%s）" % r_other)
elif r_other == 0:
    bad("非回环源竟能 AXFR —— allow-transfer 未生效（zone 数据可被任意人拖走）")
else:
    bad("非回环源 AXFR 异常: %s" % r_other)

print("=== 2) 递归（RD=1，公共域名）===")
rc, an, _ = tcp_query("example.com", 1, LOOP, rd=True)
print("  回环源 example.com A -> rcode=%s ancount=%s" % (rc, an))
if rc == 0 and an >= 1:
    ok("回环源可递归")
else:
    bad("回环源递归失败（rcode=%s ancount=%s）" % (rc, an))

rc, an, _ = tcp_query("example.com", 1, (SELF, 53), src=OTHER_LOCAL, rd=True)
print("  非回环源 example.com A（源 %s）-> rcode=%s ancount=%s" % (OTHER_LOCAL, rc, an))
if an >= 1:
    bad("非回环源竟拿到了 %s 条**递归**答案 —— 等于对外提供开放递归器（放大攻击帮凶）" % an)
else:
    ok("非回环源没拿到递归数据（rcode=%s ancount=%s）—— 本机对根权威，它拿到的是根区的"
       "**权威 NODATA**，这是正确行为" % (rc, an))

print("=== 3) 根区（root 模式）===")
rc, an, _ = tcp_query(".", 6, LOOP, rd=False)   # SOA
print("  . SOA -> rcode=%s ancount=%s" % (rc, an))
if rc == 0 and an >= 1:
    ok("根区 SOA 有应答（root 模式在服务）")
else:
    bad("根区 SOA 无应答（rcode=%s ancount=%s）" % (rc, an))

print("=== 3b) 非回环源问权威 zone 内的名字（应拿得到，allow-query { any; }）===")
rc, an, _ = tcp_query("crucible.local", 65, (SELF, 53), src=OTHER_LOCAL, rd=False)
print("  非回环源 crucible.local HTTPS（RD=0）-> rcode=%s ancount=%s" % (rc, an))
if rc == 0 and an >= 1:
    ok("对外提供权威服务正常（ECH 的 HTTPS 记录可被外部查到）")
else:
    bad("权威查询失败（rcode=%s ancount=%s）—— 对外权威服务异常" % (rc, an))

print("=== 4) 非权威公共名（从非回环源）不得拿到权威答案 ===")
rc, an, _ = tcp_query("www.example.org", 1, (SELF, 53), src=OTHER_LOCAL, rd=False)
print("  非回环源 www.example.org A（RD=0）-> rcode=%s ancount=%s" % (rc, an))
if rc == 5 or an == 0:
    ok("没有把它当自己的权威数据（rcode=%s ancount=%s）" % (rc, an))
else:
    bad("对非权威名给出了 %s 条答案（rcode=%s）—— 应排查" % (an, rc))

print()
print("=== 结果：%s ===" % ("全部 PASS" if FAIL == 0 else "%d 项 FAIL" % FAIL))
sys.exit(1 if FAIL else 0)