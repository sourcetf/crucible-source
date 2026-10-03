#!/usr/bin/env python3
"""J 项修复的 h1 判据：listener 配置变化后，**已建立**的 keep-alive 连接必须收尾。

三种模式（都由本脚本自己改配置，保证「改配置」发生在同一条连接持有期间）：
  baseline    不改配置         → 第 2 次请求**不得**出现 Connection: close（否则是无谓踢连接）
  nonlistener 只加 [access_log] → 同样**不得**收尾（非 listener 变化与在线连接无关）
  listener    改 root           → 第 2 次请求**必须** Connection: close，且新连接拿到新 root
"""
import http.client
import sys
import time

port = int(sys.argv[1])
mode = sys.argv[2]          # baseline | nonlistener | listener
cfg = sys.argv[3]
dir_a = sys.argv[4]         # 初始 root（非 listener 用例必须保持不变）
dir_b = sys.argv[5]         # 目标 root（listener 用例改成它）


def write_cfg(root, extra):
    """root 必须显式给。

    第一版这里硬编码写 dir_b，于是「只改 access_log」那一条其实同时改了 listener 的 root ——
    而 root 变了是货真价实的 listener 变化，测的就不是「非 listener 变化不收尾」了。
    是**反向判据**把它抓出来的（实现对、判据错）。
    """
    text = (
        '[[listeners]]\n'
        'address = "127.0.0.1"\n'
        f'port = {port}\n'
        f'root = "{root}"\n'
        'http_versions = ["h1", "h2"]\n'
        f'{extra}\n'
    )
    with open(cfg, "w", encoding="utf-8") as f:
        f.write(text)


def req(conn, label):
    conn.request("GET", "/index.html")
    r = conn.getresponse()
    body = r.read()
    hdr = r.getheader("Connection")
    print(f"  {label:<26} status={r.status} connection={hdr!r} body={body[:6]!r}")
    return hdr, body


# 一条连接（http.client 在 keep-alive 响应上复用同一个 socket）
conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
h1, _b1 = req(conn, "第 1 次（改前）")
if h1 and h1.lower() == "close":
    print("  !! 基线就带 Connection: close —— 说明判据本身有问题")

if mode == "baseline":
    h2, _ = req(conn, "第 2 次（未改配置）")
    ok = not h2 or h2.lower() != "close"
    print("  判定：", "PASS 未收尾" if ok else "FAIL 被无谓收尾")
    sys.exit(0 if ok else 1)

if mode == "nonlistener":
    # **root 保持 dir_a**，只多一段 [access_log]
    write_cfg(dir_a, '[access_log]\nlevel = "debug"')
    time.sleep(4.5)
    h2, _ = req(conn, "第 2 次（只加 access_log）")
    ok = not h2 or h2.lower() != "close"
    print("  判定：", "PASS 未收尾（非 listener 变化）" if ok else "FAIL 被无谓收尾")
    sys.exit(0 if ok else 1)

# listener 模式：改 root（dir_a → dir_b）
write_cfg(dir_b, "")
time.sleep(4.5)
h2, _b2 = req(conn, "第 2 次（root 已改）")
ok1 = bool(h2) and h2.lower() == "close"
print("  判定：", "PASS 已收尾（Connection: close）" if ok1 else "FAIL 仍被复用（旧策略继续生效）")

c3 = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
c3.request("GET", "/index.html")
r3 = c3.getresponse()
b3 = r3.read()
print(f"  新连接 body={b3[:6]!r}（期望 b'BBB'）")
ok2 = b3.startswith(b"BBB")
print("  判定：", "PASS 新配置已生效" if ok2 else "FAIL 新连接仍是旧配置")
sys.exit(0 if (ok1 and ok2) else 1)