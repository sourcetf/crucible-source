#!/usr/bin/env python3
"""第 6 轮「慢速/半开连接」判据：超时必须**有界**。

两个模式（对应并发报告 #2 与 #3）：

  empty  <port> <wait>   明文口：连上后**一个字节都不发**。
                         修复前：裸 `stream.readable().await` 无超时 ⇒ 永久占住 fd。
                         修复后：首字节嗅探预算 2.4s 用尽 ⇒ 交 h1，由 h1 的 30s 头读超时兜底
                                 ⇒ 实测 **32.4s** 被服务端关闭。

  h2     <port> <wait>   发 h2 preface + SETTINGS + **半截 HEADERS**（声明 len=1000 只发 10 字节）。
                         修复前：`conn.accept()` 无超时 ⇒ 永久挂住（实测 110s 仍开）。
                         修复后：h2 空闲超时 300s（nginx http2_idle_timeout 语义）⇒ 实测 **300.0s** 关闭。

判定：把 `<wait>` 设成比预期上限略大（如 60 / 400），若脚本打印「仍开着」即**不通过**。
退出码 0 = 服务端主动关闭；1 = 到点仍开着（超时无界）。
"""
import socket, sys, time


def hold_empty(port, secs, tag):
    s = socket.create_connection(("127.0.0.1", port)); t0 = time.time()
    s.settimeout(secs + 5)
    try:
        while True:
            d = s.recv(1)
            if not d:
                print("%s: 服务端关闭了连接，用时 %.1fs" % (tag, time.time() - t0)); return 0
    except socket.timeout:
        print("%s: 仍开着（客户端放弃），%.1fs" % (tag, time.time() - t0)); return 1
    except Exception as e:
        print("%s: %r @%.1fs" % (tag, e, time.time() - t0)); return 0
    finally:
        try: s.close()
        except Exception: pass


def h2_partial(port, secs, tag):
    s = socket.create_connection(("127.0.0.1", port)); t0 = time.time()
    s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
    s.sendall(b"\x00\x00\x00\x04\x00\x00\x00\x00\x00")                  # SETTINGS
    s.sendall(b"\x00\x00\x03\xe8\x01\x05\x00\x00\x00\x01" + b"\x00" * 10)  # 半截 HEADERS
    s.settimeout(secs + 5)
    try:
        while True:
            d = s.recv(1)
            if not d:
                print("%s: 服务端关闭了连接，用时 %.1fs" % (tag, time.time() - t0)); return 0
    except socket.timeout:
        print("%s: 仍开着（客户端放弃），%.1fs" % (tag, time.time() - t0)); return 1
    finally:
        try: s.close()
        except Exception: pass


m = sys.argv[1]
if m == "empty":
    sys.exit(hold_empty(int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]))
elif m == "h2":
    sys.exit(h2_partial(int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]))
else:
    print("用法: r6_net_timeouts.py empty|h2 <port> <wait_secs> <tag>"); sys.exit(2)
