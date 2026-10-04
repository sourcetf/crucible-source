#!/usr/bin/env python3
"""打开 N 个**零字节**空闲连接并保持（第 6 轮并发报告 #1/P0 的施压端）。

为什么用零字节连接：它不触发任何应用逻辑，只占 fd —— 这正是「匿名、无需鉴权即可把
进程 fd 打满」的那条路（`ulimit -n` 决定了需要多少个）。
"""
import socket, sys, time

port = int(sys.argv[1]); n = int(sys.argv[2]); hold = float(sys.argv[3])
socks = []; t0 = time.time()
for i in range(n):
    try:
        socks.append(socket.create_connection(("127.0.0.1", port), timeout=3))
    except Exception as e:
        print("open_fail 在第 %d 个: %r" % (i, e)); break
print("已建立空连接 %d 个，用时 %.1fs" % (len(socks), time.time() - t0))
time.sleep(hold)
for s in socks:
    try: s.close()
    except Exception: pass
print("已全部释放")
