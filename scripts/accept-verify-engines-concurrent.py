#!/usr/bin/env python3
"""引擎**并发**存活与一致性检查（catch 解释器线程亲和性/堆损坏类 P0）。

为什么要单列：单线程 curl 循环**测不出**这类问题 —— OpenBSD 生产机上 `/perl/` 在
6 并发下 2 轮就把进程打崩（core 栈在 libc `memset`/`malloc_lock`，OpenBSD malloc 报
堆损坏），而同样请求单线程跑几千次毫无异常。根因是 ithreads Perl 的解释器有线程
亲和性（非创建线程调用即踩坏堆），修法是让 perl/psgi 走**串行单线程池**。

用法（对着一个已起好的实例）：
    python3 scripts/accept-verify-engines-concurrent.py --port 9095 --threads 8 --secs 30

判定：每个引擎在 `--secs` 秒内持续并发请求后，**进程必须仍存活**，且所有响应为 200。
进程存活按 HTTP 探活判定（跨平台，不依赖 /proc）。
"""
import argparse
import concurrent.futures as cf
import http.client
import sys
import time

ENGINES = [
    "/php/", "/c/", "/rust/", "/go/", "/lua/", "/python/", "/ruby/", "/perl/",
    "/wsgi/", "/asgi/", "/psgi/", "/rack/", "/cgi/", "/uwsgi/", "/tsx/",
    "/asp/", "/aspnet/", "/jsp/", "/do/",
]


def one(port: int, path: str, timeout: float = 20.0):
    try:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
        c.request("GET", path)
        r = c.getresponse()
        r.read()
        c.close()
        return r.status
    except Exception:  # noqa: BLE001
        return -1


def alive(port: int) -> bool:
    """HTTP 探活：进程死了就是连接被拒（不依赖 /proc，OpenBSD 无 /proc）。"""
    return one(port, "/", timeout=5.0) != -1


def hammer(port: int, path: str, threads: int, secs: float):
    """用 `threads` 个线程持续打 `path` `secs` 秒；返回 (ok, bad, died_at)。"""
    ok = bad = 0
    t0 = time.time()
    died_at = None
    with cf.ThreadPoolExecutor(max_workers=threads) as ex:
        futs = set()
        while time.time() - t0 < secs:
            for _ in range(threads):
                futs.add(ex.submit(one, port, path))
            for f in cf.as_completed(futs):
                st = f.result()
                if st == 200:
                    ok += 1
                else:
                    bad += 1
                    if not alive(port):
                        died_at = time.time() - t0
                        return ok, bad, died_at
            futs.clear()
            if not alive(port):
                died_at = time.time() - t0
                break
    return ok, bad, died_at


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=9095)
    ap.add_argument("--threads", type=int, default=8)
    ap.add_argument("--secs", type=float, default=15.0)
    ap.add_argument("--only", default="", help="只测这些路由（逗号分隔），默认全部")
    args = ap.parse_args()

    routes = [r.strip() for r in args.only.split(",") if r.strip()] or ENGINES
    fails = []
    for path in routes:
        if not alive(args.port):
            print(f"FAIL {path:10s} 进程已不在（起先就探活失败）")
            fails.append(path)
            break
        ok, bad, died_at = hammer(args.port, path, args.threads, args.secs)
        if died_at is not None:
            print(f"FAIL {path:10s} 进程在 {died_at:.1f}s 死掉（ok={ok} bad={bad}）")
            fails.append(path)
            break
        flag = "ok  " if bad == 0 else "BAD "
        print(f"{flag} {path:10s} {args.threads} 并发 {args.secs:.0f}s：ok={ok} bad={bad}")
        if bad:
            fails.append(path)
    print(f"== summary: fails={len(fails)} {fails} ==")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
