#!/usr/bin/env python3
"""引擎**并发**存活与一致性检查（catch 解释器线程亲和性/堆损坏类 P0）。

为什么要单列：单线程 curl 循环**测不出**这类问题 —— OpenBSD 生产机上 `/perl/` 在
6 并发下 2 轮就把进程打崩（core 栈在 libc `memset`/`malloc_lock`，OpenBSD malloc 报
堆损坏），而同样请求单线程跑几千次毫无异常。根因是 ithreads Perl 的解释器有线程
亲和性（非创建线程调用即踩坏堆），修法是让 perl/psgi 走**串行单线程池**。

用法（对着一个已起好的实例）：
    python3 scripts/accept-verify-engines-concurrent.py --threads 8 --secs 30   # 默认 TLS 8443

判定：每个引擎在 `--secs` 秒内持续并发请求后，**进程必须仍存活**，且所有响应为 200。
进程存活按 HTTP 探活判定（跨平台，不依赖 /proc）。
"""
import argparse
import concurrent.futures as cf
import http.client
import sys
import time

# 应用自 2026-11-06 起只在 TLS 口（8443）提供（原明文 9095 已移除）；
# `--plain` 切回明文（供 19095 等测试端口）。由 main() 覆盖。
TLS = True

ENGINES = [
    "/php/", "/c/", "/rust/", "/go/", "/lua/", "/python/", "/ruby/", "/perl/",
    "/wsgi/", "/asgi/", "/psgi/", "/rack/", "/cgi/", "/uwsgi/", "/tsx/",
    "/asp/", "/aspnet/", "/jsp/", "/do/",
]


def one(port: int, path: str, timeout: float = 20.0):
    try:
        if TLS:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            c = http.client.HTTPSConnection("127.0.0.1", port, timeout=timeout, context=ctx)
        else:
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


def hammer_mixed(port: int, routes, threads: int, secs: float):
    """**混合**压测：`threads` 个线程同时随机打若干路由（默认：全部引擎）。

    为什么单列（真机 P0，2026-11-03）：perl 与 psgi 各自单独压都是 0 失败，但
    **一起压** 2~7 秒就崩 —— 因为两个 `.so` 各建一个 Perl 解释器，而目标机 perl 是
    `useithreads=undef/usemultiplicity=undef` 构建（`PL_curinterp` 是**进程全局**），
    两条线程互把「当前解释器」切错 ⇒ libperl 在 `Perl_call_sv`/`Perl_rpp_free_2_` 崩。
    只按路由**顺序**逐个压（上面的 `hammer`）永远测不出这种**跨引擎**交互，所以这里
    再用同一个线程池把所有路由**混在一起**打一遍。
    """
    ok = bad = 0
    t0 = time.time()
    died_at = None
    with cf.ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {}
        i = 0
        while time.time() - t0 < secs:
            for _ in range(threads):
                path = routes[i % len(routes)]
                i += 1
                futs[ex.submit(one, port, path)] = path
            for f in cf.as_completed(list(futs)):
                st = f.result()
                if st == 200:
                    ok += 1
                else:
                    bad += 1
            futs.clear()
            if not alive(port):
                died_at = time.time() - t0
                break
    return ok, bad, died_at


def main():
    ap = argparse.ArgumentParser()
    # 应用自 2026-11-06 起只在 TLS 口（8443）提供（原明文 9095 已移除）。
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--plain", dest="tls", action="store_false",
                    help="用明文 HTTP（测试端口；生产已无明文应用口）")
    ap.add_argument("--threads", type=int, default=8)
    ap.add_argument("--secs", type=float, default=15.0)
    ap.add_argument("--only", default="", help="只测这些路由（逗号分隔），默认全部")
    ap.add_argument("--no-mix", action="store_true",
                    help="跳过最后的「全路由混合并发」压测（默认做 —— 跨引擎交互只有它能测出）")
    args = ap.parse_args()
    global TLS
    TLS = args.tls

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
    if not args.no_mix and not fails:
        ok, bad, died_at = hammer_mixed(args.port, routes, args.threads, args.secs)
        if died_at is not None:
            print(f"FAIL mixed     进程在 {died_at:.1f}s 死掉（ok={ok} bad={bad}；"
                  f"路由循环={routes}）")
            fails.append("mixed")
        else:
            flag = "ok  " if bad == 0 else "BAD "
            print(f"{flag} mixed     全部 {len(routes)} 路由混合 {args.threads} 并发 "
                  f"{args.secs:.0f}s：ok={ok} bad={bad}")
            if bad:
                fails.append("mixed")
    print(f"== summary: fails={len(fails)} {fails} ==")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
