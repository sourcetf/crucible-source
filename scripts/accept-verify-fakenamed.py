#!/usr/bin/env python3
"""accept-verify-fakenamed.py — 独立的「假 named」UDP 应答器（验收用，非生产组件）。

本机没有 bind9/named，DoT/DoH 的正常递归路径只会超时，套件里两条检查因此长期 SKIP。
本守护进程绑在测试配置的 named 端口（默认 29553），对任何查询回一条最小 A 应答，并把
收到的查询 wire 记到 `$SCRATCH/tmp/fake-named.log`（节流/回显检查都读它）。
与 accept-verify-dns.py 里的同源实现共用 FakeNamed 类，避免两处逻辑漂移。

用法: python3 scripts/accept-verify-fakenamed.py [port]
"""
import importlib.util, os, signal, sys

HERE = os.path.dirname(os.path.abspath(__file__))


def load_fake_named():
    spec = importlib.util.spec_from_file_location(
        "accept_verify_dns", os.path.join(HERE, "accept-verify-dns.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.FakeNamed


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 29553
    FakeNamed = load_fake_named()
    fn = FakeNamed(port=port)
    fn.start()
    stop = lambda *_: sys.exit(0)
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    print(f"fake-named up on 127.0.0.1:{port}", flush=True)
    while True:
        signal.pause()


if __name__ == "__main__":
    main()
