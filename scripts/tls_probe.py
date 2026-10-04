#!/usr/bin/env python3
"""TLS 版本探针（验收脚本用）。

用法: python3 scripts/tls_probe.py <port> [TLSv1|TLSv1_1|TLSv1_2|TLSv1_3] [host]

为什么需要它：验收脚本此前调用 `/tmp/_tlsprobe.py`，而那个文件**在仓库与历史里都不存在**
——硬门（post-sslv2 必须仍能 TLS1.3）因此**必然失败**，其余 TLS 冒烟又都带 `|| true`，
等于既跑不通、又什么都没测。这里给出一个真实可用的实现：

* 用 python3 自带的 `ssl`（底层是平台 TLS 栈）而不是 openssl CLI（用户要求项目不依赖 openssl）；
* `minimum_version == maximum_version` 把协商钉死在目标版本上，成功即证明该版本可用；
* 退出码 0/1 明确表达结果，调用方**不要**再用 `|| true` 吞掉。
"""
import socket
import ssl
import sys

_VERSIONS = {
    "TLSv1": ssl.TLSVersion.TLSv1,
    "TLSv1_0": ssl.TLSVersion.TLSv1,
    "TLSv1_1": ssl.TLSVersion.TLSv1_1,
    "TLSv1_2": ssl.TLSVersion.TLSv1_2,
    "TLSv1_3": ssl.TLSVersion.TLSv1_3,
}


def main(argv):
    if len(argv) < 2:
        print("usage: tls_probe.py <port> [version] [host]", file=sys.stderr)
        return 2
    port = int(argv[1])
    want = argv[2] if len(argv) > 2 else "TLSv1_3"
    host = argv[3] if len(argv) > 3 else "127.0.0.1"
    ver = _VERSIONS.get(want)
    if ver is None:
        print(f"FAIL unknown version {want!r} (want one of {sorted(_VERSIONS)})")
        return 2

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = ver
        ctx.maximum_version = ver
    except (ValueError, OSError) as e:
        # 平台 TLS 栈拒绝钉该版本（LibreSSL/OpenSSL 的安全级别策略）——如实报告。
        print(f"FAIL {want}: platform refuses to pin version: {e}")
        return 1
    try:
        with socket.create_connection((host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                got = tls.version()
                print(f"OK {want} negotiated={got} cipher={tls.cipher()[0]}")
                return 0
    except Exception as e:  # noqa: BLE001 - 探针要如实报告任何失败
        print(f"FAIL {want}: {type(e).__name__}: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
