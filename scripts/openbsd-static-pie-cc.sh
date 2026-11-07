#!/usr/bin/env bash
# OpenBSD **static-pie** 链接驱动包装（给 rustc 当 linker）。**必须 bash**：要用数组重建参数
# （POSIX sh 的 @response-file 方案会让 clang 把 -static-pie 当"未使用的编译参数"丢掉 —— 实测警告
#  `cc: argument unused during compilation: '-static-pie'`，于是链接仍旧动态、留 5 条 DT_NEEDED）。
#
# 目标：`ldd` 为空（无 DT_NEEDED）+ 引擎仍可 dlopen + **只用 OpenBSD 自己的 libc**。实测（x86_64
# OpenBSD，2026-11-07）：
#   * `cc -static-pie` ⇒ ldd 为空、可运行、dlopen 项目真实引擎 .so 正常（appengine_* 全在）✅
#   * `-static`        ⇒ ldd 空但 dlopen 失败/段错误 ⇒ 打掉整套 FFI 引擎 ✗
#   * `+crt-static`    ⇒ 仍动态 PIE（ldd 非空）✗
#   * `-C link-arg=-static-pie` ⇒ 被追加到行尾，前面的 -l 已动态解析 ⇒ 仍 5 条 NEEDED ✗
#   * linker driver + `-Wl,-Bstatic` ⇒ rustc 在系统库前又插 `-Wl,-Bdynamic` 撤销它 ⇒ 仍 5 条 ✗
# 本包装器的做法：把 rustc 注入的 `-Wl,-Bdynamic` / dynamic-linker 一律剔掉，
# 再把 `-static-pie -Wl,-Bstatic` 放在最前（**作为驱动参数**，不走 @file），使其后所有 `-l` 静态解析。
# 缺静态库（如 NSS 只有 libnss3.so）会**链接失败并报错**，绝不静默退回动态。
set -u
args=()
for a in "$@"; do
  case "$a" in
    -Wl,-Bdynamic|-Wl,-dynamic-linker|-Wl,--dynamic-linker=*) ;;   # 丢弃
    *) args+=("$a") ;;
  esac
done
exec cc -static-pie -Wl,-Bstatic "${args[@]}"
