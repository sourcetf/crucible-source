#!/bin/sh
# OpenBSD **static-pie** 链接驱动包装（给 rustc 当 linker）。
#
# 为什么需要：目标要求「ldd 为空（无 DT_NEEDED）+ 跨机可移植」，且**用 OpenBSD 自己的 libc**
# （比 musl/glibc 加固更好，不引异种 libc）。实测（x86_64 OpenBSD，2026-11-07）：
#   * `cc -static-pie`   ⇒ ldd 为空、可运行、**dlopen 正常**（含 dlopen 项目真实引擎 .so：
#                          LOADED 且 appengine_execute/init/abi_version 全在）—— 正确路线；
#   * `-static`（完整静态）⇒ ldd 为空但 dlopen 失败/段错误 ⇒ 会打掉整套 FFI 引擎，不可用；
#   * `+crt-static` 单独   ⇒ 仍是动态 PIE（ldd 非空），不能当静态用。
#
# 为什么必须用**包装器**而不是 `-C link-arg=-static-pie`：
#   link-arg 被 rustc **追加到命令行末尾**，而链接器按**位置**处理静态/动态选择 ——
#   前面的 `-l…` 已经把 libc/libm/libpthread/libc++/libc++abi 动态解掉，产物仍留 5 条 DT_NEEDED
#   （真机实测）。这里把 `-static-pie -Wl,-Bstatic` 放在**最前**，其后的所有 `-l` 都按静态解析。
#
# 行为约定（fail-closed）：缺静态库（例如 NSS 的 libnss3 只有 .so）时**链接直接失败并报错**，
# 绝不静默退回动态链接 —— 否则会产出"看起来静态、其实动态"的产物，是最难查的假成功。
# 因此静态产物需要去掉 `tls_nss`（NSS 只提供共享库）；见 scripts/update-deps-and-build.sh。
exec cc -static-pie -Wl,-Bstatic "$@"
