#!/bin/sh
# Linux musl 静态构建用的 C 编译器包装（**真实现**；此前 zig-musl-cc.sh 只在有 zig 时才
# 有意义，而 lib_app_musl.sh / app_native_musl.sh 是 echo+exit 0 的空壳 —— 于是
# 「Linux 静态构建」这条路从来没真正编过任何东西）。
#
# 为什么需要：要产出 `ldd` 为空的**跨机器可移植**二进制，必须走
# `x86_64-unknown-linux-musl` + `-C target-feature=+crt-static`；没有原生 musl 工具链的
# 机器上靠 zig 当交叉 C 编译器/链接器。
#
# 选取顺序：zig cc -target <arch>-linux-musl → musl-gcc → **报错退出**。
# 绝不静默回退到系统 cc：那会产出动态链接的产物却声称"静态"，是最难查的假成功。
# OpenBSD 上不做 Rust 全静态（见 scripts/update-deps-and-build.sh 文件头的实测结论）。
set -e
ARCH="$(uname -m)"
if [ "$(uname -s)" != "Linux" ]; then
  echo "musl 包装：本机是 $(uname -s)；musl 静态只在 Linux 上有意义（用系统 cc）" >&2
  exec "${CC:-cc}" "$@"
fi
if command -v zig >/dev/null 2>&1; then
  exec zig cc -target "${ARCH}-linux-musl" "$@"
fi
for c in musl-gcc "${ARCH}-linux-musl-gcc"; do
  if command -v "$c" >/dev/null 2>&1; then exec "$c" "$@"; fi
done
echo "musl 包装：找不到 zig，也没有 musl-gcc ⇒ 无法做静态 musl 构建。" >&2
echo "  装一个即可：apt/dnf 装 musl-tools（musl-gcc），或 zig（ziglang.org/download）" >&2
exit 1
