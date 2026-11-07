#!/bin/sh
# musl 静态构建的共享辅助（**真实现**；此前是 echo+exit 0 的占位空壳）。
# 只做一件事：告诉调用方用哪个 C 编译器/链接器（CC_MUSL）。OpenBSD 回落系统 cc。
set -e
if [ "$(uname -s)" = "Linux" ] && { command -v zig >/dev/null 2>&1 || command -v musl-gcc >/dev/null 2>&1; }; then
  export CC_MUSL="${CC_MUSL:-$(CDPATH= cd -- "$(dirname "$0")" && pwd)/zig-musl-cc.sh}"
  echo "lib_app_musl: 使用 musl 静态工具链 CC_MUSL=$CC_MUSL"
else
  export CC_MUSL="${CC:-cc}"
  echo "lib_app_musl: host=$(uname -s) 无 musl 工具链 ⇒ 回落系统 cc（**非静态**）"
fi
