#!/bin/sh
# 用（可选的）musl 静态工具链构建 www-apps 原生插件；参数透传。
# 此前是 echo+exit 0 的空壳 —— 「Linux 静态构建」从未真正编过东西。现在真调用构建脚本；
# 没有 musl 工具链时**返回非零**（调用方自决降级），不假装成功。
set -e
ROOT="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
# shellcheck source=/dev/null
. "$ROOT/scripts/lib_app_musl.sh"
if [ "${CC_MUSL:-cc}" = "cc" ] || [ "${CC_MUSL:-cc}" = "${CC:-cc}" ]; then
  echo "app_native_musl: 本机没有 musl 工具链（CC_MUSL=${CC_MUSL:-cc}）⇒ 无法产出静态插件" >&2
  exit 1
fi
echo "app_native_musl: 用 $CC_MUSL 构建原生插件 args=$*"
[ -f "$ROOT/scripts/build_app_engines.sh" ] || { echo "app_native_musl: 缺 build_app_engines.sh" >&2; exit 1; }
CC="$CC_MUSL" bash "$ROOT/scripts/build_app_engines.sh" "$@"
