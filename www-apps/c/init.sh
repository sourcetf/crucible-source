#!/bin/sh
# 规格 §16.9：把 C 样例编译成**常驻** native sidecar（deps/bin/index）。
#
# 宿主用 **sh** 执行本脚本（deps.rs：`sh <init.sh>`，cwd = docroot），所以这里
# 必须是 POSIX sh（不用 bash 数组/[[ ]]）。DEPS_DIR 由宿主给出（绝对路径）。
#
# 编译器：Linux/OpenBSD 的 base `cc` 都可用；允许运维用 CC 覆盖。
# -pthread 是必须的（pthread_create / pthread_detach；规格 §16.9 的
# pthread-per-connection，不是 prefork）。
set -eu

ROOT="$(cd "$(dirname "$0")" && pwd)"
DEPS="${DEPS_DIR:-${ROOT}/deps}"
CC="${CC:-cc}"

mkdir -p "${DEPS}/bin"

"${CC}" -O2 -pthread -Wall -Wextra \
    -o "${DEPS}/bin/index" \
    "${ROOT}/main.c"

echo "c deps ok (built ${DEPS}/bin/index with ${CC} -O2 -pthread)" > "${DEPS}/.ready"
