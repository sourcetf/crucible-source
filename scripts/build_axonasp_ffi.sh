#!/usr/bin/env bash
# Build AxonASP FFI (Go c-shared when available) + ensure libapp_asp.so from C engine.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# 产物目录：默认 ${ROOT}/target/app-engines，可用 CRUCIBLE_APP_ENGINES_OUT 覆盖
# （与 build_app_engines.sh / build_script_ffi.sh 同一套语义；否则被主构建脚本调用时
#  dry-run/自定义 OUT 仍会重写现役产物）。
OUT="${CRUCIBLE_APP_ENGINES_OUT:-${ROOT}/target/app-engines}"
SRC="${ROOT}/libs/axonasp-ffi"
INC="${ROOT}/libs/app-engines/include"
COMMON="${ROOT}/libs/app-engines/common"
CC="${CC:-cc}"
mkdir -p "${OUT}"

# 用户级运行时（Go/Ruby/... 的 PATH/LD_LIBRARY_PATH）。
# shellcheck source=scripts/runtime_env.sh
. "${ROOT}/scripts/runtime_env.sh"

export PATH="/usr/local/bin:/usr/bin:/bin:${PATH:-}"
if [[ -x /usr/local/bin/gcc ]]; then
  CC=/usr/local/bin/gcc
fi

CFLAGS="-O2 -fPIC -I${INC} -I${COMMON}"
LDFLAGS="-shared -fPIC"

echo "==> building libapp_asp.so (axonasp_engine.c)"
${CC} ${CFLAGS} ${LDFLAGS} \
  -o "${OUT}/libapp_asp.so" \
  "${SRC}/axonasp_engine.c" \
  "${COMMON}/appengine_common.c"
echo "built ${OUT}/libapp_asp.so"

if ! command -v go >/dev/null 2>&1; then
  echo "WARN: go not found; skip libaxonasp.so c-shared" >&2
  exit 0
fi
if (
  cd "${SRC}"
  CGO_ENABLED=1 go build -buildmode=c-shared -o "${OUT}/libaxonasp.so" .
); then
  echo "built ${OUT}/libaxonasp.so"
else
  echo "WARN: axonasp c-shared not supported on this platform" >&2
fi
