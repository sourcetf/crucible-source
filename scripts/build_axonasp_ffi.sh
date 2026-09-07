#!/usr/bin/env bash
# Build AxonASP FFI (Go c-shared when available) + ensure libapp_asp.so from C engine.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${ROOT}/target/app-engines"
SRC="${ROOT}/libs/axonasp-ffi"
INC="${ROOT}/libs/app-engines/include"
COMMON="${ROOT}/libs/app-engines/common"
CC="${CC:-cc}"
mkdir -p "${OUT}"

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
