#!/usr/bin/env bash
# Build ASP.NET hostfxr FFI stub + libapp_aspnet.so (appengine ABI).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${ROOT}/target/app-engines"
SRC="${ROOT}/libs/aspnet-ffi"
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

echo "==> building libaspnet_ffi.so"
${CC} ${CFLAGS} ${LDFLAGS} -o "${OUT}/libaspnet_ffi.so" "${SRC}/aspnet_ffi.c"

echo "==> building libapp_aspnet.so"
if ${CC} ${CFLAGS} ${LDFLAGS} -o "${OUT}/libapp_aspnet.so" \
    "${SRC}/aspnet_engine.c" "${COMMON}/appengine_common.c" -ldl 2>/dev/null; then
  :
else
  # OpenBSD: dl* in libc
  ${CC} ${CFLAGS} ${LDFLAGS} -o "${OUT}/libapp_aspnet.so" \
    "${SRC}/aspnet_engine.c" "${COMMON}/appengine_common.c"
fi

echo "built ${OUT}/libaspnet_ffi.so ${OUT}/libapp_aspnet.so"
