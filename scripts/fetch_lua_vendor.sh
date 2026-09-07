#!/usr/bin/env bash
# Fetch PUC-Lua sources for vendored libapp_lua.so when system Lua is missing.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VENDOR="${ROOT}/libs/app-engines/lua/vendor"
# Prefer official release (has all headers). Fallback: lua.org ftp.
VER="${LUA_VENDOR_VER:-5.4.7}"
URL="https://www.lua.org/ftp/lua-${VER}.tar.gz"
MIRROR="https://github.com/lua/lua/archive/refs/tags/v${VER}.tar.gz"

mkdir -p "${VENDOR}"

have_vendor() {
  [[ -f "${VENDOR}/onelua.c" && -f "${VENDOR}/lprefix.h" && -f "${VENDOR}/lua.h" \
     && -f "${VENDOR}/lauxlib.h" && -f "${VENDOR}/lualib.h" ]]
}

if have_vendor; then
  echo "fetch_lua_vendor: vendor tree already present"
  exit 0
fi

# Broken partial trees (e.g. onelua.c without lprefix.h) break compile — wipe and re-fetch.
if [[ -d "${VENDOR}" ]] && [[ -n "$(ls -A "${VENDOR}" 2>/dev/null)" ]]; then
  echo "fetch_lua_vendor: incomplete vendor tree — removing ${VENDOR}" >&2
  rm -rf "${VENDOR}"
  mkdir -p "${VENDOR}"
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT

fetch() {
  local url="$1"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL -o "${tmpdir}/src.tgz" "${url}"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "${tmpdir}/src.tgz" "${url}"
  else
    echo "fetch_lua_vendor: need curl or wget" >&2
    return 1
  fi
}

if ! fetch "${URL}"; then
  echo "fetch_lua_vendor: primary failed, trying mirror" >&2
  fetch "${MIRROR}"
fi

tar -xzf "${tmpdir}/src.tgz" -C "${tmpdir}"

src=""
# Official release: lua-5.4.7/src/{lua.h,onelua.c,...}
for d in "${tmpdir}/lua-"*/src "${tmpdir}/lua-"* "${tmpdir}/lua/src" "${tmpdir}/lua"; do
  if [[ -d "${d}" && -f "${d}/lua.h" ]]; then
    src="${d}"
    break
  fi
done
if [[ -z "${src}" ]]; then
  echo "fetch_lua_vendor: lua.h not found in archive" >&2
  exit 1
fi

# Prefer onelua amalgam if present; else copy all .c/.h for MAKE_LIB build.
cp -f "${src}"/*.h "${VENDOR}/" 2>/dev/null || true
if [[ -f "${src}/onelua.c" ]]; then
  cp -f "${src}/onelua.c" "${VENDOR}/"
else
  # GitHub layout may lack onelua — synthesize amalgam include list via copying sources.
  for f in "${src}"/*.c; do
    [[ -f "${f}" ]] || continue
    base="$(basename "${f}")"
    case "${base}" in
      lua.c|luac.c) continue ;;
    esac
    cp -f "${f}" "${VENDOR}/"
  done
  # Create a minimal onelua.c that includes the core files if missing.
  if [[ ! -f "${VENDOR}/onelua.c" ]]; then
    cat > "${VENDOR}/onelua.c" <<'EOF'
#define MAKE_LIB
#include "lapi.c"
#include "lcode.c"
#include "lctype.c"
#include "ldebug.c"
#include "ldo.c"
#include "ldump.c"
#include "lfunc.c"
#include "lgc.c"
#include "llex.c"
#include "lmem.c"
#include "lobject.c"
#include "lopcodes.c"
#include "lparser.c"
#include "lstate.c"
#include "lstring.c"
#include "ltable.c"
#include "ltm.c"
#include "lundump.c"
#include "lvm.c"
#include "lzio.c"
#include "lauxlib.c"
#include "lbaselib.c"
#include "lcorolib.c"
#include "ldblib.c"
#include "liolib.c"
#include "lmathlib.c"
#include "loadlib.c"
#include "loslib.c"
#include "lstrlib.c"
#include "ltablib.c"
#include "lutf8lib.c"
#include "linit.c"
EOF
  fi
fi

if ! have_vendor; then
  echo "fetch_lua_vendor: incomplete vendor tree after extract" >&2
  ls -la "${VENDOR}" >&2 || true
  exit 1
fi

echo "fetch_lua_vendor: installed Lua ${VER} sources in ${VENDOR}"
ls -1 "${VENDOR}" | head -30
