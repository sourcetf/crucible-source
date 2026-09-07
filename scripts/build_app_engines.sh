#!/usr/bin/env bash
# Build Crucible app-engine artifacts (reads GO_ENGINE_MODE from configure: ffi|shm).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${ROOT}/target/app-engines"
INC="${ROOT}/libs/app-engines/include"
COMMON="${ROOT}/libs/app-engines/common"
SAMPLES="${ROOT}/libs/app-engines/samples"
LUA_DIR="${ROOT}/libs/app-engines/lua"
GO_SHM_DIR="${ROOT}/libs/app-engines/go-shm"
GO_ENGINE_MODE="${GO_ENGINE_MODE:-ffi}"
if [[ -f "${ROOT}/config.mk" ]]; then
  _mode="$(grep '^GO_ENGINE_MODE' "${ROOT}/config.mk" | sed 's/.*:= *//' || true)"
  if [[ -n "${_mode}" ]]; then
    GO_ENGINE_MODE="${_mode}"
  fi
fi

export PATH="/usr/local/bin:/usr/bin:/bin:${PATH:-}"

if [[ -x /usr/local/bin/gcc ]]; then
  CC=/usr/local/bin/gcc
elif command -v gcc >/dev/null 2>&1; then
  CC="$(command -v gcc)"
else
  CC=cc
fi

mkdir -p "${OUT}"

CFLAGS="-O2 -fPIC -pthread -I${INC} -I${COMMON}"
LDFLAGS="-shared -fPIC -pthread"
COMMON_SRC="${COMMON}/appengine_common.c ${COMMON}/appengine_util.c"

echo "==> GO_ENGINE_MODE=${GO_ENGINE_MODE}"

echo "==> building libapp_c.so (CC=${CC})"
${CC} ${CFLAGS} ${LDFLAGS} \
  -o "${OUT}/libapp_c.so" \
  "${SAMPLES}/c-plugin/plugin.c" \
  ${COMMON_SRC}

echo "==> building libapp_lua.so"
LUA_CFLAGS="${CFLAGS}"
LUA_LIBS=""
detect_lua() {
  # §13-6: vendored PUC-Lua amalgam 优先（禁 stub、禁系统 lua 版本错配导致的高并发 abort）。
  if [[ -f "${LUA_DIR}/vendor/lua.h" && -f "${LUA_DIR}/vendor/lprefix.h" && -f "${LUA_DIR}/vendor/onelua.c" ]]; then
    LUA_CFLAGS="${CFLAGS} -I${LUA_DIR}/vendor -DCRUCIBLE_HAVE_LUA -DMAKE_LIB"
    LUA_LIBS=""
    echo "    using vendored Lua amalgam at ${LUA_DIR}/vendor"
    return 0
  fi
  if pkg-config --exists lua5.4 2>/dev/null; then
    LUA_CFLAGS="${CFLAGS} $(pkg-config --cflags lua5.4) -DCRUCIBLE_HAVE_LUA"
    LUA_LIBS="$(pkg-config --libs lua5.4)"
    return 0
  fi
  if pkg-config --exists lua54 2>/dev/null; then
    LUA_CFLAGS="${CFLAGS} $(pkg-config --cflags lua54) -DCRUCIBLE_HAVE_LUA"
    LUA_LIBS="$(pkg-config --libs lua54)"
    return 0
  fi
  if pkg-config --exists lua5.3 2>/dev/null; then
    LUA_CFLAGS="${CFLAGS} $(pkg-config --cflags lua5.3) -DCRUCIBLE_HAVE_LUA"
    LUA_LIBS="$(pkg-config --libs lua5.3)"
    return 0
  fi
  if pkg-config --exists lua53 2>/dev/null; then
    LUA_CFLAGS="${CFLAGS} $(pkg-config --cflags lua53) -DCRUCIBLE_HAVE_LUA"
    LUA_LIBS="$(pkg-config --libs lua53)"
    return 0
  fi
  if pkg-config --exists lua 2>/dev/null; then
    LUA_CFLAGS="${CFLAGS} $(pkg-config --cflags lua) -DCRUCIBLE_HAVE_LUA"
    LUA_LIBS="$(pkg-config --libs lua)"
    return 0
  fi
  # OpenBSD ports commonly ship lua-5.1; also try 5.2 / generic names.
  if pkg-config --exists lua5.2 2>/dev/null; then
    LUA_CFLAGS="${CFLAGS} $(pkg-config --cflags lua5.2) -DCRUCIBLE_HAVE_LUA"
    LUA_LIBS="$(pkg-config --libs lua5.2)"
    return 0
  fi
  if pkg-config --exists lua52 2>/dev/null; then
    LUA_CFLAGS="${CFLAGS} $(pkg-config --cflags lua52) -DCRUCIBLE_HAVE_LUA"
    LUA_LIBS="$(pkg-config --libs lua52)"
    return 0
  fi
  if pkg-config --exists lua5.1 2>/dev/null; then
    LUA_CFLAGS="${CFLAGS} $(pkg-config --cflags lua5.1) -DCRUCIBLE_HAVE_LUA"
    LUA_LIBS="$(pkg-config --libs lua5.1)"
    return 0
  fi
  if pkg-config --exists lua51 2>/dev/null; then
    LUA_CFLAGS="${CFLAGS} $(pkg-config --cflags lua51) -DCRUCIBLE_HAVE_LUA"
    LUA_LIBS="$(pkg-config --libs lua51)"
    return 0
  fi
  # OpenBSD / manual installs: /usr/local/include/lua*
  local hdr=""
  for cand in \
    /usr/local/include/lua54/lua.h \
    /usr/local/include/lua5.4/lua.h \
    /usr/local/include/lua53/lua.h \
    /usr/local/include/lua5.3/lua.h \
    /usr/local/include/lua-5.4/lua.h \
    /usr/local/include/lua-5.3/lua.h \
    /usr/local/include/lua52/lua.h \
    /usr/local/include/lua5.2/lua.h \
    /usr/local/include/lua-5.2/lua.h \
    /usr/local/include/lua51/lua.h \
    /usr/local/include/lua5.1/lua.h \
    /usr/local/include/lua-5.1/lua.h \
    /usr/local/include/lua.h \
    /usr/include/lua.h
  do
    if [[ -f "${cand}" ]]; then
      hdr="${cand}"
      break
    fi
  done
  if [[ -z "${hdr}" ]]; then
    # glob fallback (prefer higher version dirs when sorted reverse)
    local d
    for d in $(ls -1d /usr/local/include/lua* 2>/dev/null | sort -r || true); do
      if [[ -f "${d}/lua.h" ]]; then
        hdr="${d}/lua.h"
        break
      fi
    done
  fi
  if [[ -n "${hdr}" ]]; then
    local idir
    idir="$(dirname "${hdr}")"
    LUA_CFLAGS="${CFLAGS} -I${idir} -DCRUCIBLE_HAVE_LUA"
    for lib in lua54 lua5.4 lua53 lua5.3 lua52 lua5.2 lua51 lua5.1 lua-5.1 lua; do
      local found=0
      local f
      for f in \
        "/usr/local/lib/lib${lib}.so" "/usr/local/lib/lib${lib}.a" \
        "/usr/lib/lib${lib}.so" "/usr/lib/lib${lib}.a" \
        /usr/local/lib/lib${lib}.so.* /usr/local/lib/lib${lib}.a.* \
        /usr/lib/lib${lib}.so.* /usr/lib/lib${lib}.a.*
      do
        if [[ -f "${f}" ]]; then
          found=1
          break
        fi
      done
      if [[ "${found}" -eq 1 ]]; then
        LUA_LIBS="-l${lib}"
        break
      fi
    done
    # OpenBSD lua-5.1: headers in lua-5.1/, library often liblua5.1.a
    if [[ -z "${LUA_LIBS}" ]]; then
      case "${idir}" in
        *lua-5.1*|*lua5.1*|*lua51*) LUA_LIBS="-llua5.1" ;;
        *lua-5.2*|*lua5.2*|*lua52*) LUA_LIBS="-llua5.2" ;;
        *lua-5.3*|*lua5.3*|*lua53*) LUA_LIBS="-llua5.3" ;;
        *lua-5.4*|*lua5.4*|*lua54*) LUA_LIBS="-llua5.4" ;;
        *) LUA_LIBS="-llua" ;;
      esac
    fi
    echo "    detected Lua headers at ${hdr} libs=${LUA_LIBS}"
    return 0
  fi
  # Optional: embed vendored lua amalgam if present under libs/app-engines/lua/vendor
  if [[ -f "${LUA_DIR}/vendor/lua.h" && -f "${LUA_DIR}/vendor/lprefix.h" && -f "${LUA_DIR}/vendor/onelua.c" ]]; then
    LUA_CFLAGS="${CFLAGS} -I${LUA_DIR}/vendor -DCRUCIBLE_HAVE_LUA -DMAKE_LIB"
    LUA_LIBS=""
    echo "    using vendored Lua amalgam at ${LUA_DIR}/vendor"
    return 0
  fi
  echo "WARN: Lua headers not found — attempting fetch_lua_vendor.sh ..." >&2
  if [[ -x "${ROOT}/scripts/fetch_lua_vendor.sh" ]]; then
    bash "${ROOT}/scripts/fetch_lua_vendor.sh" || true
    if [[ -f "${LUA_DIR}/vendor/onelua.c" && -f "${LUA_DIR}/vendor/lprefix.h" && -f "${LUA_DIR}/vendor/lua.h" ]]; then
      LUA_CFLAGS="${CFLAGS} -I${LUA_DIR}/vendor -DCRUCIBLE_HAVE_LUA -DMAKE_LIB"
      LUA_LIBS=""
      echo "    fetched vendored Lua amalgam at ${LUA_DIR}/vendor"
      return 0
    fi
  fi
  echo "FAIL: no system Lua and no vendor/lprefix.h+onelua.c — refusing stub libapp_lua.so" >&2
  return 1
}
detect_lua || exit 1
if ! echo "${LUA_CFLAGS}" | grep -q 'CRUCIBLE_HAVE_LUA'; then
  echo "FAIL: Lua build without CRUCIBLE_HAVE_LUA" >&2
  exit 1
fi
if [[ -f "${LUA_DIR}/vendor/onelua.c" && -f "${LUA_DIR}/vendor/lprefix.h" ]] && echo "${LUA_CFLAGS}" | grep -q 'vendor'; then
  ${CC} ${LUA_CFLAGS} ${LDFLAGS} \
    -o "${OUT}/libapp_lua.so" \
    "${LUA_DIR}/lua_engine.c" \
    "${LUA_DIR}/vendor/onelua.c" \
    ${COMMON_SRC} || { echo "FAIL: vendored lua compile"; exit 1; }
else
  ${CC} ${LUA_CFLAGS} ${LDFLAGS} \
    -o "${OUT}/libapp_lua.so" \
    "${LUA_DIR}/lua_engine.c" \
    ${COMMON_SRC} \
    ${LUA_LIBS} || { echo "FAIL: system lua compile"; exit 1; }
fi
# Sanity: real Lua symbols must exist (not a stub).
if command -v nm >/dev/null 2>&1; then
  if ! nm -D "${OUT}/libapp_lua.so" 2>/dev/null | grep -q 'lua_pcall\|luaL_newstate'; then
    if ! nm "${OUT}/libapp_lua.so" 2>/dev/null | grep -q 'lua_pcall\|luaL_newstate'; then
      echo "FAIL: libapp_lua.so missing lua_pcall — stub build detected" >&2
      exit 1
    fi
  fi
fi
echo "    libapp_lua.so OK (CRUCIBLE_HAVE_LUA)"

build_stub_engine() {
  local name="$1"
  local src="${ROOT}/libs/app-engines/${name}/${name}_engine.c"
  if [[ ! -f "${src}" ]]; then
    echo "WARN: missing ${src}" >&2
    return 0
  fi
  echo "==> building libapp_${name}.so"
  ${CC} ${CFLAGS} ${LDFLAGS} \
    -o "${OUT}/libapp_${name}.so" \
    "${src}" \
    ${COMMON_SRC}
}

for eng in wsgi asgi psgi rack cgi uwsgi tsx; do
  build_stub_engine "${eng}"
done

echo "==> building libapp_asp.so (AxonASP engine)"
if [[ -f "${ROOT}/libs/axonasp-ffi/axonasp_engine.c" ]]; then
  ${CC} ${CFLAGS} ${LDFLAGS} \
    -o "${OUT}/libapp_asp.so" \
    "${ROOT}/libs/axonasp-ffi/axonasp_engine.c" \
    ${COMMON_SRC}
fi

echo "==> building libapp_aspnet.so"
if [[ -f "${ROOT}/libs/aspnet-ffi/aspnet_engine.c" ]]; then
  ${CC} ${CFLAGS} ${LDFLAGS} \
    -o "${OUT}/libapp_aspnet.so" \
    "${ROOT}/libs/aspnet-ffi/aspnet_engine.c" \
    ${COMMON_SRC} \
    -ldl || \
  ${CC} ${CFLAGS} ${LDFLAGS} \
    -o "${OUT}/libapp_aspnet.so" \
    "${ROOT}/libs/aspnet-ffi/aspnet_engine.c" \
    ${COMMON_SRC}
fi

# Script engines: prefer in-process via build_script_ffi.sh (CRUCIBLE_HAVE_*).
# Keep a direct fallback build here if that script is skipped.
build_script_engine() {
  local lang="$1"
  echo "==> building libapp_${lang}.so (scriptffi; see build_script_ffi.sh for HAVE_* flags)"
  ${CC} ${CFLAGS} -DCRUCIBLE_SCRIPT_LANG='"'"${lang}"'"' ${LDFLAGS} \
    -o "${OUT}/libapp_${lang}.so" \
    "${ROOT}/libs/script-ffi/script_engine.c" \
    ${COMMON_SRC}
}

for lang in python ruby perl; do
  build_script_engine "${lang}"
done
# CRUCIBLE_HAVE_* in-process flags applied by auxiliary build_script_ffi.sh below.

echo "==> building Go engine (${GO_ENGINE_MODE})"
HOST_OS="$(uname -s | tr "[:upper:]" "[:lower:]")"
if command -v go >/dev/null 2>&1; then
  # OpenBSD: Go has no -buildmode=c-shared/c-archive on amd64. Production path is
  # go-shm-server (shared-memory IPC). Linux uses in-process FFI libapp_go.so.
  if [[ "${GO_ENGINE_MODE}" == shm || "${HOST_OS}" == openbsd ]]; then
    SHM_BIN="${OUT}/go-shm-server"
    mkdir -p "${OUT}"
    (
      cd "${GO_SHM_DIR}"
      CGO_ENABLED=0 go build -o "${SHM_BIN}" .
    )
    echo "built ${SHM_BIN} (shared-memory IPC server; OpenBSD production Go path)"
    if [[ "${HOST_OS}" == openbsd ]]; then
      cat > "${OUT}/README-go-openbsd.txt" <<EOF
Crucible Go app engine on OpenBSD
=================================

Go cannot use -buildmode=c-shared or c-archive on openbsd/amd64, so
libapp_go.so (in-process FFI) is Linux-only.

On OpenBSD, configure sets GO_ENGINE_MODE=shm and enables Cargo feature
go_shm_ipc. The webserver spawns target/app-engines/go-shm-server and
talks over shared memory + a Unix notify socket (see src/server/apps/go_shm.rs).

config.toml may still list lib = "target/app-engines/libapp_go.so"; a missing
.so is fine when go-shm-server is present (dispatch falls back to go_shm).

Build: make engines  (or this script with GO_ENGINE_MODE=shm)
Binary: ${OUT}/go-shm-server
EOF
      echo "wrote ${OUT}/README-go-openbsd.txt"
      echo "SKIP: libapp_go.so c-shared (unsupported on openbsd/amd64; using go-shm IPC)"
    else
      echo "NOTE: GO_ENGINE_MODE=shm — skipping libapp_go.so c-shared; using go-shm IPC"
    fi
  else
    # Linux / ffi: in-process FFI .so (spec §7.3)
    if (
      cd "${SAMPLES}/go-plugin"
      CGO_ENABLED=1 go build -buildmode=c-shared -o "${OUT}/libapp_go.so" .
    ); then
      echo "built ${OUT}/libapp_go.so (c-shared FFI)"
    else
      echo "WARN: go c-shared build failed" >&2
    fi
  fi
else
  echo "WARN: go not found" >&2
fi

echo "==> building libapp_rust.so"
if command -v cargo >/dev/null 2>&1; then
  (
    unset CARGO_TARGET_DIR || true
    cd "${SAMPLES}/rust-plugin"
    cargo build --release
    SO=""
    for cand in \
      "${SAMPLES}/rust-plugin/target/release/libapp_rust.so" \
      "${ROOT}/target/release/libapp_rust.so"
    do
      if [[ -f "${cand}" ]]; then SO="${cand}"; break; fi
    done
    if [[ -z "${SO}" ]]; then
      SO="$(find "${SAMPLES}/rust-plugin/target" -name 'libapp_rust.so' 2>/dev/null | head -n1 || true)"
    fi
    if [[ -n "${SO}" && -f "${SO}" ]]; then
      cp -f "${SO}" "${OUT}/libapp_rust.so"
    else
      echo "WARN: libapp_rust.so not found" >&2
    fi
  )
else
  echo "WARN: cargo not found" >&2
fi

echo "==> building auxiliary FFI libs (script-ffi / aspnet / axonasp / jsp)"
bash "${ROOT}/scripts/build_script_ffi.sh" || true
bash "${ROOT}/scripts/build_aspnet_ffi.sh" || true
bash "${ROOT}/scripts/build_axonasp_ffi.sh" || true
bash "${ROOT}/scripts/build_jsp_sidecar.sh" || true

echo "==> done. artifacts in ${OUT}"
ls -la "${OUT}" || true
