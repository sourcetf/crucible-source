#!/usr/bin/env bash
# Build Crucible app-engine artifacts (reads GO_ENGINE_MODE from configure: ffi|shm).
#
# 默认行为：**缺工具链 = 失败**。旧实现遇 `command -v go` / `command -v cargo` 判空就
# 打印一行 WARN 静默跳过，于是「rust/go 没重建但 target/app-engines 里还留着旧 .so」——
# 运维以为建好了，实际跑的是旧产物（host 的 ABI 校验只会把它 502 掉，功能面等于缺引擎）。
# 现在：所有工具链缺失/构建失败在结尾**集中汇总并非零退出**；显式
# `--allow-missing`（或 CRUCIBLE_ALLOW_MISSING_ENGINES=1）才允许降级为警告并退出 0。
#
# 产物目录：默认 ${ROOT}/target/app-engines，可用 CRUCIBLE_APP_ENGINES_OUT 覆盖
# （远程真机验证/CI 想在不碰现役 .so 的前提下跑一遍构建时用这个）。
#
# ---------------------------------------------------------------------------
# 解释器自检 —— 必须是文件里**第一段可执行代码**：本脚本用 bash 语法（数组、[[ ]]）。
# OpenBSD 的 /bin/sh 是 ksh：`sh scripts/build_app_engines.sh` 在 ksh 下解析到第一个
# bash-only 语法（`local found=() a`）就 `syntax error: '(' unexpected` 直接退出
# （实测 OpenBSD 7.9，2026-10-16 部署，一个引擎都没建，极易被当成构建成功）。
# ksh/dash 都是「逐条解析、逐条执行」，所以只要在最前面 exec 到 bash，后面的
# bash-only 语法根本没机会被解析。缺少 bash 时给出可读错误而不是语法错误。
# ---------------------------------------------------------------------------
if [ -z "${BASH_VERSION:-}" ]; then
  _cr_bash=""
  for _cr_cand in bash /usr/local/bin/bash /usr/bin/bash /bin/bash; do
    # 绝对路径候选同时用 -x 复核：`command -v /abs/path` 在各家 ksh 上行为不一。
    if command -v "${_cr_cand}" >/dev/null 2>&1 || [ -x "${_cr_cand}" ]; then
      _cr_bash="${_cr_cand}"; break
    fi
  done
  # 只有「可读且带 #! 的脚本文件」才敢再 exec：`sh < script` 时 $0 是 sh 自己，
  # 对二进制再 exec 只会得到 "cannot execute binary file"。
  _cr_self=""
  if [ -f "$0" ] && [ -r "$0" ]; then
    IFS= read -r _cr_line < "$0" 2>/dev/null || _cr_line=""
    case "${_cr_line}" in '#!'*) _cr_self="$0" ;; esac
  fi
  if [ -z "${_cr_bash}" ]; then
    echo "FATAL: $0 需要 bash（本脚本用数组/[[ ]] 语法，ksh/sh 不支持）。" >&2
    echo "       当前解释器没有 BASH_VERSION，PATH 里也找不到 bash。" >&2
    echo "       OpenBSD: pkg_add bash；或显式调用: bash $0 $*" >&2
    exit 1
  fi
  if [ -z "${_cr_self}" ]; then
    echo "FATAL: $0 需要 bash（本脚本用数组/[[ ]] 语法），但无法自动重新执行：" >&2
    echo "       \"$0\" 不是可读的脚本文件（例如把脚本管道进 sh）；请先落盘再执行：bash <脚本路径>" >&2
    exit 1
  fi
  echo "==> 检测到非 bash 解释器，自动改用 ${_cr_bash} 重新执行 ${_cr_self}" >&2
  exec "${_cr_bash}" "${_cr_self}" "$@"
fi
set -euo pipefail

ALLOW_MISSING=0
for _arg in "$@"; do
  case "${_arg}" in
    --allow-missing) ALLOW_MISSING=1 ;;
    -h|--help)
      echo "usage: $0 [--allow-missing]"
      echo "  --allow-missing  缺 go/cargo 等工具链时只告警（退出 0），默认非零退出"
      echo "  环境变量：CRUCIBLE_APP_ENGINES_OUT=<dir>  指定产物目录（默认 <root>/target/app-engines）"
      echo "            CRUCIBLE_ALLOW_MISSING_ENGINES=1 同 --allow-missing"
      echo "  本脚本需要 bash（OpenBSD 的 /bin/sh 是 ksh）：用 sh 调用会自动 re-exec 到 bash。"
      exit 0
      ;;
    *) echo "WARN: unknown argument '${_arg}'（忽略；可用 --allow-missing）" >&2 ;;
  esac
done
[[ "${CRUCIBLE_ALLOW_MISSING_ENGINES:-0}" == "1" ]] && ALLOW_MISSING=1

# 缺工具链 / 构建失败的汇总（结尾统一处理）。
MISSING_TOOLCHAIN=()
BUILD_FAILURES=()

note_missing_tool() {
  local tool="$1"; shift
  local found=() a
  for a in "$@"; do
    [[ -e "${OUT}/${a}" ]] && found+=("${a}")
  done
  if [[ ${#found[@]} -gt 0 ]]; then
    MISSING_TOOLCHAIN+=("${tool} — 对应产物**未重建，旧产物仍在**：${found[*]}（旧 .so 会被 host ABI 校验挡下，但千万别当成新构建）")
  else
    MISSING_TOOLCHAIN+=("${tool} — 对应产物缺失（该引擎将走 sidecar 或 502）")
  fi
}

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# 用户级运行时（php/ruby/java/maven/node/dotnet 由 scripts/install_app_runtimes.sh
# 装到 ~/local）：自动进 PATH/LD_LIBRARY_PATH/JAVA_HOME，否则 build_script_ffi.sh
# 找不到 ruby.h、build_jsp_sidecar.sh 找不到 mvn/javac。
# shellcheck source=scripts/runtime_env.sh
. "${ROOT}/scripts/runtime_env.sh"
OUT="${CRUCIBLE_APP_ENGINES_OUT:-${ROOT}/target/app-engines}"
INC="${ROOT}/libs/app-engines/include"
COMMON="${ROOT}/libs/app-engines/common"
SAMPLES="${ROOT}/libs/app-engines/samples"
LUA_DIR="${ROOT}/libs/app-engines/lua"
GO_SHM_DIR="${ROOT}/libs/app-engines/go-shm"
HOST_OS="$(uname -s | tr "[:upper:]" "[:lower:]")"
# GO_ENGINE_MODE 优先级：显式环境变量 > config.mk（**仅当它为目标机生成时**）> ffi。
# config.mk 是 configure 在目标机（生产 OpenBSD）生成的跟踪文件；在 Linux 开发机
# 上它写着 TARGET_OS=openbsd + GO_ENGINE_MODE=shm，照抄会**跳过 Linux 能用的
# c-shared**（/go/ 只能走 sidecar，规格 §7.3 的 in-process FFI 无法验证）。
# 只在「config.mk 的 TARGET_OS == 本机 uname」时才采纳它的模式。
GO_ENGINE_MODE_EXPLICIT="${GO_ENGINE_MODE:-}"
GO_ENGINE_MODE="${GO_ENGINE_MODE:-ffi}"
if [[ -f "${ROOT}/config.mk" ]]; then
  _mode="$(grep '^GO_ENGINE_MODE' "${ROOT}/config.mk" | sed 's/.*:= *//' || true)"
  _target="$(grep '^TARGET_OS' "${ROOT}/config.mk" | sed 's/.*:= *//' || true)"
  if [[ -n "${GO_ENGINE_MODE_EXPLICIT}" ]]; then
    GO_ENGINE_MODE="${GO_ENGINE_MODE_EXPLICIT}"
  elif [[ -n "${_mode}" && ( -z "${_target}" || "${_target}" == "${HOST_OS}" ) ]]; then
    GO_ENGINE_MODE="${_mode}"
  elif [[ -n "${_mode}" ]]; then
    echo "NOTE: config.mk TARGET_OS=${_target} ≠ 本机 ${HOST_OS}；忽略其中的 GO_ENGINE_MODE=${_mode}（按 ${GO_ENGINE_MODE} 构建）"
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
# 编译器的可读前置检查：没有它的话 ${CC} 会在第一条编译命令处
# `cc: not found` + set -e 直接退出 127，看不出是谁的问题。
if ! command -v "${CC}" >/dev/null 2>&1; then
  echo "FATAL: C 编译器 '${CC}' 不存在（\$CC / PATH 里都没有）；无法构建任何引擎。" >&2
  echo "       OpenBSD: 装了 base 的 cc，或 pkg_add gcc；也可显式 CC=/path/to/cc $0" >&2
  exit 1
fi

mkdir -p "${OUT}"

# -Werror=implicit-function-declaration：隐式声明会把返回值当 int，
# 64 位指针被截成 32 位——c-plugin 的 getenv 就这么把返回值截断后解引用，
# 一次 /c/ 请求直接把整个服务器打崩（SIGSEGV）。让它在编译期就失败。
CFLAGS="-O2 -fPIC -pthread -Wall -Werror=implicit-function-declaration -I${INC} -I${COMMON}"
LDFLAGS="-shared -fPIC -pthread"
COMMON_SRC="${COMMON}/appengine_common.c ${COMMON}/appengine_util.c"

echo "==> GO_ENGINE_MODE=${GO_ENGINE_MODE}  OUT=${OUT}"

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
# grep -E 而非 BRE `\|`：BSD grep 把 `\|` 当字面量，`grep -q 'a\|b'` 永不匹配，
# 这道门会恒为假失败。PUC-Lua 5.4 导出的是 lua_pcallk（lua_pcall 是宏），
# 用子串匹配即可同时覆盖 5.3/5.4。
# 注意：`nm | grep -q` 在 `set -o pipefail` 下会**假失败** —— grep 命中即退出，
# nm 继续写符号表收到 SIGPIPE（141），管道整体非零。先把输出收进变量再匹配。
if command -v nm >/dev/null 2>&1; then
  lua_syms="$(nm -D "${OUT}/libapp_lua.so" 2>/dev/null || true)"
  if ! grep -qE 'lua_pcall|luaL_newstate' <<<"${lua_syms}"; then
    lua_syms="$(nm "${OUT}/libapp_lua.so" 2>/dev/null || true)"
    if ! grep -qE 'lua_pcall|luaL_newstate' <<<"${lua_syms}"; then
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

# ---- Rack：MRI Ruby 真嵌入由 build_script_ffi.sh 统一构建 -------------------
# 这里原先还单独编一次 rack（为了绕开旧 build_extra_engine 拼接 RB_CFLAGS 的坑）。
# 那个坑已在 build_script_ffi.sh 修好（-L/-rpath + 平台默认 + stub 重建），而且本
# 脚本末尾必定调用 build_script_ffi.sh；再编一次只会产生一条「先失败后覆盖」的
# 误导日志。保留一个空函数占位，明确产物来源。
build_rack_engine() {
  # rack 的嵌入式 MRI 构建**只在 build_script_ffi.sh 里做一次**（平台默认：
  # Linux 开 / OpenBSD 关），本脚本末尾必定调用它。此前这里也编一遍，用的是
  # rbconfig 的原始 -lruby-3.3（没有 -L ~/local/...，用户级 ruby 下必然链接失败）
  # 后「回退诚实失败 stub」，而随后 build_script_ffi 又成功覆盖为嵌入式 ——
  # 构建日志里出现一条吓人的失败，最终产物却是好的。删除重复构建。
  echo "    rack: 由 build_script_ffi.sh 统一构建（in-process Ruby / 诚实失败按平台默认）"
}

build_rack_engine

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
# go 的位置：$GO 优先（buildenv 一类环境导出绝对路径），其次 PATH。
GO_BIN="${GO:-}"
if [[ -z "${GO_BIN}" ]] && command -v go >/dev/null 2>&1; then
  GO_BIN="$(command -v go)"
fi
[[ -x "${GO_BIN}" ]] || GO_BIN=""
if [[ -n "${GO_BIN}" ]]; then
  # OpenBSD: Go has no -buildmode=c-shared/c-archive on amd64. Production path is
  # go-shm-server (shared-memory IPC). Linux uses in-process FFI libapp_go.so.
  if [[ "${GO_ENGINE_MODE}" == shm || "${HOST_OS}" == openbsd ]]; then
    SHM_BIN="${OUT}/go-shm-server"
    mkdir -p "${OUT}"
    if (
      cd "${GO_SHM_DIR}"
      CGO_ENABLED=0 "${GO_BIN}" build -o "${SHM_BIN}" .
    ); then
      echo "built ${SHM_BIN} (shared-memory IPC server; OpenBSD production Go path)"
    else
      BUILD_FAILURES+=("go-shm-server 构建失败（go build 返回非零，见上方输出）")
    fi
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
      CGO_ENABLED=1 "${GO_BIN}" build -buildmode=c-shared -o "${OUT}/libapp_go.so" .
    ); then
      echo "built ${OUT}/libapp_go.so (c-shared FFI)"
    else
      BUILD_FAILURES+=("go c-shared build 失败（libapp_go.so 未重建）")
      echo "WARN: go c-shared build failed" >&2
    fi
  fi
else
  echo "WARN: go not found（\$GO / PATH 都没有可执行的 go）" >&2
  note_missing_tool "go" libapp_go.so go-shm-server
fi

echo "==> building libapp_rust.so"
# cargo 的位置：$CARGO 优先（buildenv 只导出 $CARGO 绝对路径、不一定改 PATH ——
# 旧实现的 `command -v cargo` 在这种环境下判空，直接静默跳过 rust 引擎），
# 其次 PATH，最后 ~/.cargo/bin。
CARGO_BIN="${CARGO:-}"
if [[ ! -x "${CARGO_BIN}" ]]; then
  CARGO_BIN="$(command -v cargo 2>/dev/null || true)"
fi
if [[ ! -x "${CARGO_BIN}" ]] && [[ -x "${HOME:-}/.cargo/bin/cargo" ]]; then
  CARGO_BIN="${HOME:-}/.cargo/bin/cargo"
fi
if [[ -x "${CARGO_BIN}" ]]; then
  if (
    unset CARGO_TARGET_DIR || true
    cd "${SAMPLES}/rust-plugin"
    "${CARGO_BIN}" build --release
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
      exit 3
    fi
  ); then
    :
  else
    rc=$?
    if [[ ${rc} -eq 3 ]]; then
      BUILD_FAILURES+=("cargo 构建成功但没有产出 libapp_rust.so")
    else
      BUILD_FAILURES+=("cargo build 失败（rc=${rc}）")
    fi
  fi
else
  echo "WARN: cargo not found（\$CARGO / PATH / ~/.cargo/bin 都没有可执行的 cargo）" >&2
  note_missing_tool "cargo" libapp_rust.so
fi

echo "==> building auxiliary FFI libs (script-ffi / aspnet / axonasp / jsp)"
bash "${ROOT}/scripts/build_script_ffi.sh" || BUILD_FAILURES+=("build_script_ffi.sh 返回非零（见上方输出）")
bash "${ROOT}/scripts/build_aspnet_ffi.sh" || BUILD_FAILURES+=("build_aspnet_ffi.sh 返回非零")
bash "${ROOT}/scripts/build_axonasp_ffi.sh" || BUILD_FAILURES+=("build_axonasp_ffi.sh 返回非零")
bash "${ROOT}/scripts/build_jsp_sidecar.sh" || BUILD_FAILURES+=("build_jsp_sidecar.sh 返回非零")

echo "==> done. artifacts in ${OUT}"
ls -la "${OUT}" || true

# 结尾汇总：**缺工具链 / 构建失败一律非零退出**（除非显式 --allow-missing）。
# 这是「静默跳过 → 以为建好了其实是旧 .so」的防线：脚本退出码必须能代表
# 「target/app-engines 里每一个该有这个运行时的引擎都刚刚被重建过」。
if [[ ${#MISSING_TOOLCHAIN[@]} -gt 0 || ${#BUILD_FAILURES[@]} -gt 0 ]]; then
  echo "" >&2
  echo "============ 引擎构建不完整（可能留着旧 .so）============" >&2
  for m in "${MISSING_TOOLCHAIN[@]}"; do
    echo "  MISSING: ${m}" >&2
  done
  for x in "${BUILD_FAILURES[@]}"; do
    echo "  FAILED : ${x}" >&2
  done
  echo "  危害：失败的引擎不会覆盖 target/app-engines 下的旧产物；用旧 .so 跑等于" >&2
  echo "        功能/修复都停留在旧构建（host ABI 校验只会把它 502 掉，不会静默执行）。" >&2
  if [[ "${ALLOW_MISSING}" == "1" ]]; then
    echo "  --allow-missing 已指定：降级为警告，继续。" >&2
  else
    echo "  确认接受降级时再显式传：$0 --allow-missing（或 CRUCIBLE_ALLOW_MISSING_ENGINES=1）" >&2
    exit 1
  fi
fi
