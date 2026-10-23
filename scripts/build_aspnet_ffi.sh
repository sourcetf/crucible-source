#!/usr/bin/env bash
# Build ASP.NET hostfxr FFI + libapp_aspnet.so (appengine ABI) + 最小 managed 样例
# (www-apps/aspnet/bin/CrucibleAspNetSample.dll；无 dotnet SDK 时跳过，mini 渲染器兜底).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# 产物目录：默认 ${ROOT}/target/app-engines，可用 CRUCIBLE_APP_ENGINES_OUT 覆盖
# （与 build_app_engines.sh / build_script_ffi.sh 同一套语义；否则被主构建脚本调用时
#  dry-run/自定义 OUT 仍会重写现役产物）。
OUT="${CRUCIBLE_APP_ENGINES_OUT:-${ROOT}/target/app-engines}"
SRC="${ROOT}/libs/aspnet-ffi"
INC="${ROOT}/libs/app-engines/include"
COMMON="${ROOT}/libs/app-engines/common"
CC="${CC:-cc}"
mkdir -p "${OUT}"

# 用户级 .NET（hostfxr/runtime/SDK）自动进 DOTNET_ROOT/PATH；没有 SDK 时下面的
# managed 样例构建会明确告警，但 C 引擎照常构建（有 hostfxr 就能跑已有 dll）。
# shellcheck source=scripts/runtime_env.sh
. "${ROOT}/scripts/runtime_env.sh"

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

# ---- 最小 real ASP.NET（hostfxr 进程内）样例 ------------------------------
# 规格 §16.6 要求 ASP.NET 走 hostfxr 进程内 FFI（不是 Kestrel 反代）。
# 只有 hostfxr 而没有托管程序集时引擎只能跑 mini 渲染器 —— 因此这里用 dotnet SDK
# 编一个最小 managed handler（www-apps/aspnet/bin/CrucibleAspNetSample.dll +
# runtimeconfig.json），让 /aspnet/ 真正经过 CoreCLR。没有 SDK 时跳过并告警
# （C 引擎仍可用；CRUCIBLE_REQUIRE_DOTNET=1 时视为构建失败）。
if [[ -x "${ROOT}/scripts/build_aspnet_managed_sample.sh" ]]; then
  if bash "${ROOT}/scripts/build_aspnet_managed_sample.sh"; then
    :
  else
    echo "WARN: ASP.NET managed 样例构建失败（/aspnet/ 将退回 mini 渲染器）" >&2
    if [[ "${CRUCIBLE_REQUIRE_DOTNET:-0}" == "1" ]]; then
      exit 1
    fi
  fi
fi
