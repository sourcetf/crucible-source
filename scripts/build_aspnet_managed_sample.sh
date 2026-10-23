#!/usr/bin/env bash
# 构建最小 real ASP.NET（hostfxr 进程内）托管样例：
#   libs/aspnet-ffi/managed/  →  www-apps/aspnet/bin/CrucibleAspNetSample.dll
#                              + CrucibleAspNetSample.runtimeconfig.json
#
# libapp_aspnet.so 在 <docroot>/bin/CrucibleAspNetSample.dll 存在且 hostfxr 可用时，
# 通过 hostfxr_initialize_for_runtime_config + load_assembly_and_get_function_pointer
# 进程内调用 Handler.Render（见 libs/aspnet-ffi/aspnet_engine.c）。
#
# 没有 dotnet SDK 时**不是错误**（老的 mini 渲染器仍工作）：打印 SKIP 并退出 0。
# 有 SDK 但构建失败：退出 1（让 build_aspnet_ffi.sh / 运维看见）。
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=scripts/runtime_env.sh
. "${ROOT}/scripts/runtime_env.sh"
PROJ_DIR="${ROOT}/libs/aspnet-ffi/managed"
PROJ="${PROJ_DIR}/CrucibleAspNetSample.csproj"
OUTDIR="${ROOT}/www-apps/aspnet/bin"
BUILD="${ROOT}/target/aspnet-managed"

if ! command -v dotnet >/dev/null 2>&1; then
  echo "SKIP: dotnet 不在 PATH（装：bash scripts/install_app_runtimes.sh --only=dotnet）"
  exit 0
fi
if ! dotnet --list-sdks >/dev/null 2>&1; then
  echo "SKIP: 只有 .NET runtime，没有 SDK（无法编译托管样例）"
  exit 0
fi
if [[ ! -f "${PROJ}" ]]; then
  echo "FAIL: 缺少 ${PROJ}" >&2
  exit 1
fi

mkdir -p "${OUTDIR}" "${BUILD}"
echo "==> building ASP.NET managed sample ($(dotnet --version 2>/dev/null))"
rm -rf "${BUILD:?}/obj" "${BUILD:?}/bin" "${BUILD:?}/publish"
if ! dotnet publish "${PROJ}" -c Release -o "${BUILD}/publish" --nologo \
      -p:BaseIntermediateOutputPath="${BUILD}/obj/" \
      -p:BaseOutputPath="${BUILD}/bin/" \
      -p:RestorePackagesPath="${BUILD}/nuget" \
      -v:minimal; then
  echo "FAIL: dotnet publish 失败" >&2
  exit 1
fi

DLL="${BUILD}/publish/CrucibleAspNetSample.dll"
[[ -s "${DLL}" ]] || { echo "FAIL: 未产出 ${DLL}" >&2; exit 1; }
cp -f "${DLL}" "${OUTDIR}/CrucibleAspNetSample.dll"

# 找本机 Microsoft.NETCore.App 版本，生成 hostfxr 需要的 runtimeconfig.json。
RT_VER="$(dotnet --list-runtimes 2>/dev/null \
  | awk '$1 == "Microsoft.NETCore.App" {v=$2} END {print v}')"
TFM="$(sed -n 's:.*<TargetFramework>\(.*\)</TargetFramework>.*:\1:p' "${PROJ}" | head -n1)"
[[ -n "${TFM}" ]] || TFM="net10.0"
[[ -n "${RT_VER}" ]] || RT_VER="10.0.0"
cat >"${OUTDIR}/CrucibleAspNetSample.runtimeconfig.json" <<EOF
{
  "runtimeOptions": {
    "tfm": "${TFM}",
    "framework": { "name": "Microsoft.NETCore.App", "version": "${RT_VER}" },
    "rollForward": "LatestMinor",
    "configProperties": { "System.Runtime.TieredPGO": true }
  }
}
EOF

# managed dll 可能带 .deps.json（无 NuGet 依赖时通常不需要；有就一并带上）。
if [[ -f "${BUILD}/publish/CrucibleAspNetSample.deps.json" ]]; then
  cp -f "${BUILD}/publish/CrucibleAspNetSample.deps.json" "${OUTDIR}/"
fi
echo "built ${OUTDIR}/CrucibleAspNetSample.dll (runtime ${RT_VER})"
ls -la "${OUTDIR}"
