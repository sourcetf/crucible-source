#!/bin/sh
# Build Go native sidecar into deps/bin/index (OpenBSD: c-shared unavailable).
#
# 没有 Go 工具链的部署机（例如远程 1 vCPU 的生产机）走 `prebuilt/index` 兜底：
# 把一台有 Go 的机器上编译好的 CGO_ENABLED=0 静态二进制放到本目录的 prebuilt/index
# （**不放在 deps/ 下** —— deps 每次 ensure 都会整体重建，放里面会被清掉），
# init.sh 直接安装它。这样远程不需要装 Go 也能用 /go/。
#
# 注意：宿主（src/server/apps/deps.rs）用 **sh** 执行 init.sh，不是 bash。
# 旧版本这里写了 `set -o pipefail` 与 `[[ ]]`：dash 下 `[[: not found`（真机日志），
# 脚本后半段行为不可预期。必须是 POSIX sh。
set -eu
ROOT="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "${ROOT}/deps/bin"
export PATH="/usr/local/bin:${HOME}/go/bin:${PATH:-}"

if command -v go >/dev/null 2>&1; then
  (
    cd "${ROOT}"
    if [ ! -f go.mod ]; then
      go mod init www-apps-go >/dev/null 2>&1 || true
    fi
    CGO_ENABLED=0 go build -o "${ROOT}/deps/bin/index" .
  )
  echo "built deps/bin/index (go sidecar)"
  exit 0
fi

if [ -x "${ROOT}/prebuilt/index" ]; then
  cp -f "${ROOT}/prebuilt/index" "${ROOT}/deps/bin/index"
  chmod +x "${ROOT}/deps/bin/index"
  echo "installed prebuilt go sidecar (no go toolchain on host)"
  exit 0
fi

echo "ERROR: go required (or provide prebuilt/index)" >&2
exit 1
