#!/usr/bin/env bash
# Build Go native sidecar into deps/bin/index (OpenBSD: c-shared unavailable).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "${ROOT}/deps/bin"
export PATH="/usr/local/bin:${HOME}/go/bin:${PATH:-}"

if ! command -v go >/dev/null 2>&1; then
  echo "ERROR: go required" >&2
  exit 1
fi

(
  cd "${ROOT}"
  if [[ ! -f go.mod ]]; then
    go mod init www-apps-go >/dev/null 2>&1 || true
  fi
  CGO_ENABLED=0 go build -o "${ROOT}/deps/bin/index" .
)
echo "built deps/bin/index (go sidecar)"
