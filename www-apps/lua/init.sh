#!/usr/bin/env bash
# Lua app deps placeholder (engine is in-process libapp_lua.so).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "${ROOT}/deps/bin"
echo "lua: FFI engine libapp_lua.so (no sidecar binary needed)" > "${ROOT}/deps/manifest.txt"
