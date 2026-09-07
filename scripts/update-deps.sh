#!/usr/bin/env bash
# Refresh vendored / workspace dependencies + optional Lua vendor amalgam.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "update-deps: cargo update --workspace"
cargo update --workspace

if [[ ! -f "${ROOT}/libs/app-engines/lua/vendor/onelua.c" ]]; then
  if [[ -x "${ROOT}/scripts/fetch_lua_vendor.sh" ]]; then
    echo "update-deps: fetching Lua vendor amalgam (optional)"
    bash "${ROOT}/scripts/fetch_lua_vendor.sh" || true
  fi
fi

echo "update-deps: done"
