#!/bin/sh
set -e
ROOT="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "${ROOT}/deps/bin"
echo "tsx: libapp_tsx.so (npx tsx / node)" > "${ROOT}/deps/manifest.txt"
