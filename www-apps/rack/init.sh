#!/bin/sh
set -e
ROOT="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "${ROOT}/deps/bin"
echo "rack: libapp_rack.so" > "${ROOT}/deps/manifest.txt"
