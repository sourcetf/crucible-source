#!/bin/sh
set -e
ROOT="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "${ROOT}/deps/bin"
echo "python: libapp_python.so" > "${ROOT}/deps/manifest.txt"
