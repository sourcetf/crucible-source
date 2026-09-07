#!/bin/sh
set -e
ROOT="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "${ROOT}/deps/bin"
echo "psgi: libapp_psgi.so" > "${ROOT}/deps/manifest.txt"
