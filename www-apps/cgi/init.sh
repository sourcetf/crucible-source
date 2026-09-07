#!/bin/sh
set -e
ROOT="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "${ROOT}/deps/bin"
chmod +x "${ROOT}/index.cgi" 2>/dev/null || true
echo "cgi: libapp_cgi.so" > "${ROOT}/deps/manifest.txt"
