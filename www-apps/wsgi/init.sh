#!/bin/sh
set -e
ROOT="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "${ROOT}/deps/bin"
echo "wsgi: libapp_wsgi.so" > "${ROOT}/deps/manifest.txt"
