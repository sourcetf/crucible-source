#!/bin/sh
set -e
ROOT="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "${ROOT}/deps/bin"
echo "uwsgi: libapp_uwsgi.so" > "${ROOT}/deps/manifest.txt"
