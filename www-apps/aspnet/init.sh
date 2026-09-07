#!/bin/sh
set -e
ROOT="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "${ROOT}/deps/bin"
echo "aspnet: libapp_aspnet.so (hostfxr stub)" > "${ROOT}/deps/manifest.txt"
