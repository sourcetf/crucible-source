#!/bin/sh
set -e
ROOT="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "${ROOT}/deps/bin"
echo "aspnet: libapp_aspnet.so (hostfxr in-process; managed sample bin/CrucibleAspNetSample.dll when present)" > "${ROOT}/deps/manifest.txt"
