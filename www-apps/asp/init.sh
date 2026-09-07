#!/bin/sh
# Classic ASP — AxonASP libapp_asp.so
set -e
ROOT="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "${ROOT}/deps/bin"
echo "asp: use libapp_asp.so (axonasp_engine)" > "${ROOT}/deps/manifest.txt"
