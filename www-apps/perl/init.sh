#!/bin/sh
# Perl script engine — FFI via libapp_perl.so
set -e
ROOT="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "${ROOT}/deps/bin"
echo "perl: use libapp_perl.so (scriptffi)" > "${ROOT}/deps/manifest.txt"
