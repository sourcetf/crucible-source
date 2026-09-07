#!/bin/sh
# Ruby script engine — FFI via libapp_ruby.so
set -e
ROOT="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "${ROOT}/deps/bin"
echo "ruby: use libapp_ruby.so (python3/ruby/perl scriptffi)" > "${ROOT}/deps/manifest.txt"
