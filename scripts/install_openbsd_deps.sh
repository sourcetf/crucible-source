#!/bin/sh
# Install runtime deps on OpenBSD for full :9095 engine matrix.
set -e
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"

need() {
  command -v "$1" >/dev/null 2>&1 && return 0
  return 1
}

install_pkg() {
  echo "==> pkg_add $*"
  pkg_add "$@" || true
}

if ! need go; then
  install_pkg go
fi

if ! need php-fpm && ! need php-cgi; then
  install_pkg php-8.4.24 php-cgi-8.4.24 || install_pkg php-8.3.33 php-cgi-8.3.33 || install_pkg php
fi

if ! need cargo; then
  install_pkg rust
fi

if ! ls /usr/local/lib/libnss3.so* >/dev/null 2>&1; then
  install_pkg nss nspr
fi

if ! command -v cmake >/dev/null 2>&1; then
  install_pkg cmake
fi

if ! command -v gmake >/dev/null 2>&1; then
  install_pkg gmake
fi

if ! command -v /usr/local/eboringssl/bin/bssl >/dev/null 2>&1; then
  install_pkg boringssl
fi

if [ ! -f /usr/local/llvm19/lib/libclang.so.0.0 ] \
  && [ ! -f /usr/local/llvm20/lib/libclang.so.0.0 ] \
  && [ ! -f /usr/local/llvm21/lib/libclang.so.0.0 ]; then
  install_pkg llvm-19.1.7p14 || install_pkg llvm
fi

echo "==> versions"
go version 2>/dev/null || echo "go: missing"
php-fpm -v 2>/dev/null | head -1 || php-cgi -v 2>/dev/null | head -1 || echo "php: missing"
cargo --version 2>/dev/null || echo "cargo: missing"
