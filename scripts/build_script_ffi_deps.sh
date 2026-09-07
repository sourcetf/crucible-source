#!/bin/sh
# Install build deps for scriptffi (python/ruby/perl headers) on OpenBSD.
set -e
export PATH="/usr/local/bin:/usr/local/sbin:$PATH"
pkg_add -I python%3 2>/dev/null || pkg_add -I python3 2>/dev/null || true
pkg_add -I ruby 2>/dev/null || true
pkg_add -I perl 2>/dev/null || true
echo "script_ffi_deps: done (headers via ports when available)"
