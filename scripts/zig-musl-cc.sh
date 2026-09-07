#!/bin/sh
# Zig musl C compiler wrapper (optional Linux static builds).
# OpenBSD: no-op — use system cc. Args ignored.
set -e
if command -v zig >/dev/null 2>&1 && [ "$(uname -s 2>/dev/null)" = "Linux" ]; then
  exec zig cc -target "$(uname -m)-linux-musl" "$@"
fi
echo "zig-musl-cc: using system CC (no zig musl on this host)" >&2
exec "${CC:-cc}" "$@"
