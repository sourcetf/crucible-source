#!/bin/sh
# Zig musl linker wrapper (optional Linux static builds).
# OpenBSD: fall through to system linker.
set -e
if command -v zig >/dev/null 2>&1 && [ "$(uname -s 2>/dev/null)" = "Linux" ]; then
  exec zig cc -target "$(uname -m)-linux-musl" "$@"
fi
echo "zig-musl-ld: using system CC as linker (no zig musl on this host)" >&2
exec "${CC:-cc}" "$@"
