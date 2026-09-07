#!/bin/sh
# Build one www-apps native plugin with optional musl static toolchain.
# OpenBSD: no-op shim (native libc via scripts/lib_app_musl.sh).
set -e
ROOT="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
# shellcheck source=/dev/null
. "$ROOT/scripts/lib_app_musl.sh"
echo "app_native_musl: no-op on $(uname -s 2>/dev/null || echo unknown) — args=$*"
exit 0
