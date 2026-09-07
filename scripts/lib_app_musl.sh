#!/bin/sh
# Optional musl static helpers — OpenBSD uses native libc; this is a no-op shim
# so the §1 tree exists. Linux CI may override with real musl wrappers.
set -e
echo "lib_app_musl: host=$(uname -s) — using system libc (no-op on OpenBSD)"
exit 0
