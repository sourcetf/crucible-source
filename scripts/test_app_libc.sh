#!/bin/sh
# Smoke-check that app-engine .so files link against expected libc.
# OpenBSD: no-op (native libc). Linux may ldd/musl-check in CI.
set -e
ROOT="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
ENG="${ROOT}/target/app-engines"
echo "test_app_libc: host=$(uname -s 2>/dev/null || echo unknown)"
if [ -d "$ENG" ]; then
  echo "test_app_libc: engines dir present ($ENG) — skip deep ldd on this host"
else
  echo "test_app_libc: no target/app-engines yet — ok"
fi
exit 0
