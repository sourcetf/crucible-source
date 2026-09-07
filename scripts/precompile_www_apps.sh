#!/bin/sh
# Precompile www-apps native helpers (optional).
# OpenBSD / default tree: no-op — apps run via app-engines FFI at request time.
# Linux CI may override to ahead-of-compile static assets.
set -e
echo "precompile_www_apps: host=$(uname -s 2>/dev/null || echo unknown) — no-op stub"
exit 0
