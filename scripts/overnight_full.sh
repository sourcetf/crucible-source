#!/bin/sh
# Overnight: sync-ready force rebuild + non-std acceptance.
# Ports ONLY: 19095/19081/19445/19446/18443 — NEVER 8443/9095/9081/9445/9446
set -e
cd /crucible
export PATH="/usr/local/bin:/usr/local/sbin:$HOME/.cargo/bin:$PATH"
export LIBCLANG_PATH="${LIBCLANG_PATH:-/usr/local/llvm19/lib}"
export BORING_BSSL_PATH="/crucible/target/tls-libs/boringssl/lib"
export BORING_BSSL_INCLUDE_PATH="/crucible/target/tls-libs/boringssl/include"

exec sh /crucible/scripts/nightly_complete.sh
