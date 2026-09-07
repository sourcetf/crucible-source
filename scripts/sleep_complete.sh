#!/bin/sh
# Overnight completion runner — NON-STANDARD ports only (config-test.toml).
# Ports: 19095/19081/19445/19446/18443 — NEVER 9095/9081/9445/9446/8443.
set -e
cd /crucible
export PATH="/usr/local/bin:/usr/local/sbin:$HOME/.cargo/bin:$PATH"
export LIBCLANG_PATH="${LIBCLANG_PATH:-/usr/local/llvm19/lib}"
export BORING_BSSL_PATH="/crucible/target/tls-libs/boringssl/lib"
export BORING_BSSL_INCLUDE_PATH="/crucible/target/tls-libs/boringssl/include"
export CRUCIBLE_ROOT=/crucible

LOG=/tmp/sleep_complete.log
exec >"$LOG" 2>&1

echo "==== sleep_complete START $(date -u) ===="

chmod +x configure scripts/*.sh libs/jsp-sidecar/*.sh 2>/dev/null || true
./configure --target=openbsd

echo "==> fetch lua vendor if needed"
bash scripts/fetch_lua_vendor.sh || true
test -f libs/app-engines/lua/vendor/lprefix.h
test -f libs/app-engines/lua/vendor/onelua.c
test -f libs/app-engines/lua/vendor/lua.h

echo "==> rebuild tomcrypt ARGTYPE=2"
rm -f target/tls-libs/libtomcrypt.a
CRUCIBLE_ROOT=/crucible sh scripts/build_libtomcrypt.sh
nm target/tls-libs/libtomcrypt.a | grep -q ltm_desc || { echo "FAIL: no ltm_desc"; exit 1; }
nm target/tls-libs/libtomcrypt.a | grep -q rc4_stream_setup || { echo "FAIL: no rc4"; exit 1; }

echo "==> engines"
GO_ENGINE_MODE=shm bash scripts/build_app_engines.sh

echo "==> release"
touch libs/tls-tomcrypt/tc_shim.c libs/tls-nss/nss_shim.c
gmake release

echo "==> geoip seed"
python3 scripts/geoip_seed_demo.py --force

echo "==> acceptance on NON-STD ports"
sh scripts/acceptance_test_ports.sh config-test.toml
ACC=$?

echo "==> post checks"
# Lua must respond with real engine text
LUA=$(curl -sS --max-time 5 http://127.0.0.1:19095/lua/ || true)
echo "lua_body=$LUA"
echo "$LUA" | grep -qi 'lua' || echo "WARN: lua body unexpected"

# SSLv2 must not kill test server
if [ -f /tmp/crucible-test.pid ]; then
  kill -0 "$(cat /tmp/crucible-test.pid)" 2>/dev/null && echo "test_server_alive_ok" || echo "FAIL: test server dead"
fi

echo "==== sleep_complete END $(date -u) exit=$ACC ===="
exit $ACC
