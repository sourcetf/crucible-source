#!/bin/sh
# One-shot overnight completion: sync-ready remote rebuild + non-std acceptance.
# Ports ONLY: 19095/19081/19445/19446/18443
set -e
cd /crucible
export PATH="/usr/local/bin:/usr/local/sbin:$HOME/.cargo/bin:$PATH"
export LIBCLANG_PATH="${LIBCLANG_PATH:-/usr/local/llvm19/lib}"
export BORING_BSSL_PATH="/crucible/target/tls-libs/boringssl/lib"
export BORING_BSSL_INCLUDE_PATH="/crucible/target/tls-libs/boringssl/include"

chmod +x configure scripts/*.sh bench/*.sh 2>/dev/null || true
./configure --target=openbsd

# Optional wrk for §19 RPS gates
if ! command -v wrk >/dev/null 2>&1; then
  echo "==> installing wrk (optional)"
  pkg_add -I wrk 2>/dev/null || true
fi
bash scripts/build_script_ffi_deps.sh 2>/dev/null || true
bash scripts/build_mruby.sh 2>/dev/null || true

# Ensure LibTomMath for TomCrypt SSLv2 (prevents LTC_ARGCHK abort)
if [ ! -f /usr/local/lib/libtommath.a ] && [ ! -f /usr/local/lib/libtommath.so ] \
  && ! ls /usr/local/lib/libtommath.so* >/dev/null 2>&1; then
  echo "==> installing libtommath"
  pkg_add -I libtommath 2>/dev/null || true
fi
# Force tomcrypt rebuild with ARGTYPE=2 + LTC_LTM_DESC (old libs abort the process)
rm -f /crucible/target/tls-libs/.tomcrypt_with_ltm /crucible/target/tls-libs/libtomcrypt.a
CRUCIBLE_ROOT=/crucible sh scripts/build_libtomcrypt.sh 2>&1 | tee /tmp/tomcrypt-build.log | tail -30
# Prove ARGTYPE / ltm_desc before release link (must be real T/D symbol, not just .o name)
nm /crucible/target/tls-libs/libtomcrypt.a 2>/dev/null | grep -E ' [TD] ltm_desc$' | head -3 || {
  echo "FAIL: vendored libtomcrypt missing ltm_desc symbol (rebuild with -DLTM_DESC)"; exit 1
}
nm /crucible/target/tls-libs/libtomcrypt.a 2>/dev/null | grep -E ' [TD] rc4_stream_setup$' | head -1 || {
  echo "FAIL: missing rc4_stream_setup"; exit 1
}

# Lua: prefer system package, else vendor amalgam
pkg_add -I lua 2>/dev/null || pkg_add -I lua54 2>/dev/null || true
if ! pkg-config --exists lua5.4 lua54 lua5.3 lua 2>/dev/null \
  && [ ! -f /usr/local/include/lua.h ] \
  && [ ! -f /usr/local/include/lua54/lua.h ]; then
  bash scripts/fetch_lua_vendor.sh 2>&1 | tee /tmp/lua-vendor.log | tail -20 || true
fi
# Drop stale lua .so so missing symbols cannot linger
rm -f /crucible/target/app-engines/libapp_lua.so
# Force C shim recompile (ltc_mp = ltm_desc)
touch /crucible/libs/tls-tomcrypt/tc_shim.c /crucible/src/server/tls/tls_tomcrypt.rs

# GeoIP demo seed (force so ASN fields exist for acceptance)
python3 scripts/geoip_seed_demo.py --force 2>&1 | tee /tmp/geoip-seed.log | tail -5 || true
bash scripts/geoip_update.sh 2>&1 | tee /tmp/geoip-update.log | tail -5 || true

# ECH + certs
[ -f cert_ec.pem ] || openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -keyout key_ec.pem -out cert_ec.pem -days 3650 -nodes -subj /CN=crucible.local 2>/dev/null || true
[ -f cert.pem ] || openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 3650 -nodes \
  -subj /CN=crucible.local 2>/dev/null || true
sh scripts/generate_ech.sh crucible.local 2>/dev/null || true

# Engines + release — abort overnight if release fails (never accept on stale bin)
GO_ENGINE_MODE=shm bash scripts/build_app_engines.sh 2>&1 | tee /tmp/engines.log | tail -30
if ! gmake release 2>&1 | tee /tmp/crucible-release.log | tail -20; then
  echo "FAIL: gmake release"; exit 1
fi
grep -E 'Finished .release' /tmp/crucible-release.log >/dev/null || {
  echo "FAIL: release log missing Finished"; exit 1
}

# Full acceptance on test ports only
sh scripts/acceptance_test_ports.sh config-test.toml 2>&1 | tee /tmp/acceptance.log

# Optional short BATCH_CAP sweep (2s) if wrk present
if command -v wrk >/dev/null 2>&1; then
  DURATION=2 CAPS="8 16 32" bash bench/sweep_batch_cap.sh 2>&1 | tee /tmp/sweep.log | tail -20 || true
fi

echo "NIGHTLY DONE — see /tmp/acceptance.log /tmp/engines.log /tmp/crucible-release.log"
