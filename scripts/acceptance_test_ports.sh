#!/bin/sh
# Full acceptance on NON-STANDARD ports (config-test.toml).
# Ports: 19095 apps, 19081 plain, 19445 tls12, 19446 tls13, 18443 prod-tls
# NEVER use 9095/9081/9445/9446/8443.
set -e
cd /crucible

export PATH="/usr/local/bin:/usr/local/sbin:$HOME/.cargo/bin:$PATH"
export LIBCLANG_PATH="${LIBCLANG_PATH:-/usr/local/llvm19/lib}"
export BORING_BSSL_PATH="/crucible/target/tls-libs/boringssl/lib"
export BORING_BSSL_INCLUDE_PATH="/crucible/target/tls-libs/boringssl/include"

CFG="${1:-config-test.toml}"
BIN="./target/release/webserver"
LOG="${CRUCIBLE_TEST_LOG:-/tmp/crucible-test.log}"

echo "==> ensure certs"
if [ ! -f cert_ec.pem ]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout key_ec.pem -out cert_ec.pem -days 3650 -nodes -subj /CN=crucible.local 2>/dev/null || true
fi
if [ ! -f state/ech/ech_keys.pem ]; then
  sh scripts/generate_ech.sh crucible.local 2>/dev/null || true
fi

echo "==> engines"
GO_ENGINE_MODE=shm bash scripts/build_app_engines.sh 2>&1 | tee /tmp/engines-accept.log | tail -40
# Require lua .so with real PUC-Lua symbols (hard gate — no stub)
test -f target/app-engines/libapp_lua.so || { echo "FAIL: libapp_lua.so missing"; exit 1; }
if command -v nm >/dev/null 2>&1; then
  nm target/app-engines/libapp_lua.so 2>/dev/null | grep -q 'lua_pcall\|luaL_newstate' \
    || nm -D target/app-engines/libapp_lua.so 2>/dev/null | grep -q 'lua_pcall\|luaL_newstate' \
    || { echo "FAIL: libapp_lua.so is stub (no lua_pcall)"; exit 1; }
fi

echo "==> release"
test -f config.mk || ./configure --target=openbsd
# Force tomcrypt/nss shims to rebuild
touch libs/tls-tomcrypt/tc_shim.c libs/tls-nss/nss_shim.c src/server/tls/*.rs 2>/dev/null || true
if ! gmake release 2>&1 | tee /tmp/crucible-release.log | tail -15; then
  echo "FAIL: gmake release failed — refusing to run acceptance on stale binary"
  exit 1
fi
grep -q 'Finished `release`' /tmp/crucible-release.log \
  || grep -q 'Finished release' /tmp/crucible-release.log \
  || { echo "FAIL: release did not finish cleanly"; tail -40 /tmp/crucible-release.log; exit 1; }
test -x "$BIN" || { echo "FAIL: $BIN missing"; exit 1; }

echo "==> seed geoip demo + start JSP sidecar (non-std sock)"
python3 scripts/geoip_seed_demo.py --force 2>/dev/null || true
mkdir -p /crucible/state/jsp
pkill -f 'jsp_sidecar' 2>/dev/null || true
rm -f /crucible/state/jsp/test.sock
nohup sh /crucible/libs/jsp-sidecar/jsp_sidecar.sh /crucible/state/jsp/test.sock /crucible/www-apps/jsp \
  >/tmp/jsp-sidecar.log 2>&1 &
echo $! >/tmp/jsp-sidecar.pid
sleep 1

echo "==> start on test ports (NEVER 8443/9095/9081/9445/9446)"
# Kill only prior test instance when possible
if [ -f /tmp/crucible-test.pid ]; then
  OLD=$(cat /tmp/crucible-test.pid 2>/dev/null || true)
  if [ -n "$OLD" ] && kill -0 "$OLD" 2>/dev/null; then
    kill "$OLD" 2>/dev/null || true
    sleep 1
  fi
  rm -f /tmp/crucible-test.pid
fi
pkill -f 'webserver --config .*config-test.toml' 2>/dev/null || true
sleep 1
RUST_LOG=info "$BIN" --config "/crucible/$CFG" >"$LOG" 2>&1 &
WPID=$!
echo "$WPID" >/tmp/crucible-test.pid
export CRUCIBLE_TEST_PID="$WPID"
sleep 2
if ! kill -0 "$WPID" 2>/dev/null; then
  echo "FAIL: server dead"; tail -40 "$LOG"; exit 1
fi
echo "server pid=$WPID"

echo "==> smoke apps :19095"
for p in rust c go lua php asp python ruby perl wsgi asgi psgi rack cgi uwsgi; do
  echo -n "  /$p/ -> "
  curl -sS --max-time 5 "http://127.0.0.1:19095/$p/" | head -n 1 || echo "(fail)"
  echo
done

echo "==> jsp sidecar :19095/jsp/"
curl -sS --max-time 5 "http://127.0.0.1:19095/jsp/" | head -n 1 || echo "(jsp optional)"
echo

echo "==> geoip API :19095 (via admin path disabled; direct rust panel)"
curl -sS --max-time 5 "http://127.0.0.1:19095/__admin" >/dev/null && echo "admin reachable" || true
curl -sS --max-time 5 "http://127.0.0.1:19095/__metrics" 2>/dev/null | head -n 2 || true
echo

echo "==> TLS 1.3 :18443"
echo | openssl s_client -connect 127.0.0.1:18443 -tls1_3 2>/dev/null | grep Protocol || true
echo "==> TLS 1.2 :19445"
echo | openssl s_client -connect 127.0.0.1:19445 -tls1_2 2>/dev/null | grep Protocol || true
echo "==> TLS 1.3 fair :19446"
echo | openssl s_client -connect 127.0.0.1:19446 -tls1_3 2>/dev/null | grep Protocol || true

echo "==> H3 QUIC :18443 (optional — body OK even if stream reset)"
if command -v curl >/dev/null 2>&1 && curl --version 2>/dev/null | grep -qi http3; then
  H3OUT=$(curl -sS --http3-only --max-time 5 -k "https://127.0.0.1:18443/" 2>/tmp/h3.err || true)
  if [ -n "$H3OUT" ]; then
    echo "$H3OUT" | head -n 1
    echo "h3_body_ok"
  else
    echo "(h3 optional fail) $(head -n1 /tmp/h3.err 2>/dev/null)"
  fi
else
  echo "curl without http3 — skip H3 smoke (quinn listener still bound on :18443 UDP)"
fi
echo
echo "==> TLS 1.0 NSS path :18443"
if openssl s_client -help 2>&1 | grep -q -- '-tls1[^_]'; then
  echo | openssl s_client -connect 127.0.0.1:18443 -tls1 2>/dev/null | grep -E 'Protocol|error|alert' | head -3 || true
else
  echo "openssl has no -tls1; skip"
fi

echo "==> SSLv2 ClientHello probe (no crash) :18443"
CRUCIBLE_TEST_PID="$WPID" python3 scripts/test_sslv2_probe.py --host 127.0.0.1 --port 18443 --settle-ms 1500 || {
  echo "FAIL: sslv2 probe / server alive check"; tail -30 "$LOG"; exit 1
}
if kill -0 "$WPID" 2>/dev/null; then echo "server still alive after sslv2 probe"; else echo "FAIL: server died on sslv2"; tail -40 "$LOG"; exit 1; fi

# Post-sslv2: verify TLS still works (server not wedged)
echo "==> post-sslv2 TLS1.3 still works :18443"
echo | openssl s_client -connect 127.0.0.1:18443 -tls1_3 2>/dev/null | grep Protocol || {
  echo "FAIL: TLS broken after sslv2"; exit 1
}

echo "==> plain static :19081"
curl -sS --max-time 5 http://127.0.0.1:19081/ | head -n 1
echo

echo "==> unit tests"
cargo test --bin webserver --features tls,tls_boring,go_shm_ipc,tls_nss,tls_tomcrypt 2>&1 | tail -12

echo "==> file_open / would_execute / script_rel"
cargo test --bin webserver file_open --features tls,tls_boring,go_shm_ipc,tls_nss,tls_tomcrypt 2>&1 | tail -6
cargo test --bin webserver would_execute --features tls,tls_boring,go_shm_ipc,tls_nss,tls_tomcrypt 2>&1 | tail -6
cargo test --bin webserver script_rel --features tls,tls_boring,go_shm_ipc,tls_nss,tls_tomcrypt 2>&1 | tail -6

echo "==> wrk smoke (if available)"
if command -v wrk >/dev/null 2>&1; then
  wrk -t2 -c8 -d3s http://127.0.0.1:19095/rust/ || true
  wrk -t2 -c8 -d3s http://127.0.0.1:19095/c/ || true
  wrk -t2 -c8 -d3s http://127.0.0.1:19081/ || true
else
  echo "wrk not installed — skip §19 RPS gates"
fi

echo "==> bench helpers"
python3 bench/app_engine_overhead.py --port 19095 --engines static,rust,c,go,lua,php --duration 2s || true
python3 bench/matrix_http_tls.py --port-plain 19081 --port-tls12 19445 --port-tls13 19446 --duration 2s || true

echo "==> geoip"
bash scripts/geoip_update.sh 2>&1 | tail -3 || true
python3 scripts/geoip_seed_demo.py --force 2>&1 | tail -3 || true
curl -sS "http://127.0.0.1:19095/__admin" >/dev/null && echo "admin ok" || true
# Lookup must return ASN (non-null) for seeded 1.2.4.8
# Lookup must return ASN (non-null) for seeded 1.2.4.8 — admin path under realm
LOOK=$(curl -sS "http://127.0.0.1:19095/__admin/api/geoip/lookup?ip=1.2.4.8" 2>/dev/null || true)
if [ -z "$LOOK" ]; then
  LOOK=$(curl -sS "http://127.0.0.1:19095/api/geoip/lookup?ip=1.2.4.8" 2>/dev/null || true)
fi
echo "geoip_lookup=$LOOK" | head -n 1
echo "$LOOK" | grep -Eq '"asn"[[:space:]]*:[[:space:]]*"?[0-9]+"?|"asn"[[:space:]]*:[[:space:]]*[0-9]+' && echo "geoip_asn_ok" || {
  echo "FAIL: geoip asn missing/null for 1.2.4.8"
  exit 1
}

echo "==> tls route log"
grep 'tls route' "$LOG" | tail -5 || true

echo "ACCEPTANCE DONE (non-std ports 19095/19081/19445/19446/18443)"
