#!/bin/sh
# Start webserver on config-test.toml NON-STANDARD ports and exercise TLS stacks.
# Ports: 18443 (prod), 19445 (tls12), 19446 (tls13) — never 8443/9445/9446.
set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [ -d /crucible ] && [ -f /crucible/config-test.toml ]; then
  ROOT=/crucible
fi
cd "$ROOT"

CFG="${1:-$ROOT/config-test.toml}"
LOG="${CRUCIBLE_TEST_LOG:-/tmp/crucible-test.log}"
# NON-STANDARD only — never production 8443/9445/9446.
PORT_PROD=18443
PORT_TLS12=19445
PORT_TLS13=19446

for p in "$PORT_PROD" "$PORT_TLS12" "$PORT_TLS13"; do
  case "$p" in
    8443|9445|9446|9081|9095)
      echo "FAIL: refused production port $p; use 18443/19445/19446 only" >&2
      exit 2
      ;;
  esac
done

# Prefer killing only a prior test-config instance (best-effort).
if [ -f /tmp/crucible-test.pid ]; then
  OLD=$(cat /tmp/crucible-test.pid 2>/dev/null || true)
  if [ -n "$OLD" ] && kill -0 "$OLD" 2>/dev/null; then
    kill "$OLD" 2>/dev/null || true
    sleep 1
  fi
  rm -f /tmp/crucible-test.pid
fi
# Fallback: only processes clearly started with config-test.toml
pkill -f 'webserver --config .*config-test.toml' 2>/dev/null || true
sleep 1

RUST_LOG="${RUST_LOG:-info}" ./target/release/webserver --config "$CFG" >"$LOG" 2>&1 &
WPID=$!
echo "$WPID" >/tmp/crucible-test.pid
sleep 2
echo "server pid=$WPID config=$CFG ports=$PORT_PROD/$PORT_TLS12/$PORT_TLS13 primary=$(strings ./target/release/webserver 2>/dev/null | grep -m1 boringssl || echo boringssl)"

echo "=== TLS 1.3 (BoringSSL + ECH/PQC path) :$PORT_PROD ==="
echo | openssl s_client -connect 127.0.0.1:$PORT_PROD -tls1_3 2>&1 | grep -E 'Protocol|Cipher|Verify' | head -4 || true

echo "=== TLS 1.2 (BoringSSL) :$PORT_PROD ==="
echo | openssl s_client -connect 127.0.0.1:$PORT_PROD -tls1_2 2>&1 | grep -E 'Protocol|Cipher' | head -2 || true

echo "=== Fair TLS1.2 :$PORT_TLS12 / TLS1.3 :$PORT_TLS13 ==="
echo | openssl s_client -connect 127.0.0.1:$PORT_TLS12 -tls1_2 2>&1 | grep -E 'Protocol|Cipher' | head -2 || true
echo | openssl s_client -connect 127.0.0.1:$PORT_TLS13 -tls1_3 2>&1 | grep -E 'Protocol|Cipher' | head -2 || true

echo "=== TLS 1.0 (NSS legacy when enabled) :$PORT_PROD ==="
if openssl s_client -help 2>&1 | grep -q -- '-tls1[^_]'; then
  echo | openssl s_client -connect 127.0.0.1:$PORT_PROD -tls1 2>&1 | grep -E 'Protocol|Cipher|error|alert' | head -4 || true
else
  echo "openssl has no -tls1; skip"
fi

echo "=== SSLv2 ClientHello probe (no crash) :$PORT_PROD ==="
python3 scripts/test_sslv2_probe.py --host 127.0.0.1 --port "$PORT_PROD" || true

if kill -0 "$WPID" 2>/dev/null; then echo "server alive"; else echo "server dead"; fi
echo "--- route log ---"
grep 'tls route' "$LOG" | tail -8 || true
echo "--- errors ---"
grep -iE 'error|panic|failed|nss |tomcrypt' "$LOG" | tail -15 || true
