#!/bin/sh
# TLS stack E2E on NON-STANDARD ports from config-test.toml.
# Ports: prod-tls=18443  tls12=19445  tls13=19446  apps=19095
# NEVER use 8443/9081/9095/9445/9446 here.
set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [ -d /crucible ] && [ -f /crucible/config-test.toml ]; then
  ROOT=/crucible
fi
cd "$ROOT"

HOST=127.0.0.1
# NON-STANDARD only — never production 8443/9445/9446.
PORT_PROD=18443
PORT_TLS12=19445
PORT_TLS13=19446
LOG="${CRUCIBLE_TEST_LOG:-/tmp/crucible-test.log}"

for p in "$PORT_PROD" "$PORT_TLS12" "$PORT_TLS13"; do
  case "$p" in
    8443|9445|9446|9081|9095)
      echo "FAIL: refused production port $p; use 18443/19445/19446 only" >&2
      exit 2
      ;;
  esac
done

echo "=== BoringSSL TLS 1.3 :$PORT_PROD ==="
echo | openssl s_client -connect "$HOST:$PORT_PROD" -tls1_3 2>/dev/null | grep -E 'Protocol|Cipher' | head -2 || true

echo "=== BoringSSL TLS 1.2 :$PORT_PROD ==="
echo | openssl s_client -connect "$HOST:$PORT_PROD" -tls1_2 2>/dev/null | grep -E 'Protocol|Cipher' | head -2 || true

echo "=== Fair TLS1.2 :$PORT_TLS12 ==="
echo | openssl s_client -connect "$HOST:$PORT_TLS12" -tls1_2 2>/dev/null | grep -E 'Protocol|Cipher' | head -2 || true

echo "=== Fair TLS1.3 :$PORT_TLS13 ==="
echo | openssl s_client -connect "$HOST:$PORT_TLS13" -tls1_3 2>/dev/null | grep -E 'Protocol|Cipher' | head -2 || true

echo "=== NSS legacy TLS 1.0 (if openssl supports -tls1) :$PORT_PROD ==="
if openssl s_client -help 2>&1 | grep -q -- '-tls1[^_]'; then
  echo | openssl s_client -connect "$HOST:$PORT_PROD" -tls1 2>/dev/null | grep -E 'Protocol|Cipher|error|alert' | head -4 || true
else
  echo "openssl has no -tls1; skip TLS 1.0 probe"
fi

echo "=== SSLv2 ClientHello junk (server must not crash) :$PORT_PROD ==="
python3 scripts/test_sslv2_probe.py --host "$HOST" --port "$PORT_PROD" || true

echo "=== ClientHello unit tests ==="
export LIBCLANG_PATH="${LIBCLANG_PATH:-/usr/local/llvm19/lib}"
FEATURES=$(grep CARGO_FEATURES config.mk 2>/dev/null | cut -d= -f2 | tr -d ' ')
FEATURES=${FEATURES:-tls,tls_boring,go_shm_ipc,tls_nss,tls_tomcrypt}
cargo test --bin webserver tls::client_hello --features "$FEATURES" 2>&1 | tail -10

echo "=== route / legacy error logs (RUST_LOG) ==="
grep -E 'tls route|nss |tomcrypt|legacy TLS failed' "$LOG" 2>/dev/null | tail -12 || true

echo "test_tls_stacks: done (ports $PORT_PROD/$PORT_TLS12/$PORT_TLS13)"
