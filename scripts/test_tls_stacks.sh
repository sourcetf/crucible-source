#!/bin/sh
# Legacy TLS stacks (NSS + TomCrypt) end-to-end + BoringSSL regression.
#
# 一条命令验证三件事：
#   1. 现代 TLS1.2/1.3 仍走 BoringSSL（不回归）；
#   2. SSLv3 与 IE6 v2-compatible ClientHello 走 NSS，且**完整握手** + HTTP 200；
#   3. SSLv2 CLIENT-HELLO 走 TomCrypt（手写实现），完整握手 + HTTP 200；
#      截断 SSLv2 探针不得打死进程（ARGCHK/abort 回归）。
#
# 端口：默认 19543（NON-STANDARD；可用 CRUCIBLE_TLS_TEST_PORT 覆盖）。
# 绝不使用 8443/9445/9446/9081/9095。
#
# 用法：
#   scripts/test_tls_stacks.sh                                   # 自起实例 + 全量验证
#   CRUCIBLE_TLS_TEST_PORT=27543 scripts/test_tls_stacks.sh
#   CRUCIBLE_TLS_TEST_URL_PORT=18443 scripts/test_tls_stacks.sh   # 复用已运行实例
#   CRUCIBLE_BIN=/path/to/webserver scripts/test_tls_stacks.sh
#
# 前提：二进制用 `--features tls,tls_boring,tls_nss,tls_tomcrypt` 构建
#       （OpenBSD 生产由 config.mk 带上；Linux 本机见 .agents/1009/reports/legacytls-wave14.md）。
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 2

PORT="${CRUCIBLE_TLS_TEST_PORT:-19543}"
HOST=127.0.0.1
if [ -n "${CRUCIBLE_TLS_TEST_URL_PORT:-}" ]; then
  PORT="$CRUCIBLE_TLS_TEST_URL_PORT"
fi
LOG="${CRUCIBLE_TEST_LOG:-${TMPDIR:-/tmp}/crucible-tls-stacks-${PORT}.log}"
CONFIG="${CRUCIBLE_TLS_TEST_CONFIG:-${TMPDIR:-/tmp}/crucible-tls-stacks-${PORT}.toml}"
BIN="${CRUCIBLE_BIN:-}"
if [ -z "$BIN" ]; then
  if [ -n "${CARGO_TARGET_DIR:-}" ] && [ -x "${CARGO_TARGET_DIR}/release/webserver" ]; then
    BIN="${CARGO_TARGET_DIR}/release/webserver"
  else
    BIN="$ROOT/target/release/webserver"
  fi
fi

for p in 8443 9445 9446 9081 9095; do
  if [ "$PORT" = "$p" ]; then
    echo "FAIL: refused production port $p; use e.g. 19543 / 27543" >&2
    exit 2
  fi
done

PASS=0
FAIL=0
step() {
  name="$1"
  shift
  if "$@"; then
    PASS=$((PASS + 1))
  else
    FAIL=$((FAIL + 1))
    echo "FAILED: $name" >&2
  fi
}

started=0
pid=""
cleanup() {
  if [ "$started" = 1 ] && [ -n "$pid" ]; then
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

port_open() {
  python3 - "$HOST" "$PORT" <<'PY' 2>/dev/null
import socket, sys
s = socket.socket(); s.settimeout(1.0)
try:
    s.connect((sys.argv[1], int(sys.argv[2])))
except OSError:
    sys.exit(1)
finally:
    s.close()
PY
}

if port_open; then
  echo "=== using already-running instance on $HOST:$PORT ==="
else
  [ -x "$BIN" ] || { echo "FAIL: webserver binary not found: $BIN" >&2; exit 2; }
  for f in cert.pem key.pem; do
    [ -f "$ROOT/$f" ] || { echo "FAIL: missing $ROOT/$f (run scripts/generate_test_certs.sh)" >&2; exit 2; }
  done
  # 隔离实例：单 TLS listener，legacy 栈显式开启。
  cat > "$CONFIG" <<EOF
[access_log]
enable = false

[[listeners]]
address = "127.0.0.1"
port = $PORT
root = "$ROOT/www"
server_name = "crucible.local"

[listeners.ssl]
cert = "$ROOT/cert.pem"
key = "$ROOT/key.pem"
enable_nss = true
enable_tomcrypt = true
EOF
  echo "=== starting $BIN on $HOST:$PORT (log $LOG) ==="
  RUST_LOG="${RUST_LOG:-info,webserver::server::tls=debug}" "$BIN" --config "$CONFIG" >"$LOG" 2>&1 &
  pid=$!
  started=1
  i=0
  while [ $i -lt 100 ]; do
    port_open && break
    if ! kill -0 "$pid" 2>/dev/null; then
      echo "FAIL: webserver exited during startup; tail of $LOG:" >&2
      tail -20 "$LOG" >&2
      exit 2
    fi
    i=$((i + 1))
    sleep 0.1
  done
  port_open || { echo "FAIL: $HOST:$PORT never became ready; tail of $LOG:" >&2; tail -20 "$LOG" >&2; exit 2; }
fi

echo "=== 1/5 BoringSSL regression (TLS1.3 / TLS1.2) ==="
step "TLS1.3" python3 scripts/tls_probe.py "$PORT" TLSv1_3 "$HOST"
step "TLS1.2" python3 scripts/tls_probe.py "$PORT" TLSv1_2 "$HOST"

echo "=== 2/5 NSS: SSLv3 ClientHello (full handshake) ==="
step "SSLv3/NSS" python3 scripts/tls_probe.py "$PORT" sslv3 "$HOST"

echo "=== 3/5 NSS: IE6 v2-compatible ClientHello (SSL_ENABLE_V2_COMPATIBLE_HELLO) ==="
step "v2compat/NSS" python3 scripts/tls_probe.py "$PORT" v2compat "$HOST"

echo "=== 4/5 TomCrypt: SSLv2 CLIENT-HELLO (full handshake) ==="
step "SSLv2/TomCrypt" python3 scripts/test_sslv2_probe.py --host "$HOST" --port "$PORT" --handshake

echo "=== 5/5 robustness: truncated SSLv2 probe must not kill the server ==="
if CRUCIBLE_TEST_LOG="$LOG" CRUCIBLE_TEST_PID="${pid:-}" \
   python3 scripts/test_sslv2_probe.py --host "$HOST" --port "$PORT"; then
  PASS=$((PASS + 1))
else
  FAIL=$((FAIL + 1))
  echo "FAILED: truncated SSLv2 probe / liveness" >&2
fi
# 之后仍能正常 TLS1.3（证明进程与 acceptor 未被遗留栈破坏）。
step "post-legacy TLS1.3" python3 scripts/tls_probe.py "$PORT" TLSv1_3 "$HOST"

if [ -f "$LOG" ]; then
  echo "=== routing evidence (RUST_LOG=tls=debug) ==="
  grep -E 'tls route .*stack=' "$LOG" | tail -12 || true
  if grep -q 'stack=Nss' "$LOG" && grep -q 'stack=TomCrypt' "$LOG" && grep -q 'stack=Boring' "$LOG"; then
    echo "routing_ok: observed Boring + Nss + TomCrypt"
  else
    echo "WARN: routing lines incomplete (log may pre-date this run)" >&2
  fi
fi

echo "=== test_tls_stacks: PASS=$PASS FAIL=$FAIL (port $PORT) ==="
[ "$FAIL" = 0 ] || exit 1
exit 0
