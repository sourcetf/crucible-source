#!/bin/sh
# h3_interop_check.sh — U-11: HTTP/3 interoperability with a *third-party* client.
#
# One command to reproduce the whole U-11 check:
#   * builds the server (Rust/quinn + h3 crate, BoringSSL),
#   * starts it (plus a UDP echo) inside a private user+net namespace so the
#     CONNECT-UDP admission policy (public-unicast targets only) can be met
#     without touching the host network,
#   * drives it with Cloudflare quiche's `quiche-client` (a fully independent
#     QUIC/HTTP-3/QPACK implementation) — GET, 404, 301, Range/206, HEAD,
#     CONNECT->501, TE enforcement, 1 MiB/8 MiB integrity, PUT/POST request
#     bodies, multiplexing, QUIC v1, and H3 GOAWAY,
#   * drives CONNECT-UDP (RFC 9298) end-to-end with the aioquic client
#     (quiche-client has no MASQUE support).
#
# Usage:
#   scripts/h3_interop_check.sh              # build + run everything
#   scripts/h3_interop_check.sh --no-build   # reuse an existing binary
#
# Environment knobs:
#   H3I_REPO      repo root (default: git toplevel of this script)
#   H3I_SCRATCH   work dir (default: ~/scratch-h3interop)
#   H3I_PORT      h3 UDP port (default: 27143)
#   QUICHE_CLIENT path to quiche-client (default: search; see below)
#   QUICHE_SRC    quiche source checkout (optional; used to build quiche-client
#                 if QUICHE_CLIENT is not found)
#   H3I_NO_NS=1   do not use a namespace (CONNECT-UDP checks will be limited)
#
# quiche-client build (when not prebuilt): quiche needs BoringSSL.  Point
# QUICHE_BSSL_PATH at an existing BoringSSL build (this repo ships one under
# target/tls-libs/boringssl) and run, from the quiche checkout:
#     QUICHE_BSSL_PATH=<...> cargo build --release --bin quiche-client
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO=${H3I_REPO:-$(git -C "$SCRIPT_DIR/.." rev-parse --show-toplevel 2>/dev/null || echo /home/dev123/crucible-git)}
SCRATCH=${H3I_SCRATCH:-$HOME/scratch-h3interop}
PORT=${H3I_PORT:-27143}
BUILD=1
[ "${1:-}" = "--no-build" ] && BUILD=0

# ── re-exec inside a private user+net namespace ──────────────────────────────
if [ -z "${H3I_IN_NS:-}" ] && [ "${H3I_NO_NS:-0}" != "1" ]; then
  SELF=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/$(basename -- "$0")
  EXTRA=""
  [ "$BUILD" = 1 ] || EXTRA="--no-build"
  export H3I_IN_NS=1 H3I_REPO="$REPO" H3I_SCRATCH="$SCRATCH" H3I_PORT="$PORT"
  exec unshare -Urn "$SELF" $EXTRA
fi

log() { echo "[h3_interop] $*"; }
FAILS=0
pass() { echo "[PASS] $1"; }
fail() { echo "[FAIL] $1"; FAILS=$((FAILS + 1)); }

mkdir -p "$SCRATCH"/{logs,tmp,state-dns,certs,bin,www/up}
export TMPDIR="$SCRATCH/tmp"

# ── toolchain ────────────────────────────────────────────────────────────────
if [ -f /home/dev123/bin/buildenv.sh ]; then . /home/dev123/bin/buildenv.sh; fi
CARGO=${CARGO:-cargo}
export CARGO_TARGET_DIR=${H3I_TARGET_DIR:-$SCRATCH/target}
mkdir -p "$CARGO_TARGET_DIR"

# ── build ────────────────────────────────────────────────────────────────────
BIN=$CARGO_TARGET_DIR/release/webserver
if [ "$BUILD" = 1 ]; then
  log "building webserver (tls,tls_boring) ..."
  if ! ( cd "$REPO" && $CARGO build --release --bin webserver --offline \
           --features tls,tls_boring ) >"$SCRATCH/logs/build.log" 2>&1; then
    echo "BUILD FAILED — see $SCRATCH/logs/build.log"; tail -20 "$SCRATCH/logs/build.log"; exit 2
  fi
fi
[ -x "$BIN" ] || { echo "missing binary $BIN"; exit 2; }
log "binary: $BIN ($(md5sum "$BIN" | cut -d' ' -f1))"

# ── test payloads / docroot ──────────────────────────────────────────────────
python3 - "$SCRATCH" <<'PY'
import hashlib, os, sys
s = sys.argv[1]
def w(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f: f.write(data)
w(f"{s}/www/index.html", b"<h1>ok</h1>\n")
w(f"{s}/www/blob-1m.bin", bytes(((i * 131 + 7) & 0xFF) for i in range(1 << 20)))
w(f"{s}/www/blob-8m.bin", bytes(((i * 131 + 7) & 0xFF) for i in range(8 << 20)))
w(f"{s}/up-2m.bin", bytes(((i * 1103515245 + 12345) >> 16 & 0xFF) for i in range(2 << 20)))
lines = []
for n in ("blob-1m.bin", "blob-8m.bin"):
    h = hashlib.sha256(open(f"{s}/www/{n}", "rb").read()).hexdigest()
    lines.append(f"{h}  {n}\n")
w(f"{s}/www/SHA256SUMS", "".join(lines).encode())
PY

cp -f "$REPO/cert.pem" "$SCRATCH/certs/cert.pem"
cp -f "$REPO/key.pem"  "$SCRATCH/certs/key.pem"

cat > "$SCRATCH/config.toml" <<EOF
[access_log]
enable = true
level = "info"
realtime = true

[[listeners]]
address = "127.0.0.1"
port = $PORT
root = "$SCRATCH/www"
server_name = "h3interop.crucible.local"
http_versions = ["h3"]
connect_udp = true

[listeners.autoindex]
enabled = true
enable_upload = true
paths = ["/up"]

[listeners.ssl]
cert = "$SCRATCH/certs/cert.pem"
key = "$SCRATCH/certs/key.pem"
prefer_tls13 = true
EOF

# ── network aliases for CONNECT-UDP (public-looking targets on lo) ───────────
ip link set lo up 2>/dev/null || true
ip addr add 1.1.1.1/32 dev lo 2>/dev/null || true
ip addr add 8.8.8.8/32 dev lo 2>/dev/null || true

# ── start echo + server ──────────────────────────────────────────────────────
python3 "$REPO/scripts/interop_h3_echo.py" --host 1.1.1.1 --port 9000 \
  >"$SCRATCH/logs/echo.log" 2>&1 &
ECHO_PID=$!
RUST_LOG=info CRUCIBLE_DNS_STATE_ROOT="$SCRATCH/state-dns" \
  "$BIN" --config "$SCRATCH/config.toml" >"$SCRATCH/logs/server.log" 2>&1 &
SRV_PID=$!
cleanup() { kill "$SRV_PID" "$ECHO_PID" 2>/dev/null; wait 2>/dev/null; }
trap cleanup EXIT

for _ in $(seq 1 80); do grep -q "h3 quinn endpoint ready" "$SCRATCH/logs/server.log" && break; sleep 0.25; done
if ! grep -q "h3 quinn endpoint ready" "$SCRATCH/logs/server.log"; then
  echo "SERVER FAILED TO START"; tail -20 "$SCRATCH/logs/server.log"; exit 2
fi
log "server ready on 127.0.0.1:$PORT"

# ── locate quiche-client ─────────────────────────────────────────────────────
QC=${QUICHE_CLIENT:-}
if [ -z "$QC" ]; then
  for c in \
      /home/dev123/scratch-u06/quiche-target/release/quiche-client \
      "$HOME/quiche/target/release/quiche-client" \
      "$SCRATCH/quiche-target/release/quiche-client"; do
    [ -x "$c" ] && QC=$c && break
  done
fi
if [ -z "$QC" ] && [ -n "${QUICHE_SRC:-}" ] && [ -d "$QUICHE_SRC" ]; then
  log "quiche-client not found; building from $QUICHE_SRC ..."
  BSSL=${QUICHE_BSSL_PATH:-$REPO/target/tls-libs/boringssl}
  if ( cd "$QUICHE_SRC" && QUICHE_BSSL_PATH="$BSSL" CARGO_TARGET_DIR="$SCRATCH/quiche-target" \
         $CARGO build --release --bin quiche-client ) >"$SCRATCH/logs/quiche-build.log" 2>&1; then
    QC=$SCRATCH/quiche-target/release/quiche-client
  else
    log "quiche build failed (see logs/quiche-build.log)"
  fi
fi

# ── aioquic baseline sanity (independent Python implementation) ──────────────
if python3 "$REPO/scripts/interop_h3_http.py" --port "$PORT" --paths / --n 1 \
     >"$SCRATCH/logs/aioquic-get.log" 2>&1; then
  pass "aioquic baseline GET /"
else
  fail "aioquic baseline GET /"
fi

# ── CONNECT-UDP (RFC 9298) end-to-end via aioquic ────────────────────────────
# Run *before* the quiche GOAWAY check: that check mutates the cert and makes the
# server close + restart the h3 endpoint, which would race the tunnel setup.
if python3 "$REPO/scripts/interop_h3_udp.py" --port "$PORT" --target 1.1.1.1:9000 \
     --count 1000 --sizes 1,1024,32768 --window 8 \
     --json "$SCRATCH/logs/cu-results.json" >"$SCRATCH/logs/cu.log" 2>&1; then
  pass "CONNECT-UDP end-to-end (aioquic)"
else
  fail "CONNECT-UDP end-to-end (aioquic)"
fi
tail -3 "$SCRATCH/logs/cu.log"

# ── third-party (quiche) HTTP/3 suite (its GOAWAY check restarts the endpoint) ─
if [ -n "$QC" ] && [ -x "$QC" ]; then
  log "third-party client: $QC"
  if python3 "$REPO/scripts/interop_h3_quiche.py" --client "$QC" --port "$PORT" \
       --www "$SCRATCH/www" --up "$SCRATCH/up-2m.bin" --cert "$SCRATCH/certs/cert.pem" \
       --json "$SCRATCH/logs/quiche-results.json"; then
    pass "quiche HTTP/3 interop suite"
  else
    fail "quiche HTTP/3 interop suite"
  fi
else
  echo "[SKIP] quiche-client not available (set QUICHE_CLIENT or QUICHE_SRC)"
fi

echo "==================================================================="
if [ "$FAILS" = 0 ]; then
  echo "[h3_interop] ALL CHECKS PASSED"
else
  echo "[h3_interop] $FAILS CHECK(S) FAILED"
fi
echo "logs: $SCRATCH/logs/   results: $SCRATCH/logs/*.json"
exit $([ "$FAILS" = 0 ] && echo 0 || echo 1)
