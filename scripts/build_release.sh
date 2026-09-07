#!/usr/bin/env bash
# Build Crucible release binary. Unset leaked CARGO_TARGET_DIR from www-apps.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Critical: www-apps/rust init may pollute CARGO_TARGET_DIR
unset CARGO_TARGET_DIR || true
export CARGO_TARGET_DIR="${ROOT}/target"

RESTART=0
for a in "$@"; do
  case "$a" in
    --restart) RESTART=1 ;;
  esac
done

echo "[build] release with features from config.mk / CARGO_FEATURES"
if [[ -f "${ROOT}/config.mk" ]]; then
  # shellcheck disable=SC1091
  # BSD grep/sed 无 \s（GNU 扩展）；曾导致永远读不到 config.mk 的 FEATURES，
  # 静默 fallback 到 tls,tls_boring（go_shm_ipc/NSS/TomCrypt 代码从未编进二进制）。
  CF="$(grep -E '^CARGO_FEATURES[[:space:]]*[:?]*=[[:space:]]*' "${ROOT}/config.mk" | tail -1 | sed 's/^[^=]*=[[:space:]]*//' | tr -d '"' | tr -d "'")" || true
  if [[ -n "${CF:-}" ]]; then
    CARGO_FEATURES="$CF"
  fi
fi
FEATURES="${CARGO_FEATURES:-tls,tls_boring}"
echo "[build] FEATURES=${FEATURES}"
if ! cargo build --release --features "${FEATURES}"; then
  echo "[build] retry with tls,tls_boring" >&2
  cargo build --release --features "tls,tls_boring"
fi

BIN="${ROOT}/target/release/webserver"
if [[ ! -x "$BIN" ]]; then
  echo "missing $BIN" >&2
  exit 1
fi
echo "[build] ok: $BIN"

if [[ "$RESTART" -eq 1 ]]; then
  LOG=/tmp/webserver-restart.log
  {
    echo "=== restart $(date) ==="
    # Prefer exact --config argv; avoid killing unrelated processes.
    pkill -f '[/]target/release/webserver.*--config' 2>/dev/null || true
    sleep 1
    nohup "$BIN" --config "${ROOT}/config.toml" >>"$LOG" 2>&1 &
    echo "pid $!"
  } | tee -a "$LOG"
fi
