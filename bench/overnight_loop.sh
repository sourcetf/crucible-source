#!/usr/bin/env bash
# Overnight knob sweep on NON-STANDARD test ports (config-test.toml).
# Mutates CRUCIBLE_BATCH_CAP env and restarts test server between iters.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STATUS_DIR="${ROOT}/bench/overnight"
STATUS="${STATUS_DIR}/status.json"
MAX_ITER="${MAX_ITER:-20}"
DURATION="${DURATION:-5}"
# Non-std ports — never 9081/9095
TARGET="${TARGET:-http://127.0.0.1:19081/}"
BASELINE="${BASELINE:-}"
CAPS=(${CAPS:-8 12 16 24 32})

mkdir -p "${STATUS_DIR}"
echo "{\"started\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\", \"iter\": 0, \"best\": null}" > "${STATUS}"

best_rps="0"
best_cap="16"

restart_test() {
  local cap="$1"
  export CRUCIBLE_BATCH_CAP="${cap}"
  if [ -f /tmp/crucible-test.pid ]; then
    OLD=$(cat /tmp/crucible-test.pid 2>/dev/null || true)
    if [ -n "${OLD}" ] && kill -0 "${OLD}" 2>/dev/null; then
      kill "${OLD}" 2>/dev/null || true
      sleep 1
    fi
  fi
  pkill -f 'webserver --config .*config-test.toml' 2>/dev/null || true
  sleep 1
  cd "${ROOT}"
  nohup env CRUCIBLE_BATCH_CAP="${cap}" ./target/release/webserver --config "${ROOT}/config-test.toml" \
    >>/tmp/crucible-test.log 2>&1 &
  echo $! >/tmp/crucible-test.pid
  sleep 2
}

for ((i=1; i<=MAX_ITER; i++)); do
  cap="${CAPS[$(( (i-1) % ${#CAPS[@]} ))]}"
  echo "==> overnight iter ${i}/${MAX_ITER} BATCH_CAP=${cap}"
  restart_test "${cap}"

  if [ -n "${BASELINE}" ]; then
    if python3 "${ROOT}/bench/h2_fair_gate.py" \
        --target "${TARGET}" \
        --baseline "${BASELINE}" \
        --duration "${DURATION}"; then
      echo "{\"iter\": ${i}, \"status\": \"pass\", \"batch_cap\": ${cap}, \"updated\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" > "${STATUS}"
      echo "dual-gate PASS at iter ${i} BATCH_CAP=${cap}"
      exit 0
    fi
  fi

  # Score via wrk when available
  rps="0"
  if command -v wrk >/dev/null 2>&1; then
    out="$(wrk -t2 -c32 -d${DURATION}s "${TARGET}" 2>/dev/null || true)"
    rps="$(echo "${out}" | sed -n 's/.*Requests\/sec:[[:space:]]*\([0-9.]*\).*/\1/p' | head -1)"
    rps="${rps:-0}"
  fi
  echo "iter=${i} BATCH_CAP=${cap} rps=${rps}"
  # bash float compare via awk
  if awk "BEGIN{exit !(${rps}+0 > ${best_rps}+0)}"; then
    best_rps="${rps}"
    best_cap="${cap}"
  fi
  echo "{\"iter\": ${i}, \"status\": \"running\", \"batch_cap\": ${cap}, \"rps\": \"${rps}\", \"best_cap\": ${best_cap}, \"best_rps\": \"${best_rps}\", \"updated\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" > "${STATUS}"
  sleep 1
done

echo "overnight_loop done best_cap=${best_cap} best_rps=${best_rps}"
echo "{\"iter\": ${MAX_ITER}, \"status\": \"done\", \"best_cap\": ${best_cap}, \"best_rps\": \"${best_rps}\", \"updated\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" > "${STATUS}"
exit 0
