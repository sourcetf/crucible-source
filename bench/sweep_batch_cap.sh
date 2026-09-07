#!/usr/bin/env bash
# Sweep BATCH_CAP on NON-STANDARD test ports; restarts test server with CRUCIBLE_BATCH_CAP.
# Does NOT auto-promote a new default into source — prints ranking only.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="${TARGET:-http://127.0.0.1:19081/}"
DURATION="${DURATION:-5}"
CAPS="${CAPS:-8 12 16 24 32}"
CFG="${CFG:-${ROOT}/config-test.toml}"

echo "==> sweep_batch_cap (runtime CRUCIBLE_BATCH_CAP restart)"
echo "target=${TARGET} duration=${DURATION}s caps=${CAPS} cfg=${CFG}"

restart_with_cap() {
  local cap="$1"
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
  nohup env CRUCIBLE_BATCH_CAP="${cap}" ./target/release/webserver --config "${CFG}" \
    >>/tmp/crucible-test.log 2>&1 &
  echo $! >/tmp/crucible-test.pid
  sleep 2
}

results=()
for cap in ${CAPS}; do
  echo "--- BATCH_CAP=${cap} ---"
  restart_with_cap "${cap}"
  export TARGET DURATION
  if out="$(python3 - <<'PY'
import os, shutil, subprocess, re, sys
url = os.environ.get("TARGET", "http://127.0.0.1:19081/")
dur = os.environ.get("DURATION", "5")
wrk = shutil.which("wrk")
if not wrk:
    print("SKIP")
    sys.exit(0)
cmd = [wrk, "-t2", "-c32", f"-d{dur}s", url]
try:
    o = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, timeout=120)
except Exception as e:
    print(f"ERR:{e}")
    sys.exit(0)
m = re.search(r"Requests/sec:\s+([\d.]+)", o)
print(m.group(1) if m else "n/a")
PY
)"; then
    echo "BATCH_CAP=${cap} rps=${out}"
    results+=("${cap}:${out}")
  fi
done

echo "==> sweep summary"
printf '%s\n' "${results[@]:-none}"

# Restore default BATCH_CAP=16
restart_with_cap 16
echo "==> restored CRUCIBLE_BATCH_CAP=16"
bash "${ROOT}/bench/restore_baseline.sh" || true
