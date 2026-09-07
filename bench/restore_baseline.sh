#!/usr/bin/env bash
# Restore frozen plain-h2 wire baseline snapshot knobs / artifacts.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SNAP="${ROOT}/bench/snapshots/baseline-plain-h2-wire-20260812"
DEST="${ROOT}/bench/baselines"

if [[ ! -d "${SNAP}" ]]; then
  echo "snapshot missing: ${SNAP}" >&2
  echo "creating placeholder snapshot dir"
  mkdir -p "${SNAP}"
  cat > "${SNAP}/README.txt" <<'EOF'
Frozen plain-h2 wire baseline (2026-08-12).
Restore copies marker files into bench/baselines/.
EOF
  echo "BATCH_CAP=16" > "${SNAP}/knobs.env"
  echo "COALESCE_WRITES=false" >> "${SNAP}/knobs.env"
  echo "max_send_buffer_size=131072" >> "${SNAP}/knobs.env"
fi

mkdir -p "${DEST}"
cp -a "${SNAP}/." "${DEST}/"
echo "restored baseline from ${SNAP} -> ${DEST}"
if [[ -f "${DEST}/knobs.env" ]]; then
  echo "--- knobs.env ---"
  cat "${DEST}/knobs.env"
fi
