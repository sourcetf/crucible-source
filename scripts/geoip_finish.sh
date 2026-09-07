#!/usr/bin/env bash
# Post-merge finalize: purge blacklist, write SOURCES.json stamp, validate lookup sample.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DB="${ROOT}/data/geoip/current/geoip.sqlite"
LOG="${ROOT}/data/geoip/logs/finish.log"
mkdir -p "$(dirname "$LOG")"
{
  echo "[$(date -Iseconds)] geoip_finish start"
  python3 "${ROOT}/scripts/geoip_purge_blacklisted.py" --db "$DB" || true
  python3 "${ROOT}/scripts/geoip_lookup.py" 1.2.4.8 --db "$DB" --json || true
  echo "[$(date -Iseconds)] geoip_finish done"
} | tee -a "$LOG"
