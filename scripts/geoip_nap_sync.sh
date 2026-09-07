#!/usr/bin/env bash
# §6 过夜补齐：flock 单飞；merge → netorg(RIR/LACNIC RDAP Tor) → geofeed → asn/bgp → finish。
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOG="${ROOT}/data/geoip/logs/nap_sync.log"
mkdir -p "$(dirname "$LOG")"

exec 9>"${ROOT}/data/geoip/logs/nap_sync.lock"
if ! flock -n 9; then
  echo "[$(date '+%F %T')] nap_sync: another run holds the lock; exit"
  exit 0
fi

{
  echo "[$(date '+%F %T')] geoip_nap_sync start"
  bash "${ROOT}/scripts/geoip_update.sh" --only merge
  # 重载型 enrich（whois dumps / RDAP Tor / geofeed 扫描）只在过夜窗口跑
  python3 "${ROOT}/scripts/geoip_enrich_netorg.py"
  python3 "${ROOT}/scripts/geoip_enrich_rir_geofeed.py"
  python3 "${ROOT}/scripts/geoip_resolve_asn_bgp.py"
  bash "${ROOT}/scripts/geoip_finish.sh"
  echo "[$(date '+%F %T')] geoip_nap_sync done"
} | tee -a "$LOG"
