#!/usr/bin/env bash
# §6 GeoIP 更新总链：fetch 层 → merge（§5 权重）→ enrich 全套 → finish（黑名单清洗+校验）。
# 用法：
#   geoip_update.sh                # 全链
#   geoip_update.sh --only merge   # 只重跑 merge
#   --only fetch|enrich|finish|blacklist
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DB="${ROOT}/data/geoip/current/geoip.sqlite"
LOG="${ROOT}/data/geoip/logs/update.log"
mkdir -p "${ROOT}/data/geoip/current" "${ROOT}/data/geoip/logs"
ONLY="${2:-all}"

have_network() {
  command -v curl >/dev/null 2>&1 && curl -fsS --connect-timeout 3 -o /dev/null https://example.com 2>/dev/null
}

{
  echo "[$(date '+%F %T')] geoip_update start (only=${ONLY})"

  if [ "${ONLY}" = "all" ] || [ "${ONLY}" = "fetch" ]; then
    if have_network; then
      python3 "${ROOT}/scripts/geoip_fetch_layers.py" || echo "warn: fetch_layers failed"
    else
      echo "warn: no network; skip fetch"
    fi
  fi

  if [ "${ONLY}" = "all" ] || [ "${ONLY}" = "merge" ]; then
    python3 "${ROOT}/scripts/geoip_merge.py" --db "$DB" --init-schema --import-layers \
      || echo "warn: merge failed"
  fi

  if [ "${ONLY}" = "all" ] || [ "${ONLY}" = "enrich" ]; then
    for script in \
      geoip_enrich_iana_special.py \
      geoip_enrich_geocn.py \
      geoip_enrich_qqwry.py \
      geoip_enrich_cernet.py \
      geoip_enrich_cloud_geo.py \
      geoip_enrich_places.py \
      geoip_resolve_asn_bgp.py \
      geoip_enrich_netorg.py \
      geoip_enrich_rir_geofeed.py \
      geoip_enrich_ripe_anycast_extract.py \
      geoip_enrich_ixp.py \
      geoip_enrich_google_rdns.py \
      geoip_enrich_cn_extra.py; do
      python3 "${ROOT}/scripts/${script}" || echo "warn: ${script} failed"
    done
  fi

  if [ "${ONLY}" = "all" ] || [ "${ONLY}" = "blacklist" ] || [ "${ONLY}" = "finish" ]; then
    python3 "${ROOT}/scripts/geoip_purge_blacklisted.py" --root "${ROOT}/data/geoip/current" || true
  fi

  if [ "${ONLY}" = "all" ] || [ "${ONLY}" = "finish" ]; then
    bash "${ROOT}/scripts/geoip_finish.sh" || true
  fi

  # 最终保证：库必须在且可查。
  if [ ! -f "$DB" ]; then
    python3 "${ROOT}/scripts/geoip_seed_demo.py" --db "$DB" --force
  fi
  echo "[$(date '+%F %T')] geoip_update done"
} | tee -a "$LOG"
