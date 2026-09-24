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

# 单实例锁：面板按钮、cron、手工命令都可能同时触发。merge/enrich 不是为并发写的
# （两个进程同时改同一个 SQLite），实测一次误操作就拉起了 4 个并发更新。
# mkdir 是原子的：拿不到就是有人在跑。锁里记 pid，进程没了就清陈旧锁，避免永久卡死。
LOCK="${ROOT}/data/geoip/logs/update.lock"
if ! mkdir "$LOCK" 2>/dev/null; then
  OLDPID="$(cat "$LOCK/pid" 2>/dev/null || echo 0)"
  # 必须确认那个 pid 的命令行仍是本脚本：pid 会被复用，只看 kill -0 会让锁永远清不掉。
  if [ "${OLDPID:-0}" -gt 1 ] && kill -0 "$OLDPID" 2>/dev/null      && ps -p "$OLDPID" -o command= 2>/dev/null | grep -q 'geoip_update.sh'; then
    echo "[$(date '+%F %T')] geoip_update 已在运行（pid=${OLDPID}），本次跳过 (only=${ONLY})" >>"$LOG"
    exit 0
  fi
  echo "[$(date '+%F %T')] geoip_update 清理陈旧锁（pid=${OLDPID:-?} 已不在）" >>"$LOG"
  rm -rf "$LOCK"
  if ! mkdir "$LOCK" 2>/dev/null; then
    echo "[$(date '+%F %T')] geoip_update 抢锁失败，本次跳过 (only=${ONLY})" >>"$LOG"
    exit 0
  fi
fi
echo $$ >"$LOCK/pid"
trap 'rm -rf "$LOCK" 2>/dev/null' EXIT INT TERM

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

  # 磁盘预检：merge 是就地重写 geoip.sqlite（导入各层 + 建索引），需要相当于库大小
  # 量级的临时空间（回滚日志/临时 B 树）。实测一次磁盘写满的后果：merge 默默死在
  # 半路（dmesg 里刷 "file system full"），面板只看到「更新没了」，而库里还是旧数据。
  # 空间不够就**跳过 merge 并说清楚**，保留上一份完整数据，比写坏库好得多。
  if [ "${ONLY}" = "all" ] || [ "${ONLY}" = "merge" ]; then
    DBSZ=$( [ -f "$DB" ] && du -k "$DB" 2>/dev/null | awk '{print $1}' || echo 0 )
    FREEK=$(df -k "$DB" 2>/dev/null | awk 'NR==2{print $4}')
    NEEDK=$(( DBSZ + 262144 ))   # 库大小 + 256MiB 余量
    if [ -n "$FREEK" ] && [ "$FREEK" -lt "$NEEDK" ]; then
      echo "warn: 磁盘空间不足，跳过 merge（需 ≥$((NEEDK/1024))MiB 空闲，实际 $((FREEK/1024))MiB）。"
      echo "warn: 建议先清理 ${ROOT}/data/geoip/sources 下的旧层文件（raw 抓取缓存），再重跑 --only merge。"
    else
      python3 "${ROOT}/scripts/geoip_merge.py" --db "$DB" --init-schema --import-layers \
        || echo "warn: merge failed"
    fi
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
