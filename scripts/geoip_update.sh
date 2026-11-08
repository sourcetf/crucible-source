#!/usr/bin/env bash
# §6 GeoIP 更新总链：fetch 层 → merge（§5 权重）→ enrich 全套 → finish（黑名单清洗+校验）。
# 用法：
#   geoip_update.sh                # 全链（staging 构建 + 原子换库）
#   geoip_update.sh --only merge   # 只重建库（同样 staging + 原子换库）
#   --only fetch|enrich|blacklist|finish|geofeed
#   --only geofeed                 # P1-9：只导入面板自定义 geofeed 列表（读供给层 JSON）
#
# P2-19 原始分层保留：fetch 把 `01-cloud/…` 等原始分层写进 `current/`（merge 依赖它）。
# 默认（未设 `GEOIP_KEEP_RAW=1`）在全链收尾时**清掉**这些原始分层目录，只保留
# `geoip.sqlite` / `SOURCES.json`（§23.1）；设 `GEOIP_KEEP_RAW=1` 才保留原始分层。
#
# U-17/原子性：`all`/`merge` 不再原地重写 geoip.sqlite，而是先建
# `geoip.sqlite.next`，enrich/finish 全在 .next 上跑，最后 `integrity_check` +
# 原子 `mv` 覆盖旧库。任何一步失败都**不换库**，线上继续读旧库（旧库原样保留）。
#
# 路径覆盖：`CRUCIBLE_GEOIP_DATA_ROOT` 可把整条链指到 staging/测试目录
# （默认 `<repo>/data/geoip`）；`CRUCIBLE_GEOIP_DB` 可单独覆盖库路径。
# 生产默认行为与旧版一致（只多了 staging + 原子切换）。
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DATA="${CRUCIBLE_GEOIP_DATA_ROOT:-${ROOT}/data/geoip}"
DB="${CRUCIBLE_GEOIP_DB:-${DATA}/current/geoip.sqlite}"
LOG="${CRUCIBLE_GEOIP_LOG:-${DATA}/logs/update.log}"
STAGE="${DB}.next"
mkdir -p "$(dirname "$DB")" "$(dirname "$LOG")" "${DATA}/sources"

# `--only X` / `--only=X` 都接受；旧实现只认 `$2`，`--only=merge` 会退化成 all。
ONLY=all
ARGS=("$@")
for ((i = 0; i < ${#ARGS[@]}; i++)); do
  a="${ARGS[$i]}"
  if [ "$a" = "--only" ]; then
    ONLY="${ARGS[$((i + 1))]:-all}"
  elif [[ "$a" == --only=* ]]; then
    ONLY="${a#--only=}"
  fi
done

# 单实例锁：面板按钮、cron、手工命令都可能同时触发。merge/enrich 不是为并发写的
# （两个进程同时改同一个 SQLite），实测一次误操作就拉起了 4 个并发更新。
# mkdir 是原子的：拿不到就是有人在跑。锁里记 pid，进程没了就清陈旧锁，避免永久卡死。
LOCK="${DATA}/logs/update.lock"
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

# 导出给所有 Python 步骤：同一份数据根 / 库 / 面板 / 层目录（脚本内相对路径
# `data/geoip` 的硬编码也用 CRUCIBLE_GEOIP_DATA_ROOT 兜住）。
export CRUCIBLE_GEOIP_DATA_ROOT="$DATA"
export CRUCIBLE_GEOIP_DB="$DB"
export CRUCIBLE_GEOIP_SOURCES="${DATA}/current/SOURCES.json"
export CRUCIBLE_GEOIP_PANEL_DB="${DATA}/panel.sqlite"
export CRUCIBLE_GEOIP_PANEL="${DATA}/panel.toml"
export CRUCIBLE_GEOIP_LAYERS="${DATA}/current"
export CRUCIBLE_GEOIP_SOURCES_DIR="${DATA}/sources"
# P1-9：自定义 geofeed 供给层（面板写入的 URL 列表；--only=geofeed 时被消费）。
export CRUCIBLE_GEOIP_CUSTOM_GEOFEED="${CRUCIBLE_GEOIP_CUSTOM_GEOFEED:-${DATA}/sources/custom_geofeed.json}"

have_network() {
  command -v curl >/dev/null 2>&1 && curl -fsS --connect-timeout 3 -o /dev/null https://example.com 2>/dev/null
}

now_ms() {
  # 返回**纳秒**（调用处用 `/(10^6)` 换算成 ms）。
  #
  # 原实现是 `date +%s%N` —— **GNU 专有**。OpenBSD 的 date 不支持 `%N`，会原样输出字面 `N`，
  # 于是 `run_step` 里 `$(( $(now_ms) - t0 ))` 成了 `1794102289N` 这种非法 token；而 OpenBSD
  # 的 sh/ksh 在算术错误时**直接终止脚本** ⇒ 整条 GeoIP 更新链在**第一个 run_step 结束后**
  # 就死掉（fetch 跑完、merge/enrich/finish/完整性门禁/原子换库全没执行），库永远停在旧版本。
  # 真机实证（2026-11-08）：`daily` 定时确实在触发、`update.log` 显示 `13/14 sources ok` 后
  # 再无输出，而 `current/geoip.sqlite` 仍是 Sep 24 的库。
  # 修法：用 python3 取纳秒（脚本本来就依赖 python3），无 python 时退回秒×1e9（精度差但可用）。
  python3 -c 'import time;print(time.time_ns())' 2>/dev/null \
    || echo "$(( $(date +%s) * 1000000000 ))"
}
file_size() {
  # BSD/GNU 通吃：OpenBSD 的 stat **没有** `-c`（GNU 语法，只有 `-f %z`）；反之 GNU stat 只有 `-c`。
  # 原实现 `stat -c %s ... || echo 0` 在 OpenBSD 上**恒返回 0**（错误被 `||` 吞掉），
  # 于是「按现有库大小预估所需空间」的磁盘预检形同虚设。
  [ -f "$1" ] || { echo 0; return; }
  stat -f %z "$1" 2>/dev/null || stat -c %s "$1" 2>/dev/null || echo 0
}

# 一步一计时：输出 `<step> rc=… elapsed=…ms`，主会话/报告直接引用。
run_step() {
  local name="$1"
  local usedb="$2"
  shift 2
  local t0 rc
  t0="$(now_ms)"
  if [ -n "$usedb" ]; then
    CRUCIBLE_GEOIP_DB="$usedb" "$@"
  else
    "$@"
  fi
  rc=$?
  echo "[$(date '+%F %T')] step ${name} rc=${rc} elapsed=$(( ($(now_ms) - t0) / 1000000 ))ms"
  return "$rc"
}


db_stats() {
  python3 - "$1" <<'PY'
import sqlite3, sys
p = sys.argv[1]
try:
    c = sqlite3.connect(p)
    q = lambda s: c.execute(s).fetchone()[0]
    print(
        "db_stats",
        f"geoip={q('SELECT COUNT(*) FROM geoip')}",
        f"ipv4={q('SELECT COUNT(*) FROM ipv4')}",
        f"ipv6={q('SELECT COUNT(*) FROM ipv6')}",
        f"anycast={q('SELECT COUNT(*) FROM anycast')}",
        f"file={p}",
    )
    c.close()
except Exception as e:  # noqa: BLE001
    print(f"db_stats failed: {e}", file=sys.stderr)
    sys.exit(1)
PY
}

# staging 完整性门禁：库可读、integrity_check=ok、主表非空。不过关绝不换库。
validate_stage() {
  python3 - "$1" <<'PY'
import sqlite3, sys
p = sys.argv[1]
try:
    c = sqlite3.connect(p)
    ok = c.execute("PRAGMA integrity_check").fetchone()[0]
    n = c.execute("SELECT COUNT(*) FROM geoip").fetchone()[0]
    c.close()
except Exception as e:  # noqa: BLE001
    print(f"stage invalid: {e}")
    sys.exit(1)
print(f"stage integrity={ok} geoip_rows={n} bytes={__import__('os').path.getsize(p)}")
sys.exit(0 if ok == "ok" and n > 0 else 1)
PY
}

ENRICH_SCRIPTS=(
  geoip_enrich_iana_special.py
  geoip_enrich_geocn.py
  geoip_enrich_qqwry.py
  geoip_enrich_cernet.py
  geoip_enrich_cloud_geo.py
  geoip_enrich_places.py
  geoip_resolve_asn_bgp.py
  geoip_enrich_netorg.py
  geoip_enrich_rir_geofeed.py
  geoip_enrich_ripe_anycast_extract.py
  geoip_enrich_ixp.py
  geoip_enrich_google_rdns.py
  geoip_enrich_cn_extra.py
)

{
  echo "[$(date '+%F %T')] geoip_update start (only=${ONLY} data=${DATA} db=${DB})"

  if [ "${ONLY}" = "all" ] || [ "${ONLY}" = "fetch" ]; then
    if [ "${GEOIP_SKIP_FETCH:-0}" = "1" ]; then
      echo "skip fetch (GEOIP_SKIP_FETCH=1)，复用 ${DATA}/current 下已有层文件"
    elif have_network; then
      run_step fetch "" python3 "${ROOT}/scripts/geoip_fetch_layers.py" || echo "warn: fetch_layers failed"
    else
      echo "warn: no network; skip fetch"
    fi
  fi

  # 前置检查：GeoCN.jsonl 是**国内主力源**（权重 820，实测 220 万行）的输入，由 Go 写的
  # scripts/geoip-mmdb2jsonl 从同目录 GeoCN.mmdb 生成 —— 更新链不会自动生成它（本机也没装 Go）。
  # 缺了它 enrich 只会打一行 "run mmdb2jsonl first"，然后静默丢掉最大的源，
  # 所以在开工前就把话说重一点，并明确「不要为了腾空间删它」。
  #
  # 文件名大小写：上游/文档里出现过 GeoCn 与 GeoCN 两种写法，实际落盘的是 **GeoCN**。
  # OpenBSD 的文件系统区分大小写，只测 GeoCn.* 会让**源明明在**也天天报「将被跳过」
  # （实测 111 万行照样导进去了，警告纯属误报）。两种拼写都认。
  geoip_src_exists() { [ -s "${DATA}/sources/$1" ] || [ -s "${DATA}/sources/$2" ]; }
  if ! geoip_src_exists GeoCN.jsonl GeoCn.jsonl; then
    if geoip_src_exists GeoCN.mmdb GeoCn.mmdb; then
      echo "warn: 缺少 sources/GeoCN.jsonl（GeoCN.mmdb 在，但需要 Go 工具生成）——"
      echo "warn: 本次会跳过国内主力源（约 220 万行）。生成命令：cd ${ROOT} && go run scripts/geoip-mmdb2jsonl . > data/geoip/sources/GeoCN.jsonl"
    else
      echo "warn: 缺少 sources/GeoCN.mmdb 与 GeoCN.jsonl —— 国内主力源将被跳过。"
    fi
  fi

  TARGET_DB="$DB"
  STAGED=0
  CRITICAL_FAIL=0
  ENRICH_FAILS=0
  ENRICH_TOTAL=0

  # ---------- merge：构建 staging（不碰线上库） ----------
  if [ "${ONLY}" = "all" ] || [ "${ONLY}" = "merge" ]; then
    # file_size 返回**字节**，df -k 是 1KiB 块：先换算，否则 257MB 的库会被当成
    # 257GB（实测把一次正常更新误判成「磁盘不足」直接跳过 merge）。
    DBSZ_K=$(( $(file_size "$DB") / 1024 ))
    FREEK=$(df -k "$(dirname "$DB")" 2>/dev/null | awk 'NR==2{print $4}')
    NEEDK=$(( DBSZ_K + 262144 ))   # 库大小 + 256MiB 余量
    if [ -n "$FREEK" ] && [ "$FREEK" -lt "$NEEDK" ]; then
      echo "warn: 磁盘空间不足，跳过 merge（需 ≥$((NEEDK/1024))MiB 空闲，实际 $((FREEK/1024))MiB）。"
      echo "warn: 保留旧库不变；建议先清理 ${DATA}/sources 下的旧层文件（raw 抓取缓存）。"
      CRITICAL_FAIL=1
    else
      rm -f "$STAGE"
      if run_step merge "$STAGE" python3 "${ROOT}/scripts/geoip_merge.py" \
           --db "$STAGE" --init-schema --import-layers --layers "${DATA}/current"; then
        echo "[$(date '+%F %T')] merge staged ${STAGE} size=$(file_size "$STAGE")B"
        TARGET_DB="$STAGE"
        STAGED=1
      else
        echo "warn: merge failed —— 丢弃 staging，旧库保持不变"
        rm -f "$STAGE"
        CRITICAL_FAIL=1
      fi
    fi
  fi

  # ---------- enrich：在 staging 上跑（只有 merge 成功才做） ----------
  if { [ "${ONLY}" = "all" ] || [ "${ONLY}" = "enrich" ]; } && [ "$CRITICAL_FAIL" -eq 0 ]; then
    ENRICH_TARGET="$TARGET_DB"
    ENRICH_TIMEOUT="${GEOIP_ENRICH_TIMEOUT:-1800}"
    for script in "${ENRICH_SCRIPTS[@]}"; do
      ENRICH_TOTAL=$((ENRICH_TOTAL + 1))
      # 每个 enrich 单独限时：某个源挂住（慢 RIR dump / RDAP / rdns）不应让整条
      # 更新链永远卡在 staging 上。默认 1800s/步，可用 GEOIP_ENRICH_TIMEOUT 覆盖。
      #
      # netorg 例外：它要通读 RIPE/APNIC/AFRINIC/LACNIC 四份 whois 全量 dump
      # （RIPE 解压后约 2GB、近千万对象，逐条 upsert），1800s 打不住 —— 实测单 RIPE
      # 就要 30 分钟以上。给它 7200s，可用 GEOIP_NETORG_TIMEOUT 覆盖。
      step_timeout="$ENRICH_TIMEOUT"
      case "$script" in
        geoip_enrich_netorg.py) step_timeout="${GEOIP_NETORG_TIMEOUT:-7200}" ;;
      esac
      if ! run_step "enrich/${script}" "$ENRICH_TARGET" \
           timeout "$step_timeout" python3 "${ROOT}/scripts/${script}"; then
        ENRICH_FAILS=$((ENRICH_FAILS + 1))
        echo "warn: ${script} failed (timeout=${step_timeout}s)"
      fi
    done
    if [ "$ENRICH_TOTAL" -gt 0 ] && [ "$ENRICH_FAILS" -ge "$ENRICH_TOTAL" ]; then
      echo "warn: 所有 enrich 步骤都失败 —— 视为更新失败，回滚（不换库）"
      CRITICAL_FAIL=1
    elif [ "${GEOIP_REQUIRE_ALL_ENRICH:-0}" = "1" ] && [ "$ENRICH_FAILS" -gt 0 ]; then
      echo "warn: GEOIP_REQUIRE_ALL_ENRICH=1 且 ${ENRICH_FAILS}/${ENRICH_TOTAL} enrich 失败 —— 回滚（不换库）"
      CRITICAL_FAIL=1
    fi
  fi

  # ---------- geofeed（P1-9 自定义列表批量刷新；仅 --only=geofeed） ----------
  # 面板把启用的 URL 落成供给层 JSON，这里消费它并逐 URL 导入（RFC8805）。
  # 直接作用于 TARGET_DB（--only=geofeed 时 TARGET_DB == 线上库，因为跳过了 merge）。
  if [ "${ONLY}" = "geofeed" ] && [ "$CRITICAL_FAIL" -eq 0 ]; then
    if [ -s "${CRUCIBLE_GEOIP_CUSTOM_GEOFEED}" ]; then
      run_step geofeed "$TARGET_DB" python3 "${ROOT}/scripts/geoip_enrich_geofeed.py" \
        --db "$TARGET_DB" --urls-file "${CRUCIBLE_GEOIP_CUSTOM_GEOFEED}" \
        || echo "warn: custom geofeed import failed"
    else
      echo "warn: --only=geofeed 但供给层 ${CRUCIBLE_GEOIP_CUSTOM_GEOFEED} 不存在/为空（先在面板添加 URL 并刷新）"
    fi
  fi

  # ---------- blacklist / finish：同样作用于 staging ----------
  if { [ "${ONLY}" = "all" ] || [ "${ONLY}" = "blacklist" ] || [ "${ONLY}" = "finish" ]; } && [ "$CRITICAL_FAIL" -eq 0 ]; then
    if ! run_step blacklist "$TARGET_DB" python3 "${ROOT}/scripts/geoip_purge_blacklisted.py" \
         --db "$TARGET_DB" --root "${DATA}/current" --blacklist "${DATA}/blacklist.json"; then
      echo "warn: blacklist purge failed —— 回滚（不换库）"
      CRITICAL_FAIL=1
    fi
  fi

  if { [ "${ONLY}" = "all" ] || [ "${ONLY}" = "finish" ]; } && [ "$CRITICAL_FAIL" -eq 0 ]; then
    # 原 geoip_finish.sh 的最后一步是「样本 lookup 必须可查」；这里直接在目标库上做，
    # 避免它内部写死的生产路径把 staging 测试又指回 data/geoip/current。
    if ! run_step finish-lookup "$TARGET_DB" python3 "${ROOT}/scripts/geoip_lookup.py" \
         1.2.4.8 --db "$TARGET_DB" --json; then
      echo "warn: 样本 lookup 失败 —— 回滚（不换库）"
      CRITICAL_FAIL=1
    fi
  fi

  # ---------- 原子换库 ----------
  if [ "$STAGED" -eq 1 ]; then
    if [ "$CRITICAL_FAIL" -eq 0 ] && validate_stage "$STAGE"; then
      # 同一文件系统内 rename 是原子的：并发查询要么读到旧文件、要么读到新文件，
      # 不会看到半个库。旧库在 rename 前始终保持完整（失败回滚自然成立）。
      if mv -f "$STAGE" "$DB"; then
        echo "[$(date '+%F %T')] swapped staged db -> ${DB} size=$(file_size "$DB")B"
        db_stats "$DB" || true
      else
        echo "warn: mv staging -> db 失败，旧库保持不变"
        rm -f "$STAGE"
        CRITICAL_FAIL=1
      fi
    else
      echo "warn: staging 校验失败，丢弃 ${STAGE}，旧库保持不变"
      rm -f "$STAGE"
      CRITICAL_FAIL=1
    fi
  fi

  # 最终保证：库必须在且可查（只有完全没有库时才 seed；有旧库就不动）。
  if [ ! -f "$DB" ]; then
    run_step seed "" python3 "${ROOT}/scripts/geoip_seed_demo.py" --db "$DB" --force || true
  fi
  # P2-19：原始分层默认不保留（§23.1）。全链/仅 fetch 跑完后，若未设 GEOIP_KEEP_RAW=1，
  # 清掉 `current/NN-*` 原始分层目录（保留 geoip.sqlite / SOURCES.json）；设了则原样保留。
  if { [ "${ONLY}" = "all" ] || [ "${ONLY}" = "fetch" ]; } && [ "${GEOIP_KEEP_RAW:-0}" != "1" ]; then
    removed=0
    for d in "${DATA}/current"/[0-9][0-9]-*; do
      [ -d "$d" ] || continue
      rm -rf "$d" && removed=$((removed + 1))
    done
    if [ "$removed" -gt 0 ]; then
      echo "[$(date '+%F %T')] raw layers cleaned (${removed} dirs；GEOIP_KEEP_RAW!=1，设 1 可保留)"
    fi
  fi

  # tor 池是自我守护化的进程，采完必须显式收掉（否则会一直残留）。
  if [ -d /tmp/geoip-tor-pool ]; then
    python3 "${ROOT}/scripts/geoip_tor_pool.py" stop || echo "warn: tor pool stop failed"
  fi
  if [ "$CRITICAL_FAIL" -ne 0 ]; then
    echo "[$(date '+%F %T')] geoip_update done (FAILED: 旧库保持不变 / rolled back)"
  else
    echo "[$(date '+%F %T')] geoip_update done (ok)"
  fi
} | tee -a "$LOG"
