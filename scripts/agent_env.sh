#!/bin/sh
# Crucible 并行 agent 测试环境：让 N 个子 agent 在同一台 VM 上互不干扰地跑自己的实例。
#
#   sh scripts/agent_env.sh start  <id>     # 用端口块 base=20000+id*200 起一个实例
#   sh scripts/agent_env.sh stop   <id>
#   sh scripts/agent_env.sh status <id>
#   sh scripts/agent_env.sh rebuild <id>    # 全局锁内：停自己的实例 → cargo build → 重启
#   sh scripts/agent_env.sh ports  <id>     # 打印端口
#
# 端口映射：new = base + (old - 19000)，其中 base = 20000 + id*200
#   19095→base+95  19081→base+81  19445→base+445 19446→base+446
#   18443→base+443 18444→base+444 55555→base+555 55556→base+556 11853→base+853
# 每个 id 独立的：DNS 状态根 state/dns-agent<id>、pidfile、日志、config-agent<id>.toml。
#
# 全局构建锁：/tmp/crucible-agent-build.lock（mkdir 原子锁）。rebuild 会在锁内
# 停掉**所有** agent 实例（因为共用 target/release/webserver，替换运行中的文件会
# Text file busy），构建完再把叫过 start 的实例拉起来。
set -e
cd /crucible

ID="${2:-}"
case "$ID" in ''|*[!0-9]*) echo "usage: $0 {start|stop|status|rebuild|ports} <id:1..99>" >&2; exit 2;; esac
BASE=$((20000 + ID * 200))
CFG="config-agent${ID}.toml"
PID="/tmp/crucible-agent${ID}.pid"
LOG="/tmp/crucible-agent${ID}.log"
LOCK=/tmp/crucible-agent-build.lock
STARTERS=/tmp/crucible-agent-starters

port_map() {
  # OpenBSD 的 sed **不支持 \b**（GNU 扩展）：必须按实际出现形式改写。
  # 配置里所有端口都是 `port = N` 形式（含 [dns.https_rr] 的 18443，与 listener 同号）。
  sed -e "s/port = 19095/port = $((BASE + 95))/" \
      -e "s/port = 19081/port = $((BASE + 81))/" \
      -e "s/port = 19445/port = $((BASE + 445))/" \
      -e "s/port = 19446/port = $((BASE + 446))/" \
      -e "s/port = 18443/port = $((BASE + 443))/" \
      -e "s/port = 18444/port = $((BASE + 444))/" \
      -e "s/port = 55555/port = $((BASE + 555))/" \
      -e "s/port = 55556/port = $((BASE + 556))/" \
      -e "s/port = 11853/port = $((BASE + 853))/" \
      config-test.toml > "$CFG.tmp"
  if [ "${AGENT_DNS:-0}" = "1" ]; then
    mv "$CFG.tmp" "$CFG"
  else
    # 默认关掉 [dns]：named/rndc/DoT 的端口由 test_mode 派生（5353/1953/11853），
    # 多实例会互相抢；只有专门测 DNS 的 agent 才用 AGENT_DNS=1。
    awk 'BEGIN{d=0} /^\[/{d=($0=="[dns]")} d&&/^enabled = true$/{print "enabled = false"; next} {print}' \
      "$CFG.tmp" > "$CFG.tmp2" && mv "$CFG.tmp2" "$CFG"
    rm -f "$CFG.tmp"
  fi
  # JSP 两个 app 的 socket 指到共享 sidecar（setup 里起一次），避免每个实例各拉一个 JVM。
  sed -e 's#socket = "state/jsp/test.sock"#socket = "/crucible/state/jsp/test.sock"#' "$CFG" > "$CFG.tmp" && mv "$CFG.tmp" "$CFG"
}

lock_acquire() {
  i=0
  while ! mkdir "$LOCK" 2>/dev/null; do
    i=$((i + 1))
    [ "$i" -gt 900 ] && { echo "lock timeout" >&2; exit 1; }
    # 老锁（>25min）视为死锁，清掉
    if [ -d "$LOCK" ] && [ -n "$(find "$LOCK" -maxdepth 0 -mmin +25 2>/dev/null)" ]; then
      rmdir "$LOCK" 2>/dev/null || true
    fi
    sleep 2
  done
}
lock_release() { rmdir "$LOCK" 2>/dev/null || true; }

is_running() {
  [ -f "$PID" ] && kill -0 "$(cat "$PID")" 2>/dev/null
}

do_start() {
  port_map
  mkdir -p "state/dns-agent${ID}"
  if is_running; then echo "agent${ID}: already running pid=$(cat "$PID")"; return 0; fi
  CRUCIBLE_DNS_STATE_ROOT="/crucible/state/dns-agent${ID}" \
    nohup ./target/release/webserver --config "/crucible/$CFG" >>"$LOG" 2>&1 </dev/null &
  echo $! > "$PID"
  echo "agent${ID}: pid=$(cat "$PID") ports=$((BASE + 95)),$((BASE + 81)),$((BASE + 445)),$((BASE + 446)),$((BASE + 443)) log=$LOG"
  touch "$STARTERS" 2>/dev/null || true
}

do_stop() {
  if is_running; then
    kill -TERM "$(cat "$PID")" 2>/dev/null || true
    n=0; while kill -0 "$(cat "$PID")" 2>/dev/null && [ $n -lt 15 ]; do sleep 1; n=$((n + 1)); done
    kill -KILL "$(cat "$PID")" 2>/dev/null || true
  fi
  rm -f "$PID"
  echo "agent${ID}: stopped"
}

do_status() {
  if is_running; then
    echo "agent${ID}: RUNNING pid=$(cat "$PID")"
    curl -s -o /dev/null -w "  probe $((BASE + 95)) -> %{http_code}\n" --max-time 5 "http://127.0.0.1:$((BASE + 95))/" || true
  else
    echo "agent${ID}: not running (config=$CFG ports base=$BASE)"
  fi
}

do_rebuild() {
  lock_acquire
  # 停掉所有 agent 实例（含自己），避免 Text file busy / 混用旧镜像
  for f in /tmp/crucible-agent*.pid; do
    [ -f "$f" ] || continue
    p=$(cat "$f" 2>/dev/null)
    [ -n "$p" ] && kill -TERM "$p" 2>/dev/null || true
  done
  sleep 2
  for f in /tmp/crucible-agent*.pid; do
    [ -f "$f" ] || continue
    p=$(cat "$f" 2>/dev/null)
    [ -n "$p" ] && kill -KILL "$p" 2>/dev/null || true
  done
  RC=0
  CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-4} cargo build --release || RC=$?
  # 谁在跑过就把谁拉起来
  for f in /tmp/crucible-agent*.pid; do
    [ -f "$f" ] || continue
    other=$(basename "$f" | sed -e 's/crucible-agent//' -e 's/\.pid//')
    [ -z "$other" ] && continue
    sh scripts/agent_env.sh start "$other" >/dev/null 2>&1 || true
  done
  lock_release
  [ "$RC" = 0 ] && echo "agent${ID}: rebuild OK" || echo "agent${ID}: rebuild FAILED (rc=$RC)"
  return "$RC"
}

case "${1:-}" in
  start)   do_start ;;
  stop)    do_stop ;;
  status)  do_status ;;
  ports)   echo "base=$BASE http=$((BASE + 95)) static=$((BASE + 81)) tls12=$((BASE + 445)) tls13=$((BASE + 446)) prod=$((BASE + 443)) h3=$((BASE + 444))" ;;
  rebuild) do_rebuild ;;
  *) echo "usage: $0 {start|stop|status|rebuild|ports} <id:1..99>" >&2; exit 2 ;;
esac
