#!/bin/sh
# accept-verify-start.sh — 启动一个隔离的 Crucible 验收实例（工号 1009 / agent-verify2）。
# 端口块 26000+，DNS 状态根独立。cwd 必须是仓库根（docroot 是相对路径）。
# 用法: sh scripts/accept-verify-start.sh
set -e
REPO=/home/dev123/crucible-git
SCRATCH=/home/dev123/scratch-verify2
CFG=${ACCEPT_CFG:-$SCRATCH/conf/config-verify.toml}
BIN=${ACCEPT_BIN:-$SCRATCH/bin/webserver}
LOG=$SCRATCH/logs/webserver.log
PIDF=$SCRATCH/webserver.pid

cd "$REPO"
mkdir -p "$SCRATCH/logs"
export CRUCIBLE_DNS_STATE_ROOT=$SCRATCH/state-dns
mkdir -p "$CRUCIBLE_DNS_STATE_ROOT"

# 只杀我们自己的实例（按 config 路径精确匹配），不碰别人的
if [ -f "$PIDF" ]; then
  OLD=$(cat "$PIDF" 2>/dev/null || true)
  if [ -n "$OLD" ] && kill -0 "$OLD" 2>/dev/null; then kill "$OLD" 2>/dev/null || true; sleep 1; fi
  rm -f "$PIDF"
fi
pkill -f "webserver --config $CFG" 2>/dev/null || true
sleep 1

: > "$LOG"
nohup "$BIN" --config "$CFG" >>"$LOG" 2>&1 </dev/null &
WPID=$!
echo "$WPID" >"$PIDF"
echo "started pid=$WPID cfg=$CFG log=$LOG"
# 等待端口就绪
i=0
while [ $i -lt 40 ]; do
  if curl -s -o /dev/null --max-time 1 http://127.0.0.1:26081/ 2>/dev/null; then echo "ready after ${i}00ms"; exit 0; fi
  i=$((i+1)); sleep 0.25
done
echo "WARN: not ready in 10s; last log:"; tail -20 "$LOG"
exit 1
