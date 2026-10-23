#!/bin/sh
# accept-verify-start.sh — 启动一个隔离的 Crucible 验收实例（工号 1009 / agent-verify5）。
# 端口块 38000+，DNS 状态根独立。cwd 必须是仓库根（docroot 是相对路径）。
# 用法: sh scripts/accept-verify-start.sh
set -e
REPO=/home/dev123/crucible-git
SCRATCH=/home/dev123/scratch-verify7
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
# 应用运行时（PHP/Ruby/Perl/JDK/Node/.NET）装在 ~/local：15 个引擎要真 200 必须
# 让实例继承 runtime_env.sh 的 PATH/LD_LIBRARY_PATH/JAVA_HOME/DOTNET_ROOT。
# runtime_env.sh 是 bash 脚本（含 local/函数），用 bash 子壳 source 后 exec —— PID 不变，
# accept-verify-stop.sh 仍按 PID/config 精确停实例。
nohup bash -c '. "$1/scripts/runtime_env.sh" 2>/dev/null || true; exec "$2" --config "$3"' \
  _ "$REPO" "$BIN" "$CFG" >>"$LOG" 2>&1 </dev/null &
WPID=$!
echo "$WPID" >"$PIDF"
echo "started pid=$WPID cfg=$CFG log=$LOG"
# 等待端口就绪
i=0
while [ $i -lt 40 ]; do
  if curl -s -o /dev/null --max-time 1 http://127.0.0.1:38081/ 2>/dev/null; then echo "ready after ${i}00ms"; exit 0; fi
  i=$((i+1)); sleep 0.25
done
echo "WARN: not ready in 10s; last log:"; tail -20 "$LOG"
exit 1
