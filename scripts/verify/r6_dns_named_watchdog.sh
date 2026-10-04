#!/bin/sh
# 第 6 轮并发报告 #4：named 必须有**存活看门狗**。
#
# 修复前：`reconcile()`（内含 named_alive→spawn）只在启动 / 配置变更 / 面板操作时被调用，
# `maintenance_loop` 没有任何周期性 liveness 检查 ⇒ named 一旦 OOM/崩溃，**在下次改配置之前
# DNS 一直不可用**（静默故障，除了解析失败没有别的信号）。实测 26s 内不重启。
# 修复后：每 30s 探一次，死了走同一条 reconcile 拉起。
#
# 判据：
#   D-a 前置：本实例的 named 在跑（按 **-c 配置文件路径**识别，绝不动生产那个）
#   D-b kill 之后 75s 内**自动**出现新的 named（新 pid）
#   D-c 实例日志出现看门狗文案，证明走的是看门狗而不是别的东西
#
# 用法：
#   CRUCIBLE_DNS_STATE_ROOT=/tmp/r6-dns sh -c 'cd /crucible && ./target/release/webserver --config /crucible/<cfg> > /tmp/r6dns.log 2>&1 &'
#   R6_STATE_ROOT=/tmp/r6-dns R6_LOG=/tmp/r6dns.log sh scripts/verify/r6_dns_named_watchdog.sh
#
# 安全：只 kill 命令行里带 `-c $R6_STATE_ROOT/etc/named.conf` 的那个 named。
STATE="${R6_STATE_ROOT:-}"
LOG="${R6_LOG:-}"
WAIT="${R6_WAIT:-75}"
pass=0; fail=0
chk() { if [ "$2" = "0" ]; then echo "PASS  $1"; pass=$((pass+1));
        else echo "FAIL  $1 :: $3"; fail=$((fail+1)); fi; }
[ -n "$STATE" ] || { echo "必须给 R6_STATE_ROOT（本实例的 DNS 状态目录）"; exit 2; }

find_named() { ps -o pid,args -ax | grep '[n]amed' | grep -- "-c $STATE/etc/named.conf" | awk '{print $1}'; }
pid=$(find_named | head -1)
[ -n "$pid" ]; chk "D-a 前置：本实例 named 在跑 (pid=$pid)" $? "pid='$pid'"
[ -n "$pid" ] || exit 1

echo "kill $pid …"; kill "$pid" 2>/dev/null; sleep 3
n=$(find_named | wc -l | tr -d ' ')
echo "kill 后立即: $n 个"; [ "$n" = "0" ]; chk "D-b1 已杀掉" $? "n=$n"

echo "等 ${WAIT}s（看门狗 tick=30s）…"; sleep "$WAIT"
new=$(find_named | head -1)
echo "等完后: pid=$new"
[ -n "$new" ] && [ "$new" != "$pid" ]; chk "D-b2 自动拉起（新 pid）" $? "new=$new old=$pid"

if [ -n "$LOG" ] && [ -f "$LOG" ]; then
  grep -q '看门狗' "$LOG"; chk "D-c 日志出现看门狗文案" $? ""
else
  echo "SKIP  D-c（未给 R6_LOG）"
fi
echo; echo "==== 汇总: PASS=$pass FAIL=$fail ===="
[ "$fail" = "0" ]
