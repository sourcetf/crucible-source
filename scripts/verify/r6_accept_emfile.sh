#!/bin/sh
# 第 6 轮并发报告 #1（**P0**）：fd 被打满后，监听口**不得永久死亡**。
#
# 修复前：`accept_loop` 用 `res?` 把任何 accept 错误直接 return Err ⇒ 该监听口此后不再
# accept（只有重启进程才恢复）；而且 v4/v6 是两个独立 accept 任务、只按 `bind_key` 记账，
# 死掉的那个释放 fd、活着的仍持 socket ⇒ reconciler 重建时一半 EADDRINUSE、整函数返回 Err
# 把刚绑上的另一半一起丢掉，每 2s 重试、**永远失败**。
#
# 判据：
#   A-a  基线可服务（200）
#   A-b  打满期间**允许**不可服务（000）—— 这是攻击确实生效的那一步，不是缺陷
#   A-c  释放 fd 之后必须**恢复**可服务（200）—— 修复前这里是永久 000
#   A-d  实例日志出现节流的「accept 失败（退避重试…）」且 `accept_loop … ended` 计数为 0
#        ⇒ 证明走的是重试路径，而不是「没被打到」
#
# 用法： R6_PORT=19095 R6_LOG=/var/log/xxx.log sh scripts/verify/r6_accept_emfile.sh
# 注意：会给目标实例制造真实 fd 压力，**只在测试实例上跑**；N 需大于该进程的 ulimit -n。
PORT="${R6_PORT:-19095}"
LOG="${R6_LOG:-}"
N="${R6_N:-2000}"
HOLD="${R6_HOLD:-30}"
B="http://127.0.0.1:$PORT"
pass=0; fail=0
chk() { if [ "$2" = "0" ]; then echo "PASS  $1"; pass=$((pass+1));
        else echo "FAIL  $1 :: $3"; fail=$((fail+1)); fi; }

echo "基线: $(curl -s -m 5 -o /dev/null -w '%{http_code}' "$B/")"
c=$(curl -s -m 5 -o /dev/null -w '%{http_code}' "$B/"); [ "$c" = "200" ]; chk "A-a 基线 200" $? "c=$c"

cd /tmp || exit 1
nohup python3 "$(dirname "$0")/r6_accept_emfile.py" "$PORT" "$N" "$HOLD" > /tmp/r6exh.txt 2>&1 &
sleep 12
c=$(curl -s -m 5 -o /dev/null -w '%{http_code}' "$B/"); echo "打满期间: $c"; cat /tmp/r6exh.txt
sleep $((HOLD - 8))
c=$(curl -s -m 5 -o /dev/null -w '%{http_code}' "$B/"); echo "释放后: $c"
[ "$c" = "200" ]; chk "A-c 释放后恢复 200" $? "c=$c"

if [ -n "$LOG" ] && [ -f "$LOG" ]; then
  n=$(grep -c 'accept 失败' "$LOG")
  ended=$(grep -c 'accept_loop .* ended' "$LOG")
  echo "日志: accept 失败=$n  accept_loop ended=$ended"
  [ "$n" -ge 1 ]; chk "A-d 走了退避重试路径" $? "n=$n"
  [ "$ended" = "0" ]; chk "A-e accept 循环没有结束" $? "ended=$ended"
else
  echo "SKIP  A-d/A-e（未给 R6_LOG，无法核对日志证据）"
fi
echo; echo "==== 汇总: PASS=$pass FAIL=$fail ===="
[ "$fail" = "0" ]
