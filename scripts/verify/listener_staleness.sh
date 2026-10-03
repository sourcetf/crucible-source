#!/bin/sh
# J 项修复的隔离复验：**已建立**的 h1/h2 连接在 listener 配置变化后必须收尾。
#
# 为什么需要它：h1/h2 在 accept 时拿走一份 `ListenerConfig` 快照，整条连接的所有请求都用它
# —— 也就是说 `root`/`basic_auth`/`page_rules`/`file_open`/限流 改了之后，**已建立**的连接
# 永远沿用旧策略（只有新连接拿到新配置）。改 `basic_auth` 口令「改了没生效」是安全相关的。
#
# 六条判据（前两条是**反向**判据，防的是「修过头」：每次保存配置就把在线连接全踢下线）：
#   h1 ① 不改配置       → keep-alive 连接不得出现 Connection: close
#   h1 ② 只改 [access_log] → 不得出现 Connection: close（非 listener 变化与连接无关）
#   h1 ③ 改 root        → 必须 Connection: close，且**新**连接拿到新 root
#   h2 ① 不改配置       → h2 会话不得收到 GOAWAY
#   h2 ② 改 root        → h2 会话必须 GOAWAY/关闭，且**新**会话拿到新 root
# （h2 用 node 自带 http2 模块：curl 看不到 GOAWAY 帧。）
#
# 全程 loopback + 临时实例，不碰生产端口。
set -u
DIR=$(cd "$(dirname "$0")" && pwd)
BIN=${BIN:-/crucible/bin/webserver}
D=/tmp/crucible-stale
CFG=/tmp/crucible-stale.toml
PORT=${PORT:-18470}
FAIL=0

rm -rf $D; mkdir -p $D/A $D/B
printf 'AAA' > $D/A/index.html
printf 'BBB' > $D/B/index.html

write_a() {
  cat > $CFG <<EOF
[[listeners]]
address = "127.0.0.1"
port = $PORT
root = "$D/A"
http_versions = ["h1", "h2"]
EOF
}

write_a
$BIN --config $CFG --check-config >/dev/null 2>&1 || { echo "!! 预检失败"; exit 1; }
cd $D || exit 1
$BIN --config $CFG > $D/v.log 2>&1 &
PID=$!

cleanup() { kill $PID 2>/dev/null; rm -f $CFG; rm -rf $D; }
trap cleanup EXIT INT TERM

sleep 3
kill -0 $PID 2>/dev/null || { echo "!! 实例没起来"; tail -5 $D/v.log; exit 1; }
echo "pid=$PID  port=$PORT"

# 每轮都从同一初始状态（root=A）开始；等 mtime 监视器（2s 轮询）把配置读进去
reset_a() { write_a; sleep 4.5; }

echo
echo "=== h1 ① 基线：不改配置，keep-alive 连接不得被收尾（反向判据）==="
reset_a
python3 "$DIR/listener_staleness_h1.py" $PORT baseline $CFG "$D/A" "$D/B" || FAIL=1

echo
echo "=== h1 ② 只改 [access_log]：不得收尾（反向判据）==="
reset_a
python3 "$DIR/listener_staleness_h1.py" $PORT nonlistener $CFG "$D/A" "$D/B" || FAIL=1

echo
echo "=== h1 ③ 改 root：必须 Connection: close 且新连接拿到新 root ==="
reset_a
python3 "$DIR/listener_staleness_h1.py" $PORT listener $CFG "$D/A" "$D/B" || FAIL=1

echo
echo "=== h2 ① 基线：不改配置，h2 会话不得收到 GOAWAY（反向判据）==="
reset_a
node "$DIR/listener_staleness_h2.js" $PORT baseline $CFG "$D/B" || FAIL=1

echo
echo "=== h2 ② 改 root：必须 GOAWAY/关闭，且新会话拿到新 root ==="
reset_a
node "$DIR/listener_staleness_h2.js" $PORT listener $CFG "$D/B" || FAIL=1

echo
if [ "$FAIL" -eq 0 ]; then
  echo "=== J 项复验：全部 PASS ==="
else
  echo "=== J 项复验：有 FAIL（见上）==="
fi
exit $FAIL