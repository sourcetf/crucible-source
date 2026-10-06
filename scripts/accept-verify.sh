#!/bin/sh
# accept-verify.sh — 工号 1009 黑盒验收一键跑。
#   sh scripts/accept-verify.sh            # 全量：起实例 + 上游 + 跑 HTTP/H2/H3/DNS + 汇总
#   sh scripts/accept-verify.sh --no-build # 跳过 cargo build（用已有二进制）
# 端口块 23000+；DNS 状态根独立；不碰别人的端口/进程。
set -u
REPO=/home/dev123/crucible-git
SCRATCH=/home/dev123/scratch-verify
PY=python3

cd "$REPO" || exit 2
mkdir -p "$SCRATCH"/{tmp,logs,conf,state-dns,bin}

# ── 准备测试 docroot ──
mkdir -p "$SCRATCH/www-adv/new" "$SCRATCH/www-adv/old" "$SCRATCH/www-rate" \
         "$SCRATCH/www-auth" "$SCRATCH/www-ip" "$SCRATCH/www-up/sub" "$SCRATCH/www-up/php" \
         "$SCRATCH/www-up/listing/sub"
echo "adv index" > "$SCRATCH/www-adv/index.html"
echo "new content" > "$SCRATCH/www-adv/new/index.html"
echo "rate ok" > "$SCRATCH/www-rate/index.html"
echo "auth ok" > "$SCRATCH/www-auth/index.html"
echo "ip ok" > "$SCRATCH/www-ip/index.html"
echo "up index" > "$SCRATCH/www-up/index.html"
echo "sub" > "$SCRATCH/www-up/sub/inside.txt"
echo "<?php echo 'up';" > "$SCRATCH/www-up/php/index.php"
echo "inner" > "$SCRATCH/www-up/listing/sub/x.txt"

# ── 构建（可选）──
if [ "${1:-}" != "--no-build" ]; then
  . /home/dev123/bin/buildenv.sh
  export CARGO_TARGET_DIR="$SCRATCH/target"
  export CARGO_BUILD_JOBS=8
  echo "==> cargo build (release, tls,tls_boring)"
  $CARGO build --release --bin webserver --offline --features tls,tls_boring 2>&1 | tail -3
fi

# ── 生成配置（忠实于 config-test.toml，含 address_v6）──
$PY scripts/accept-verify-genconf.py >/dev/null || exit 2
# 另生成一份去掉 address_v6 的副本：绕开「双栈 [::] 绑定失败连带掐掉 h3 端点」这个
# 环境/缺陷，用于真正验证 HTTP/3 协议面（见报告 verify-wave3）。
sed '/address_v6 = "::"/d' "$SCRATCH/conf/config-verify.toml" > "$SCRATCH/conf/config-verify-nov6.toml"

# ── 起上游 ──
pkill -f accept-verify-upstream.py 2>/dev/null || true
sleep 0.3
nohup $PY scripts/accept-verify-upstream.py 23099 >"$SCRATCH/logs/upstream.log" 2>&1 &
echo $! > "$SCRATCH/upstream.pid"
sleep 0.5

# ── PASS 1：忠实配置（含 address_v6）→ 主套件（复现双栈/h3 缺陷）──
sh scripts/accept-verify-stop.sh >/dev/null 2>&1
sh scripts/accept-verify-start.sh || { echo "START FAILED"; tail -30 "$SCRATCH/logs/webserver.log"; exit 2; }
sleep 1
echo; echo "########## PASS1: HTTP/1.x + H2 + 静态 + 应用 + Admin + DNS（config-test 忠实档）##########"
$PY scripts/accept-verify.py --json "$SCRATCH/accept-results.json"
RC1=$?

# ── PASS 2：去 address_v6 档 → HTTP/3 / DoT / DoH ──
ACCEPT_CFG="$SCRATCH/conf/config-verify-nov6.toml" sh scripts/accept-verify-start.sh >/dev/null 2>&1
sleep 1.5
echo; echo "########## PASS2: HTTP/3 + DoT + DoH（去 address_v6 以启用 QUIC 端点）##########"
$PY scripts/accept-verify-h3.py --json "$SCRATCH/accept-h3-results.json"
RC2=$?

echo; echo "########## 日志尾部 ##########"
tail -5 "$SCRATCH/logs/webserver.log"

exit $(( RC1 | RC2 ))
