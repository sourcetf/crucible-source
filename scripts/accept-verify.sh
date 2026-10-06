#!/bin/sh
# accept-verify.sh — 工号 1009 / agent-verify2 黑盒验收一键跑（wave-5）。
#   sh scripts/accept-verify.sh            # 全量：构建 + 起实例 + 上游 + 跑 HTTP/H2/H3/DNS + 扩展 + 汇总
#   sh scripts/accept-verify.sh --no-build # 跳过 cargo build（用已有二进制）
# 端口块 26000+；DNS 状态根独立；不碰别人的端口/进程。
set -u
REPO=/home/dev123/crucible-git
SCRATCH=/home/dev123/scratch-verify2
PY=python3

cd "$REPO" || exit 2
mkdir -p "$SCRATCH"/{tmp,logs,conf,state-dns,bin}

# ── 准备测试 docroot ──
mkdir -p "$SCRATCH/www-adv/new" "$SCRATCH/www-adv/old" "$SCRATCH/www-rate" \
         "$SCRATCH/www-auth" "$SCRATCH/www-ip" "$SCRATCH/www-up/sub" "$SCRATCH/www-up/php" \
         "$SCRATCH/www-up/listing/sub" "$SCRATCH/outside" "$SCRATCH/www-adv/symout" \
         "$SCRATCH/www-adv/symin" "$SCRATCH/www-tlsip" "$SCRATCH/www-h3ip" \
         "$SCRATCH/www-h3dir/sub"
echo "adv index" > "$SCRATCH/www-adv/index.html"
echo "new content" > "$SCRATCH/www-adv/new/index.html"
echo "rate ok" > "$SCRATCH/www-rate/index.html"
echo "auth ok" > "$SCRATCH/www-auth/index.html"
echo "ip ok" > "$SCRATCH/www-ip/index.html"
echo "tlsip ok" > "$SCRATCH/www-tlsip/index.html"
echo "h3ip ok" > "$SCRATCH/www-h3ip/index.html"
echo "h3dir index" > "$SCRATCH/www-h3dir/index.html"
echo "h3dir sub" > "$SCRATCH/www-h3dir/sub/inside.txt"
echo "up index" > "$SCRATCH/www-up/index.html"
echo "sub" > "$SCRATCH/www-up/sub/inside.txt"
echo "<?php echo 'up';" > "$SCRATCH/www-up/php/index.php"
echo "inner" > "$SCRATCH/www-up/listing/sub/x.txt"
# ETag/inode：一个用于原子替换的文件
echo "etag-body-1" > "$SCRATCH/www-adv/etag.txt"
# 符号链接索引绕过：symout/index.html -> docroot 外；symin/index.html -> docroot 内
echo "OUTSIDE-SECRET" > "$SCRATCH/outside/secret.html"
echo "INSIDE-REAL" > "$SCRATCH/www-adv/real.html"
ln -sf "$SCRATCH/outside/secret.html" "$SCRATCH/www-adv/symout/index.html"
ln -sf ../real.html "$SCRATCH/www-adv/symin/index.html"
# 多段 Range 用文件（2000 字节 = 1000×'A' + 1000×'B'；用 >128 字节间隔强制 multipart）
python3 -c "open('$SCRATCH/www-adv/range.txt','wb').write(b'A'*1000+b'B'*1000)"

# ── 构建（可选）──
if [ "${1:-}" != "--no-build" ]; then
  . /home/dev123/bin/buildenv.sh
  export CARGO_BUILD_JOBS=8
  echo "==> cargo build (release, tls,tls_boring) into $CARGO_TARGET_DIR"
  $CARGO build --release --bin webserver --offline --features tls,tls_boring 2>&1 | tail -3
  cp "$CARGO_TARGET_DIR/release/webserver" "$SCRATCH/bin/webserver"
  echo "==> staged binary: $(md5sum "$SCRATCH/bin/webserver")"
fi

# ── 生成配置（忠实于 config-test.toml，含 address_v6）──
$PY scripts/accept-verify-genconf.py >/dev/null || exit 2
# 另生成一份去掉 address_v6 的副本：绕开「双栈 [::] 绑定失败连带掐掉 h3 端点」这个
# 环境/缺陷，用于真正验证 HTTP/3 协议面（见报告 verify-wave3）。
sed '/address_v6 = "::"/d' "$SCRATCH/conf/config-verify.toml" > "$SCRATCH/conf/config-verify-nov6.toml"

# ── 起上游（明文 26099 + TLS 26100）──
pkill -f accept-verify-upstream.py 2>/dev/null || true
sleep 0.3
nohup $PY scripts/accept-verify-upstream.py 26099 >"$SCRATCH/logs/upstream.log" 2>&1 &
echo $! > "$SCRATCH/upstream.pid"
sleep 0.5

# ── PASS 1：忠实配置（含 address_v6）→ 主套件（复现双栈/h3 缺陷）──
sh scripts/accept-verify-stop.sh >/dev/null 2>&1
sh scripts/accept-verify-start.sh || { echo "START FAILED"; tail -30 "$SCRATCH/logs/webserver.log"; exit 2; }
sleep 1
echo; echo "########## PASS1: HTTP/1.x + H2 + 静态 + 应用 + Admin + DNS（config-test 忠实档）##########"
$PY scripts/accept-verify.py --json "$SCRATCH/accept-results.json"
RC1=$?

# ── PASS 1.5：扩展（TLS/h3 面 ip_access、metrics 鉴权、SIGHUP、worker 上界、WS→h2 上游）──
echo; echo "########## PASS1.5: 扩展覆盖（TLS/h3 ip_access、metrics、SIGHUP、worker cap、WS→h2）##########"
$PY scripts/accept-verify-ext.py --json "$SCRATCH/accept-ext-results.json"
RC3=$?

# ── PASS 2：去 address_v6 档 → HTTP/3 / DoT / DoH ──
ACCEPT_CFG="$SCRATCH/conf/config-verify-nov6.toml" sh scripts/accept-verify-start.sh >/dev/null 2>&1
sleep 1.5
echo; echo "########## PASS2: HTTP/3 + DoT + DoH（去 address_v6 以启用 QUIC 端点）##########"
$PY scripts/accept-verify-h3.py --json "$SCRATCH/accept-h3-results.json"
RC2=$?

echo; echo "########## 日志尾部 ##########"
tail -5 "$SCRATCH/logs/webserver.log"

exit $(( RC1 | RC2 | RC3 ))
