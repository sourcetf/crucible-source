#!/bin/sh
# accept-verify.sh — 工号 1009 / agent-verify3b 黑盒验收一键跑（wave-6）。
#   sh scripts/accept-verify.sh            # 全量：构建 + 起实例 + 上游 + 跑 HTTP/H2/H3/DNS + 扩展 + 汇总
#   sh scripts/accept-verify.sh --no-build # 跳过 cargo build（用已有二进制）
# 端口块 28000+；DNS 状态根独立；不碰别人的端口/进程。
set -u
REPO=/home/dev123/crucible-git
SCRATCH=/home/dev123/scratch-verify3b
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
# 上传 RCE 闸门：app docroot 下的运行期文件（PUT 覆盖这些 = RCE/凭据注入）
mkdir -p "$SCRATCH/www-up/cga/deps/bin"
printf '#!/bin/sh\necho cga\n' > "$SCRATCH/www-up/cga/init.sh"
chmod +x "$SCRATCH/www-up/cga/init.sh"
printf 'DB_PASSWORD=cga-secret\n' > "$SCRATCH/www-up/cga/.env"
printf '#!/bin/sh\necho sidecar\n' > "$SCRATCH/www-up/cga/deps/bin/index"
chmod +x "$SCRATCH/www-up/cga/deps/bin/index"
printf '#!/bin/sh\necho cga-index\n' > "$SCRATCH/www-up/cga/index.cgi"
chmod +x "$SCRATCH/www-up/cga/index.cgi"
ln -sfn cga "$SCRATCH/www-up/link"
# per-child .env：a=带 .env 慢(2s) b=无 .env 快 c=无 .env 慢(3s) d=带 .env 快 s=cgi_script 带 .env
for d in a b c d s; do mkdir -p "$SCRATCH/env-www/$d/deps"; done
printf 'WINDOWMARK=from-app-A\nSECRET_A=a-only-secret\n' > "$SCRATCH/env-www/a/.env"
printf 'WINDOWMARK=from-app-D\nSECRET_D=d-only-secret\n' > "$SCRATCH/env-www/d/.env"
printf 'WINDOWMARK=from-app-S\nSECRET_S=s-only-secret\n' > "$SCRATCH/env-www/s/.env"
cat > "$SCRATCH/env-www/a/index.cgi" <<'CGI'
#!/bin/sh
sleep "${SLEEP:-2}"
printf 'Content-Type: text/plain\r\n\r\n'
printf 'WINDOWMARK=%s SECRET_A=%s SECRET_D=%s\n' "${WINDOWMARK-<unset>}" "${SECRET_A-<unset>}" "${SECRET_D-<unset>}"
CGI
cat > "$SCRATCH/env-www/b/index.cgi" <<'CGI'
#!/bin/sh
printf 'Content-Type: text/plain\r\n\r\n'
printf 'WINDOWMARK=%s SECRET_A=%s\n' "${WINDOWMARK-<unset>}" "${SECRET_A-<unset>}"
CGI
cat > "$SCRATCH/env-www/c/index.cgi" <<'CGI'
#!/bin/sh
sleep "${SLEEP:-3}"
printf 'Content-Type: text/plain\r\n\r\n'
printf 'WINDOWMARK=%s\n' "${WINDOWMARK-<unset>}"
CGI
cat > "$SCRATCH/env-www/d/index.cgi" <<'CGI'
#!/bin/sh
printf 'Content-Type: text/plain\r\n\r\n'
printf 'WINDOWMARK=%s SECRET_D=%s SECRET_A=%s\n' "${WINDOWMARK-<unset>}" "${SECRET_D-<unset>}" "${SECRET_A-<unset>}"
CGI
cat > "$SCRATCH/env-www/s/index.cgi" <<'CGI'
#!/bin/sh
printf 'Content-Type: text/plain\r\n\r\n'
printf 'WINDOWMARK=%s SECRET_S=%s SECRET_A=%s\n' "${WINDOWMARK-<unset>}" "${SECRET_S-<unset>}" "${SECRET_A-<unset>}"
CGI
chmod +x "$SCRATCH"/env-www/*/index.cgi
# h3 GOAWAY 用：第二个 docroot（触发热重载的 root 变更）
mkdir -p "$SCRATCH/www-h3dir2/sub"
echo "h3dir2 index" > "$SCRATCH/www-h3dir2/index.html"
# per-site 访问日志独立实例用（同 config 内 root 必须互不相同）
mkdir -p "$SCRATCH/www-alog" "$SCRATCH/www-alog2"
echo "alog" > "$SCRATCH/www-alog/index.html"
echo "alog2" > "$SCRATCH/www-alog2/index.html"
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
  $CARGO build --release --bin webserver --offline --features tls,tls_boring >"$SCRATCH/logs/build.log" 2>&1
  RC=$?
  tail -3 "$SCRATCH/logs/build.log"
  if [ $RC -ne 0 ]; then
    echo "BUILD FAILED (rc=$RC) — 不覆盖已 staged 的二进制（绝不用旧产物冒充当前工作树）；日志 $SCRATCH/logs/build.log"
    exit 2
  fi
  cp "$CARGO_TARGET_DIR/release/webserver" "$SCRATCH/bin/webserver"
  echo "==> staged binary: $(md5sum "$SCRATCH/bin/webserver")"
fi

# ── C 引擎：cgi（per-child .env 复核要求用当前源码产物，不走仓库里可能过期的 .so）──
if [ -f "$REPO/libs/app-engines/cgi/cgi_engine.c" ]; then
  gcc -O2 -fPIC -pthread -Wall -Werror=implicit-function-declaration \
      -I"$REPO/libs/app-engines/include" -I"$REPO/libs/app-engines/common" \
      -shared -fPIC -pthread -o "$SCRATCH/bin/libapp_cgi.so" \
      "$REPO/libs/app-engines/cgi/cgi_engine.c" \
      "$REPO/libs/app-engines/common/appengine_common.c" \
      "$REPO/libs/app-engines/common/appengine_util.c" \
    && echo "==> libapp_cgi.so: $(md5sum "$SCRATCH/bin/libapp_cgi.so")" \
    || { echo "libapp_cgi.so BUILD FAILED"; exit 2; }
fi

# ── 生成配置（忠实于 config-test.toml，含 address_v6）──
$PY scripts/accept-verify-genconf.py >/dev/null || exit 2
# 另生成一份去掉 address_v6 的副本：绕开「双栈 [::] 绑定失败连带掐掉 h3 端点」这个
# 环境/缺陷，用于真正验证 HTTP/3 协议面（见报告 verify-wave3）。
sed '/address_v6 = "::"/d' "$SCRATCH/conf/config-verify.toml" > "$SCRATCH/conf/config-verify-nov6.toml"

# ── 起上游（明文 28099 + TLS 28100）──
# 只杀**本端口**的上游：共享机上别的 agent 可能跑同名脚本（照抄的套件），
# 宽泛的 `pkill -f accept-verify-upstream.py` 会互相误杀（实测发生）。
pkill -f "accept-verify-upstream.py 28099" 2>/dev/null || true
sleep 0.3
nohup $PY scripts/accept-verify-upstream.py 28099 >"$SCRATCH/logs/upstream.log" 2>&1 &
echo $! > "$SCRATCH/upstream.pid"
sleep 0.5

ensure_upstream() {
  if ! curl -s -o /dev/null --max-time 3 "http://127.0.0.1:28099/proxy" 2>/dev/null; then
    echo "WARN: 上游 28099 不在（被别的 agent 的 pkill 误杀？）→ 重启"
    nohup $PY scripts/accept-verify-upstream.py 28099 >>"$SCRATCH/logs/upstream.log" 2>&1 &
    echo $! > "$SCRATCH/upstream.pid"
    sleep 0.5
  fi
}

# ── PASS 1：忠实配置（含 address_v6）→ 主套件（复现双栈/h3 缺陷）──
sh scripts/accept-verify-stop.sh >/dev/null 2>&1
sh scripts/accept-verify-start.sh || { echo "START FAILED"; tail -30 "$SCRATCH/logs/webserver.log"; exit 2; }
sleep 1

# 共享工作树：别的 agent 的 pkill/stop 脚本可能误杀我们的实例（实测发生过一次 SIGTERM）。
# 每趟开始前探活，死了就重启，绝不让后续趟次跑在死实例上。
ensure_up() {
  ensure_upstream
  if ! curl -s -o /dev/null --max-time 2 "http://127.0.0.1:28081/" 2>/dev/null; then
    echo "WARN: 实例在 $1 前消失（外部 SIGTERM？）→ 重启并用同一配置继续"
    tail -3 "$SCRATCH/logs/webserver.log" | cut -c1-160
    sh scripts/accept-verify-start.sh || { echo "RESTART FAILED"; exit 2; }
    sleep 1
  fi
}

echo; echo "########## PASS1: HTTP/1.x + H2 + 静态 + 应用 + Admin + DNS（config-test 忠实档）##########"
$PY scripts/accept-verify.py --json "$SCRATCH/accept-results.json"
RC1=$?

# ── PASS 1.5：扩展（TLS/h3 面 ip_access、metrics 鉴权、SIGHUP、worker 上界、WS→h2 上游）──
ensure_up "PASS1.5"
echo; echo "########## PASS1.5: 扩展覆盖（TLS/h3 ip_access、页面规则维度、per-site 日志、per-child .env、上传闸门、ACME 入口）##########"
$PY scripts/accept-verify-ext.py --json "$SCRATCH/accept-ext-results.json"
RC3=$?

# ── PASS 1.6：h3 GOAWAY（配置变更 → GOAWAY；在飞请求仍拿响应）──
ensure_up "PASS1.6"
echo; echo "########## PASS1.6: HTTP/3 GOAWAY（配置变更优雅停机 + 在飞请求）##########"
$PY scripts/accept-verify-goaway.py --json "$SCRATCH/accept-goaway-results.json"
RC4=$?

# ── PASS 2：去 address_v6 档 → HTTP/3 / DoT / DoH ──
ACCEPT_CFG="$SCRATCH/conf/config-verify-nov6.toml" sh scripts/accept-verify-start.sh >/dev/null 2>&1
sleep 1.5
echo; echo "########## PASS2: HTTP/3 + DoT + DoH（去 address_v6 以启用 QUIC 端点）##########"
$PY scripts/accept-verify-h3.py --json "$SCRATCH/accept-h3-results.json"
RC2=$?

echo; echo "########## 日志尾部 ##########"
tail -5 "$SCRATCH/logs/webserver.log"

exit $(( RC1 | RC2 | RC3 | RC4 ))
