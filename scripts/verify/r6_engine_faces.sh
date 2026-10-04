#!/bin/sh
# 第 6 轮「引擎客户端可见面」判据（E1/E3/E4/E5/E6/E8/P2，E2 可选）。
#
# 判据（前两条是**回归**对照，防「改过头」）：
#   E1a/E1b/E1c  cgi / lua / php 三个引擎仍正常出内容（回归）
#   E3           lua 500：body 为固定文本 `lua: application error`，**不含**服务器绝对路径
#   E4           python 脚本抛异常：**不得** 200（修复前是 200+空 body 的静默失败），
#                且 body 无 traceback / 无 /crucible 路径
#   E5           php 404：body 为 `php: script not found`，**不含** docroot 绝对路径
#   E6           php 能拿到 `.env`（`APP_HELLO=php`）—— 修复前 FastCGI params 恒空、静默拿空值
#   E8           CGI 打两行 `Content-Type:` → 响应只能有**一个** content-type，且后者胜出
#   P2           `.env` 值 ≥2048 字节时，其后的变量**不得**被丢掉
#   E2（可选）   CGI 超时须杀掉**孙进程**（需 R6_SLOW=1，约 35s）
#
# 用法（对 config-test.toml 起的测试实例）：
#   sh scripts/verify/r6_engine_faces.sh
#   R6_PLAIN=http://127.0.0.1:22095 sh scripts/verify/r6_engine_faces.sh
#
# 前置：被请求的实例 docroot 指向本仓库（脚本会自行创建/清理 www-apps 下的 r6_* 夹具）。

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
B="${R6_PLAIN:-http://127.0.0.1:19095}"
APPS="$ROOT/www-apps"
pass=0; fail=0
chk() { if [ "$2" = "0" ]; then echo "PASS  $1"; pass=$((pass+1));
        else echo "FAIL  $1 :: $3"; fail=$((fail+1)); fi; }

cleanup() {
  rm -f "$APPS/cgi/r6_ct.cgi" "$APPS/cgi/r6_env.cgi" "$APPS/cgi/r6_hang.cgi" "$APPS/cgi/.env"
  rm -f "$APPS/lua/r6_err.lua" "$APPS/python/r6_err.py"
}
trap cleanup EXIT INT TERM

# ---- 夹具 ----
mkdir -p "$APPS/cgi" "$APPS/lua" "$APPS/python" 2>/dev/null
cat > "$APPS/cgi/r6_ct.cgi" <<'X'
#!/bin/sh
printf 'Content-Type: text/plain; charset=utf-8\r\n'
printf 'Content-Type: application/json\r\n'
printf '\r\n{"ok":"r6_ct"}\n'
X
cat > "$APPS/cgi/r6_env.cgi" <<'X'
#!/bin/sh
printf 'Content-Type: text/plain; charset=utf-8\r\n\r\n'
printf 'AFTER=[%s] LONGLEN=[%s]\n' "${R6_AFTER:-MISSING}" "${#R6_LONG}"
X
python3 -c "
long_v='a'*2500
open('$APPS/cgi/.env','w').write('R6_LONG=%s\nR6_AFTER=present\n'%long_v)"
printf 'this is not valid lua ((( [\n' > "$APPS/lua/r6_err.lua"
printf 'raise RuntimeError("r6 boom in /crucible/www-apps/python/r6_err.py")\n' > "$APPS/python/r6_err.py"
chmod 755 "$APPS/cgi/r6_ct.cgi" "$APPS/cgi/r6_env.cgi"

echo "=== E1 回归：三个引擎仍正常 ==="
curl -s -m 20 "$B/cgi/"  | grep -q 'hello from cgi';  chk "E1a cgi 正常"  $? ""
curl -s -m 20 "$B/lua/"  | grep -q 'hello from lua';  chk "E1b lua 正常"  $? ""
curl -s -m 20 "$B/php/"  | grep -q 'hello from php';  chk "E1c php 正常"  $? ""

echo "=== E3 lua 500 不回显绝对路径 ==="
o=$(curl -s -i -m 20 "$B/lua/r6_err.lua")
echo "$o" | grep -q '/crucible'; [ $? -ne 0 ]; chk "E3a body 无 /crucible 路径" $? "$(echo "$o"|tail -2)"
echo "$o" | grep -q 'lua: application error'; chk "E3b body 为固定文本" $? "$(echo "$o"|tail -2)"

echo "=== E4 python 抛异常不得静默 200 ==="
o=$(curl -s -i -m 20 "$B/python/r6_err.py")
echo "$o" | head -1 | grep -q '200 OK'; [ $? -ne 0 ]; chk "E4a 不是 200" $? "$(echo "$o"|head -1)"
echo "$o" | grep -qE '/crucible|Traceback'; [ $? -ne 0 ]; chk "E4b body 无 traceback/路径" $? "$(echo "$o"|tail -1)"

echo "=== E5 php 404 不回显 docroot ==="
o=$(curl -s -i -m 20 "$B/php/r6_nope.php")
echo "$o" | grep -q '/crucible'; [ $? -ne 0 ]; chk "E5a body 无 docroot" $? "$(echo "$o"|tail -2)"
echo "$o" | grep -q 'php: script not found'; chk "E5b body 为固定文本" $? "$(echo "$o"|tail -2)"

echo "=== E6 php 拿到 .env ==="
o=$(curl -s -m 20 "$B/php/index.php")
echo "$o" | grep -q 'APP_HELLO=php'; chk "E6 php getenv(APP_HELLO) 有值" $? "$(echo "$o"|tail -1)"

echo "=== E8 Content-Type 去重 ==="
o=$(curl -s -i -m 20 "$B/cgi/r6_ct.cgi")
n=$(echo "$o" | grep -ci '^content-type:')
[ "$n" = "1" ]; chk "E8a 只有一个 content-type (实得 $n)" $? "n=$n"
echo "$o" | grep -qi '^content-type: application/json'; chk "E8b 后者胜出" $? "$(echo "$o"|grep -i '^content-type:')"

echo "=== P2 .env 超长值(2500)不得丢掉其后的变量 ==="
o=$(curl -s -i -m 20 "$B/cgi/r6_env.cgi")
echo "$o" | grep -q 'AFTER=\[present\]'; chk "P2a R6_AFTER 仍在" $? "$(echo "$o"|tail -1)"
echo "$o" | grep -q 'LONGLEN=\[2500\]'; chk "P2b 超长值本身也设上了" $? "$(echo "$o"|tail -1)"

if [ "${R6_SLOW:-0}" = "1" ]; then
  echo "=== E2 CGI 超时须杀掉孙进程（约 35s）==="
  cat > "$APPS/cgi/r6_hang.cgi" <<'X'
#!/bin/sh
sleep 311 &
sleep 60
printf 'Content-Type: text/plain\r\n\r\ndone\n'
X
  chmod 755 "$APPS/cgi/r6_hang.cgi"
  before=$(pgrep -f 'sleep 311' | wc -l | tr -d ' ')
  t0=$(date +%s); curl -s -o /dev/null -m 45 "$B/cgi/r6_hang.cgi"; t1=$(date +%s)
  sleep 3
  left=$(pgrep -f 'sleep 311' | wc -l | tr -d ' ')
  echo "耗时=$((t1-t0))s 请求前孙进程=$before 请求后=$left"
  [ "$((left))" = "0" ]; chk "E2 孙进程已被杀（无残留 sleep 311）" $? "left=$left"
else
  echo "SKIP  E2（孙进程）—— 需要约 35s；置 R6_SLOW=1 打开"
fi

echo
echo "==== 汇总: PASS=$pass FAIL=$fail ===="
[ "$fail" = "0" ]
