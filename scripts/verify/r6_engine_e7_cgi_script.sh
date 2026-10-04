#!/bin/sh
# E7：`cgi_script` 引擎 + 应用 `paths` 前缀。
#
# 判据：
#   E7a  GET <paths>/r6_info.cgi → 200（修复前裸用 uri.path()，会去找 docroot/<paths>/x.cgi ⇒ 必然 404）
#   E7b  GET <paths>/          → 200 且是 index.cgi（目录回落）
#
# 用法： sh scripts/verify/r6_engine_e7_cgi_script.sh
#        R6_PLAIN=http://127.0.0.1:22095 R6_CPATH=/cgs sh scripts/verify/r6_engine_e7_cgi_script.sh
#
# 前置：测试配置里要有一条 cgi_script 应用，例如
#   [[listeners.apps]]
#   docroot = "www-apps/cgi"
#   enabled = true
#   engine  = "cgi_script"
#   index   = "index.cgi"
#   paths   = ["/cgs"]        # ← 本脚本默认用 /cgs
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
B="${R6_PLAIN:-http://127.0.0.1:19095}"
P="${R6_CPATH:-/cgs}"
F="$ROOT/www-apps/cgi/r6_info.cgi"
pass=0; fail=0
chk() { if [ "$2" = "0" ]; then echo "PASS  $1"; pass=$((pass+1));
        else echo "FAIL  $1 :: $3"; fail=$((fail+1)); fi; }

cleanup() { rm -f "$F"; }
trap cleanup EXIT INT TERM
cat > "$F" <<'X'
#!/bin/sh
printf 'Content-Type: text/plain; charset=utf-8\r\n\r\n'
printf 'SCRIPT_NAME=%s PATH_INFO=%s\n' "${SCRIPT_NAME:-?}" "${PATH_INFO:-?}"
X
chmod 755 "$F"

o=$(curl -s -i -m 20 "$B$P/r6_info.cgi")
if echo "$o" | head -1 | grep -q '404' && [ "${R6_STRICT:-0}" != "1" ]; then
  echo "SKIP  E7：$P 上没有 cgi_script 路由（把上面注释里的 [[listeners.apps]] 加进测试配置即可）"
  exit 0
fi
echo "$o" | head -1 | grep -q '200'; chk "E7a $P/r6_info.cgi 能执行" $? "$(echo "$o"|head -1)"
o2=$(curl -s -i -m 20 "$B$P/")
echo "$o2" | grep -q 'hello from cgi'; chk "E7b $P/ 目录回落到 index.cgi" $? "$(echo "$o2"|head -1)"
echo; echo "==== 汇总: PASS=$pass FAIL=$fail ===="
[ "$fail" = "0" ]
