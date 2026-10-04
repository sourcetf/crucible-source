#!/bin/sh
# E4（pyembed 面）：wsgi / asgi 应用抛异常时，客户端只应拿到**固定文本**，
# 不得回显 traceback 与 `script=/绝对路径`；且**必须**是 500（不是 200 也不是静默空响应）。
#
# 判据：
#   W-a/W-b/W-c  wsgi：body 无 path/traceback、body 是 `wsgi: application error`、状态 500
#   A-a/A-b/A-c  asgi：同上（`asgi: application error`）
#   回归         wsgi / asgi 正常请求仍 200（防「改过头」）
#
# 用法： sh scripts/verify/r6_wsgi_asgi_500.sh
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
B="${R6_PLAIN:-http://127.0.0.1:19095}"
APPS="$ROOT/www-apps"
pass=0; fail=0
chk() { if [ "$2" = "0" ]; then echo "PASS  $1"; pass=$((pass+1));
        else echo "FAIL  $1 :: $3"; fail=$((fail+1)); fi; }
cleanup() { rm -f "$APPS/wsgi/r6_err.py" "$APPS/asgi/r6_err.py"; }
trap cleanup EXIT INT TERM

cat > "$APPS/wsgi/r6_err.py" <<'X'
def application(environ, start_response):
    start_response("200 OK", [("Content-Type", "text/plain")])
    raise RuntimeError("r6 wsgi boom at /crucible/www-apps/wsgi/r6_err.py")
app = application
X
cat > "$APPS/asgi/r6_err.py" <<'X'
async def app(scope, receive, send):
    raise RuntimeError("r6 asgi boom at /crucible/www-apps/asgi/r6_err.py")
X

o=$(curl -s -i -m 25 "$B/wsgi/r6_err.py")
echo "$o" | grep -qE '/crucible|Traceback|RuntimeError'; [ $? -ne 0 ]; chk "W-a body 无 path/traceback" $? "$(echo "$o"|tail -1)"
echo "$o" | grep -q 'application error'; chk "W-b body 为固定文本" $? "$(echo "$o"|tail -1)"
echo "$o" | head -1 | grep -q '500'; chk "W-c 状态 500" $? "$(echo "$o"|head -1)"

o=$(curl -s -i -m 25 "$B/asgi/r6_err.py")
echo "$o" | grep -qE '/crucible|Traceback|RuntimeError'; [ $? -ne 0 ]; chk "A-a body 无 path/traceback" $? "$(echo "$o"|tail -1)"
echo "$o" | grep -q 'application error'; chk "A-b body 为固定文本" $? "$(echo "$o"|tail -1)"
echo "$o" | head -1 | grep -q '500'; chk "A-c 状态 500" $? "$(echo "$o"|head -1)"

curl -s -m 20 "$B/wsgi/" | grep -q 'hello from wsgi'; chk "回归 wsgi 正常" $? ""
curl -s -m 20 "$B/asgi/" | grep -q 'hello from asgi'; chk "回归 asgi 正常" $? ""
echo; echo "==== 汇总: PASS=$pass FAIL=$fail ===="
[ "$fail" = "0" ]
