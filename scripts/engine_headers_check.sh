#!/bin/sh
# 请求头跨语言回归：临时把 5 个脚本样例换成「回显 X-Request-ID」版本，
# 并发打 120 个唯一 id，校验每个响应回显的是**自己**的 id（串台 = ABI 头块串了
# 请求/缓冲），然后原样还原样例文件。
#
# 用法：BASE=http://127.0.0.1:19095 sh scripts/engine_headers_check.sh
set -e
BASE="${BASE:-http://127.0.0.1:19095}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TMPD="$(mktemp -d /tmp/eng-hdr.XXXXXX)"
trap 'restore' EXIT INT TERM
restored=0
restore() {
  [ "$restored" = 1 ] && return 0
  restored=1
  for f in www-apps/python/index.py www-apps/perl/index.pl www-apps/wsgi/index.py \
           www-apps/asgi/index.py www-apps/psgi/index.psgi; do
    # 备份名必须带**路径**（三个 index.py 用 basename 会互相覆盖，还原时把 A 的内容
    # 写进 B —— 实测把 ASGI 应用写到了 python/wsgi 的 docroot，造成 500/空响应）。
    b="$TMPD/$(echo "$f" | tr '/' '_').bak"
    [ -f "$b" ] && cp -p "$b" "$f"
  done
  echo "[restore] 样例文件已还原"
}

for f in www-apps/python/index.py www-apps/perl/index.pl www-apps/wsgi/index.py \
         www-apps/asgi/index.py www-apps/psgi/index.psgi; do
  cp -p "$f" "$TMPD/$(echo "$f" | tr '/' '_').bak"
done

cat > www-apps/python/index.py <<'PY'
import os
rid = os.environ.get("HTTP_X_REQUEST_ID", "no-id")
print("Content-Type: text/plain")
print("")
print("python-echo id=%s" % rid)
PY

cat > www-apps/perl/index.pl <<'PL'
my $rid = $ENV{HTTP_X_REQUEST_ID} // "no-id";
print "Content-Type: text/plain\r\n\r\n";
print "perl-echo id=$rid\n";
PL

cat > www-apps/wsgi/index.py <<'PY'
def application(environ, start_response):
    rid = environ.get("HTTP_X_REQUEST_ID", "no-id")
    start_response("200 OK", [("Content-Type", "text/plain")])
    return [("wsgi-echo id=%s\n" % rid).encode()]
app = application
PY

cat > www-apps/asgi/index.py <<'PY'
async def app(scope, receive, send):
    hs = {k.decode("latin-1"): v.decode("latin-1") for k, v in scope.get("headers", [])}
    rid = hs.get("x-request-id", "no-id")
    body = ("asgi-echo id=%s\n" % rid).encode()
    await send({"type": "http.response.start", "status": 200,
                "headers": [(b"content-type", b"text/plain")]})
    await send({"type": "http.response.body", "body": body})
application = app
PY

cat > www-apps/psgi/index.psgi <<'PSGI'
my $app = sub {
    my $env = shift;
    my $rid = $env->{HTTP_X_REQUEST_ID} // "no-id";
    return [200, ["Content-Type" => "text/plain"], ["psgi-echo id=$rid\n"]];
};
$app;
PSGI

# mtime 变化 → deps 缓存失效；wsgi/asgi/psgi 走 FFI，python/perl 视构建而定
echo "== headers cross-talk (120 concurrent unique ids per language) =="
BASE="$BASE" python3 - <<'PY'
import concurrent.futures as cf, http.client, os, random, sys

base = os.environ["BASE"]
host = base.split("//", 1)[1].split("/")[0]
hn, _, p = host.partition(":")
port = int(p or 80)
routes = [("/python/", "python-echo id="), ("/perl/", "perl-echo id="),
          ("/wsgi/", "wsgi-echo id="), ("/psgi/", "psgi-echo id="),
          ("/asgi/", "asgi-echo id=")]
N = 120
bad = 0

def one(path, i, tag):
    rid = "%s-%d-%d" % (tag, i, random.randrange(10**9))
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=60)
    try:
        c.request("GET", path, headers={"Host": host, "X-Request-ID": rid})
        r = c.getresponse()
        body = r.read().decode("utf-8", "replace")
        return rid in body and r.status == 200, (r.status, rid, body.strip()[:80])
    finally:
        c.close()

for path, marker in routes:
    tag = marker.split("-")[0]
    fails = []
    with cf.ThreadPoolExecutor(max_workers=24) as ex:
        for ok, info in ex.map(lambda i: one(path, i, tag), range(N)):
            if not ok:
                fails.append(info)
    print("%s %-9s %d concurrent, mismatches=%d" % ("ok " if not fails else "BAD", path, N, len(fails)))
    for f in fails[:3]:
        print("      e.g.", f)
    bad += len(fails)
print("== summary: mismatches=%d ==" % bad)
sys.exit(1 if bad else 0)
PY
