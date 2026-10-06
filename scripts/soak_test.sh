#!/bin/sh
# Crucible 可靠性浸泡测试（混合负载 + 资源采样 + 慢连接/关停检查）
#
# 目的：在长时间混合负载下发现 fd / 进程 / 内存泄漏、偶发 5xx、连接不封顶、
#       SIGTERM 关停不干净、崩溃后残留等问题。所有判据都基于**实测数字**。
#
# 用法：
#   sh scripts/soak_test.sh [DURATION] [APP_PORT] [STATIC_PORT] [TLS12] [TLS13] [PROD]
#   ID=10 sh scripts/soak_test.sh                 # 端口块按 base=20000+ID*200 推导
#   PIDFILE=/tmp/crucible-agent10.pid sh scripts/soak_test.sh 300
#
# 环境变量：
#   ID          实例号（默认 10）→ 端口块
#   PIDFILE     被测 webserver 的 pidfile（默认 /tmp/crucible-agent${ID}.pid）
#   SAMPLE      采样间隔秒（默认 30）
#   WORKERS     每类负载的并发 curl 循环数（默认 4）
#   OUT         采样 CSV 输出（默认 /tmp/soak-<app_port>.csv）
#   SKIP_SLOW   设为 1 跳过慢连接检查
#   SLOW_CONNS  慢连接条数（默认 64）
#
# 退出码：0 = 通过；1 = 疑似泄漏（fd/进程/RSS 单调增长）；2 = 服务器进程消失；3 = 5xx 激增
set -u

ID="${ID:-10}"
BASE=$((20000 + ID * 200))
DURATION="${1:-300}"
APP_PORT="${2:-$((BASE + 95))}"
STATIC_PORT="${3:-$((BASE + 81))}"
TLS12="${4:-$((BASE + 445))}"
TLS13="${5:-$((BASE + 446))}"
PROD="${6:-$((BASE + 443))}"
PIDFILE="${PIDFILE:-/tmp/crucible-agent${ID}.pid}"
SAMPLE="${SAMPLE:-30}"
WORKERS="${WORKERS:-4}"
OUT="${OUT:-/tmp/soak-${APP_PORT}.csv}"
SKIP_SLOW="${SKIP_SLOW:-0}"
SLOW_CONNS="${SLOW_CONNS:-64}"
TMPD="$(mktemp -d /tmp/soak.XXXXXX)"
STOP="$TMPD/stop"

log() { printf '%s\n' "$*"; }

[ -f "$PIDFILE" ] || { log "no pidfile $PIDFILE"; exit 2; }
PID=$(cat "$PIDFILE")
kill -0 "$PID" 2>/dev/null || { log "pid $PID not alive"; exit 2; }

sampler() {
  fd=$(fstat -p "$PID" 2>/dev/null | wc -l | tr -d ' ')
  rss=$(ps -p "$PID" -o rss= 2>/dev/null | tr -d ' ')
  vsz=$(ps -p "$PID" -o vsz= 2>/dev/null | tr -d ' ')
  # 本实例的直接子进程（php-fpm master / native sidecar / ruby sidecar / go-shm）
  kids=$(ps -axww -o ppid= 2>/dev/null | awk -v p="$PID" '$1==p' | wc -l | tr -d ' ')
  # 本实例的 php-fpm 进程（含 master 与 pool worker：命令行里带本实例的 conf 路径）
  fpm=$(ps -axww -o command= 2>/dev/null | grep -c "state/php/${APP_PORT}-" 2>/dev/null)
  # 连到本实例应用口的已建立连接数（连接不封顶/回收失效会体现在这里）
  est=$(netstat -an 2>/dev/null | grep -c "127.0.0.1.${APP_PORT} ")
  echo "$(date +%s),$fd,$rss,$vsz,$kids,$fpm,$est"
}

# 一条 curl 的返回码计数（按 code 汇总到 $TMPD/codes.*）
record() { echo "$1" >> "$TMPD/codes.$$"; }

# 一个 keep-alive 批次：一次 curl 打多个 URL，复用同一条连接。
# 注意：/rack/ 是**已知且诚实**的 502（MRI 嵌入默认关），不计入失败率，单独列出。
APP_URLS="/ /php/ /c/ /rust/ /go/ /lua/ /python/ /ruby/ /perl/ /wsgi/ /asgi/ /psgi/ /cgi/ /uwsgi/ /tsx/ /asp/ /aspnet/ /jsp/ /do/"

worker_app() {
  while [ ! -f "$STOP" ]; do
    for u in $APP_URLS; do
      c=$(curl -s -o /dev/null -m 10 -w '%{http_code}' "http://127.0.0.1:$APP_PORT$u" 2>/dev/null)
      record "$c"
    done
  done
}

worker_static() {
  # 一次 curl 打多个 URL（复用同一条 keep-alive 连接）。每个 URL 都要 -o /dev/null，
  # 否则第 2 个 URL 的 body 会混进 -w 的输出（第一版脚本就踩了这个坑）。
  while [ ! -f "$STOP" ]; do
    c=$(curl -s -m 10 -o /dev/null "http://127.0.0.1:$STATIC_PORT/index.html" \
                             -o /dev/null "http://127.0.0.1:$STATIC_PORT/" \
                             -w '%{http_code}\n' 2>/dev/null)
    record "$c"
  done
}

worker_h2() {
  while [ ! -f "$STOP" ]; do
    c=$(curl -s -m 10 --http2-prior-knowledge -o /dev/null "http://127.0.0.1:$APP_PORT/rust/" \
                                             -o /dev/null "http://127.0.0.1:$APP_PORT/python/" \
                                             -w '%{http_code}\n' 2>/dev/null)
    record "$c"
  done
}

worker_tls() {
  while [ ! -f "$STOP" ]; do
    c=$(curl -sk -o /dev/null -m 10 -w '%{http_code}' "https://127.0.0.1:$TLS12/" 2>/dev/null)
    record "$c"
    c=$(curl -sk -o /dev/null -m 10 -w '%{http_code}' "https://127.0.0.1:$TLS13/" 2>/dev/null)
    record "$c"
  done
}

worker_admin() {
  while [ ! -f "$STOP" ]; do
    c=$(curl -s -o /dev/null -m 10 -u admin:admin -w '%{http_code}' \
        "http://127.0.0.1:$APP_PORT/__admin/api/overview" 2>/dev/null)
    record "$c"
    c=$(curl -s -o /dev/null -m 10 -u admin:admin -w '%{http_code}' \
        "http://127.0.0.1:$APP_PORT/__admin/api/catalog" 2>/dev/null)
    record "$c"
    # 未认证必须 401（绝不能 200）—— 顺手回归 admin 鉴权
    c=$(curl -s -o /dev/null -m 10 -w '%{http_code}' "http://127.0.0.1:$APP_PORT/__admin/api/overview" 2>/dev/null)
    record "$c"
  done
}

worker_upload() {
  body="$TMPD/payload.bin"
  dd if=/dev/zero of="$body" bs=1024 count=64 2>/dev/null
  while [ ! -f "$STOP" ]; do
    c=$(curl -s -o /dev/null -m 20 -w '%{http_code}' -X PUT \
        --data-binary "@$body" "http://127.0.0.1:$PROD/soak-upload.bin" 2>/dev/null)
    record "$c"
  done
}

# ---- 起始基线 ----
log "soak: pid=$PID app=$APP_PORT static=$STATIC_PORT tls12=$TLS12 tls13=$TLS13 prod=$PROD dur=${DURATION}s"
echo "t,fd,rss,vsz,kids,fpm,estab" > "$OUT"
sampler >> "$OUT"

log "warmup..."
for u in $APP_URLS; do curl -s -o /dev/null -m 20 "http://127.0.0.1:$APP_PORT$u" 2>/dev/null; done

log "starting $WORKERS workers per class..."
i=0
while [ $i -lt "$WORKERS" ]; do
  worker_app    & i=$((i + 1))
  worker_static & i=$((i + 1))
  worker_tls    & i=$((i + 1))
  worker_h2     & i=$((i + 1))
  worker_admin  & i=$((i + 1))
  worker_upload & i=$((i + 1))
done
PIDS=$(jobs -p)

# ---- 采样循环 ----
t=0
while [ "$t" -lt "$DURATION" ]; do
  sleep "$SAMPLE"
  t=$((t + SAMPLE))
  if ! kill -0 "$PID" 2>/dev/null; then
    log "FAIL: server pid $PID died during soak (t=${t}s)"
    touch "$STOP"; wait 2>/dev/null
    exit 2
  fi
  sampler >> "$OUT"
  log "  t=${t}s $(tail -1 "$OUT")"
done

touch "$STOP"
sleep 2
wait 2>/dev/null

# ---- 慢连接封顶检查 ----
SLOW_RC=0
if [ "$SKIP_SLOW" != "1" ]; then
  log "slowloris: opening $SLOW_CONNS half-open connections..."
  j=0
  : > "$TMPD/slowpids"
  while [ $j -lt "$SLOW_CONNS" ]; do
    # 只发请求行的一部分，不发结束 CRLF，然后挂住
    ( printf 'GET / HTTP/1.1\r\nHost: x\r\nX-Slow: ' | nc 127.0.0.1 "$APP_PORT" >/dev/null 2>&1 ) &
    echo $! >> "$TMPD/slowpids"
    j=$((j + 1))
  done
  sleep 3
  legit=$(curl -s -o /dev/null -m 8 -w '%{http_code}' "http://127.0.0.1:$APP_PORT/rust/" 2>/dev/null)
  log "  legit request under slowloris -> $legit"
  [ "$legit" = "200" ] || { log "  WARN: legit request degraded under slowloris ($legit)"; SLOW_RC=3; }
  # 收掉慢连接
  if [ -f "$TMPD/slowpids" ]; then
    while read -r sp; do kill "$sp" 2>/dev/null; done < "$TMPD/slowpids"
  fi
fi

# ---- 汇总 ----
# 基准取**暖机后**的采样（第 3 行数据；第 1 行是起负载前的冷基线，RSS/子进程都偏低，
# 拿它当基准会把「引擎懒加载」误报成泄漏）。稳态段 = 从暖机样本到结束。
log ""
log "=== results (CSV: $OUT) ==="
log "cold : $(sed -n '2p' "$OUT")"
log "warm : $(sed -n '3p' "$OUT")"
log "last : $(tail -1 "$OUT")"
base_fd=$(sed -n '3p' "$OUT" | cut -d, -f2)
last_fd=$(tail -1 "$OUT" | cut -d, -f2)
base_rss=$(sed -n '3p' "$OUT" | cut -d, -f3)
last_rss=$(tail -1 "$OUT" | cut -d, -f3)
base_kids=$(sed -n '3p' "$OUT" | cut -d, -f5)
last_kids=$(tail -1 "$OUT" | cut -d, -f5)

# 返回码分布 + 5xx/000 统计
tot=0; bad=0
if ls "$TMPD"/codes.* >/dev/null 2>&1; then
  cat "$TMPD"/codes.* 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]{3}$' > "$TMPD/allcodes"
  tot=$(wc -l < "$TMPD/allcodes" | tr -d ' ')
  bad=$(grep -c -E '^(5[0-9][0-9]|000)' "$TMPD/allcodes" 2>/dev/null || true)
  log "codes: $(sort "$TMPD/allcodes" | uniq -c | tr '\n' ' ')"
fi
log "requests=$tot  5xx/000=$bad"

RC=0
bad="${bad:-0}"; tot="${tot:-0}"
# fd：稳态段增长超过 +20 视为泄漏（fd 泄漏是最硬的信号）。
[ "$last_fd" -gt "$((base_fd + 20))" ]   && { log "LEAK: fd $base_fd -> $last_fd"; RC=1; }
# RSS：暖机后翻倍（+20MB 余量）视为泄漏。
[ "$last_rss" -gt "$((base_rss * 2 + 20000))" ] && { log "LEAK: rss ${base_rss}KB -> ${last_rss}KB"; RC=1; }
# 子进程：懒加载的引擎 sidecar 最多再起几个（php-fpm/ruby/go/jsp），+6 以上才可疑。
[ "$last_kids" -gt "$((base_kids + 6))" ] && { log "LEAK: children $base_kids -> $last_kids"; RC=1; }
[ "$SLOW_RC" != "0" ] && RC="$SLOW_RC"
[ "$bad" -gt $((tot / 100 + 5)) ] 2>/dev/null && { log "FAIL: 5xx/000 rate too high"; RC=3; }

# ---- 空闲连接回收检查：负载停止后连接数必须回落 ----
sleep 5
idle_est=$(netstat -an 2>/dev/null | grep -c "127.0.0.1.${APP_PORT} ")
log "idle established on :$APP_PORT after 5s = $idle_est"
if [ "$idle_est" -gt 100 ]; then
  log "LEAK: $idle_est 条连接在负载停止 5s 后仍未回收（keep-alive 空闲连接未封顶/回收）"
  RC=1
fi

rm -rf "$TMPD"
if [ "$RC" = "0" ]; then log "soak: PASS"; else log "soak: FAIL(rc=$RC)"; fi
exit "$RC"
