#!/usr/bin/env bash
# DNS wave-20「A.1 剩余缺口」真机验证：G-05 also-notify / G-06 rotation_days=0 /
# G-09 ns_name+ns_glue / G-23 旧绝对记录名迁移 / G-24 UI 下拉无 SOA /
# G-25 ACME 失败日志可读摘要 / G-07 ACME dns-01（pebble + 本机权威区）。
#
# 一条命令：
#   scripts/dns_gap_verify.sh            # 跑全部阶段
#   scripts/dns_gap_verify.sh g05 g09    # 只跑指定阶段
#
# 端口块（base 35500，避开 24/26/28/29/31/32/33/36/38/40xxx；27xxx 已被
# scratch-ecs 的临时实例占用过）：
#   35553 master named / 35953 rndc / 35595 admin+web
#   35554 slave named  / 35954 slave rndc
#   35700 pebble / 35701 pebble mgmt / 35502 acme-http
# 状态目录：$DNSG_DIR（默认 ~/scratch-dnsgap），每个阶段独立 CRUCIBLE_DNS_STATE_ROOT。
set -u

BASE=${DNSG_BASE:-35500}
DNS=$((BASE + 53))
RNDC=$((BASE + 453))
WEB=$((BASE + 95))
SLAVE=$((BASE + 54))
SLAVE_RNDC=$((BASE + 454))
PEBBLE=$((BASE + 200))
PEBBLE_MGMT=$((BASE + 201))
ACME_HTTP=$((BASE + 2))
WORK=${DNSG_DIR:-$HOME/scratch-dnsgap}
BIN=${DNSG_BIN:-${CARGO_TARGET_DIR:-$HOME/scratch-tls/target}/release/webserver}
AUTH="admin:admin"
PASS=0
FAIL=0
SKIP=0
PIDS=()
STAGES=("$@")

ok() { PASS=$((PASS + 1)); echo "PASS: $1"; }
bad() { FAIL=$((FAIL + 1)); echo "FAIL: $1"; }
skip() { SKIP=$((SKIP + 1)); echo "SKIP: $1"; }
need() { command -v "$1" >/dev/null 2>&1; }
want() {
    local s
    for s in "${STAGES[@]:-}"; do [ "$s" = "$1" ] && return 0; done
    [ ${#STAGES[@]} -eq 0 ] || [ -z "${STAGES[0]:-}" ]
}

cleanup() {
    local p
    for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
    for p in $(pgrep -f "named -c $WORK/.*/etc/named.conf" 2>/dev/null || true); do
        kill "$p" 2>/dev/null || true
    done
    for p in $(pgrep -f "$WORK/slave/named.conf" 2>/dev/null || true); do
        kill "$p" 2>/dev/null || true
    done
    for p in $(pgrep -f "pebble -config $WORK/pebble.json" 2>/dev/null || true); do
        kill "$p" 2>/dev/null || true
    done
    if [ "${DNSG_KEEP:-0}" = "1" ]; then
        echo "== 现场保留：$WORK =="
    fi
}
trap cleanup EXIT INT TERM

port_free() {
    python3 - "$1" <<'PY' >/dev/null 2>&1
import socket,sys
p=int(sys.argv[1])
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
try: s.bind(("127.0.0.1",p)); s.close()
except OSError: raise SystemExit(1)
PY
}

api() { curl -s -m 30 -u "$AUTH" "http://127.0.0.1:$WEB/__admin$1"; }
post() { curl -s -m 60 -u "$AUTH" -H 'Content-Type: application/json' -d "$2" "http://127.0.0.1:$WEB/__admin$1"; }
post_long() { curl -s -m 240 -u "$AUTH" -H 'Content-Type: application/json' -d "${2:-}" "http://127.0.0.1:$WEB/__admin$1"; }
post_code() { # path body -> "HTTP_CODE<TAB>body"
    local out
    out=$(curl -s -m 60 -o "$WORK/.body" -w '%{http_code}' -u "$AUTH" \
        -H 'Content-Type: application/json' -d "$2" "http://127.0.0.1:$WEB/__admin$1")
    printf '%s\t%s' "$out" "$(cat "$WORK/.body" 2>/dev/null)"
}
digq() { dig @127.0.0.1 -p "$DNS" "$@" +time=4 +tries=1; }
digs() { dig @127.0.0.1 -p "$SLAVE" "$@" +time=3 +tries=1; }
# rndc reload 是异步的（命令返回 ≠ zone 已重载）；断言依赖新内容的 dig 必须轮询。
wait_dig() { # $1=期望正则 $2..=dig 参数；超时输出最后一次原始结果
    local pat=$1; shift
    local i out=""
    for i in $(seq 1 40); do
        out=$(digq "$@" 2>/dev/null)
        printf '%s' "$out" | grep -qE -- "$pat" && { printf '%s' "$out"; return 0; }
        sleep 0.25
    done
    printf '%s' "$out"
}
wait_dig_empty() { # $@=dig 参数；等到回答为空（或超时返回最后结果）
    local i out=""
    for i in $(seq 1 40); do
        out=$(digq "$@" 2>/dev/null)
        [ -z "$out" ] && { printf ''; return 0; }
        sleep 0.25
    done
    printf '%s' "$out"
}
expect() {
    if printf '%s' "$2" | grep -qE -- "$3"; then ok "$1"; else bad "$1（got: $(printf '%s' "$2" | head -c 220)）"; fi
}
expect_not() {
    if printf '%s' "$2" | grep -qE -- "$3"; then bad "$1（matched: $3 / got: $(printf '%s' "$2" | head -c 220)）"; else ok "$1"; fi
}
# 空输出断言（`grep '^$'` 对**零行**输入返回 1，不能用来判空）。
expect_empty() {
    if [ -z "$2" ]; then ok "$1"; else bad "$1（got: $(printf '%s' "$2" | head -c 220)）"; fi
}

write_base_config() {
    # $1=state, $2=extra [dns] body
    cat > "$WORK/cfg-$1.toml" <<EOF
[access_log]
enable = false
[admin]
realm = "dnsgap"
path = "/__admin"
[[admin.users]]
username = "admin"
password_hash = "\$argon2id\$v=19\$m=19456,t=2,p=1\$E/RLobwgix2BWMRMT++urA\$yEympjJtiDh0ezwSQsnkbsfYAoSzeDAHYw3EsUMBsj4"
[dns]
enabled = true
listen_addr = "127.0.0.1"
port = $DNS
rndc_port = $RNDC
test_mode = true
recursion_acl = ["127.0.0.1"]
axfr_out_acl = ["127.0.0.1"]
ecs = true
$2
[dns.modes]
root = false
recursive = false
authoritative = true
[[listeners]]
address = "127.0.0.1"
port = $WEB
root = "$WORK/www"
http_versions = ["h1"]
server_name = "crucible.local"
EOF
    mkdir -p "$WORK/www"
    # 每个阶段用**干净**的状态根（否则上一次运行的 key/zone/db 会污染证据）。
    rm -rf "$WORK/$1" "$WORK/$1-home"
    mkdir -p "$WORK/$1"
}

start_server() {
    local st=$1 home=${2:-$WORK/$1-home}
    mkdir -p "$home"
    env CRUCIBLE_DNS_STATE_ROOT="$WORK/$st" HOME="$home" CRUCIBLE_NAMED_USER= \
        "$BIN" --config "$WORK/cfg-$st.toml" > "$WORK/$st/server.log" 2>&1 &
    echo $! > "$WORK/$st/server.pid"
    PIDS+=("$!")
    local i
    for i in $(seq 1 80); do
        if curl -sf -m 1 -u "$AUTH" "http://127.0.0.1:$WEB/__admin/api/dns/status" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.25
    done
    echo "FATAL: server($st) not ready; log:" >&2
    tail -30 "$WORK/$st/server.log" >&2
    return 1
}

stop_server() {
    local st=$1 pid
    pid=$(cat "$WORK/$st/server.pid" 2>/dev/null || true)
    [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
    for p in $(pgrep -f "named -c $WORK/$st/etc/named.conf" 2>/dev/null || true); do
        kill "$p" 2>/dev/null || true
    done
    sleep 0.6
}

# ---------------------------------------------------------------- G-05 also-notify
stage_g05() {
    echo "===== G-05: master zone also-notify → 第二 named 实例收到 NOTIFY ==="
    write_base_config g05 ""
    start_server g05 || { bad "g05 server start"; return 1; }
    post /api/dns/zones "{\"action\":\"add\",\"name\":\"notify.test\",\"kind\":\"master\",\"axfr_acl\":[\"127.0.0.1\"],\"also_notify\":[\"127.0.0.1:$SLAVE\"]}" >/dev/null
    post /api/dns/records '{"zone":"notify.test","name":"www","rtype":"A","ttl":300,"rdata":"192.0.2.10"}' >/dev/null
    sleep 1
    local conf; conf=$(cat "$WORK/g05/etc/named.conf")
    expect "G-05 named.conf also-notify（ip port N）" "$conf" "also-notify \\{ 127\\.0\\.0\\.1 port $SLAVE; \\};"
    expect "G-05 面板/DB 保存 also_notify" "$(api /api/dns/zones)" "\"also_notify\":\\[\"127\\.0\\.0\\.1:$SLAVE\"\\]"
    expect "G-05 非法 also-notify 被拒" "$(post /api/dns/zones "{\"action\":\"add\",\"name\":\"bad.test\",\"also_notify\":[\"10.0.0.0/8\"]}")" '"error"'

    # 第二 named 实例：secondary notify.test，primaries 指向 master。
    # 必须清空旧 slave 状态：上一次运行留下的 zone 文件（BIND 默认 raw 格式）里
    # 已经有 www/www2，会让「初次 AXFR」「NOTIFY 更新」两个等待瞬间通过，掩盖真实失败。
    rm -rf "$WORK/slave"
    mkdir -p "$WORK/slave/zones"
    cat > "$WORK/slave/named.conf" <<EOF
options { directory "$WORK/slave/zones"; listen-on port $SLAVE { 127.0.0.1; }; listen-on-v6 port $SLAVE { none; }; recursion no; allow-transfer { none; }; };
controls { inet 127.0.0.1 port $SLAVE_RNDC allow { 127.0.0.1; } keys { "rndc-key"; }; };
key "rndc-key" { algorithm hmac-sha256; secret "1111111111111111111111111111111111111111111111111111111111111111"; };
zone "notify.test" { type secondary; primaries { 127.0.0.1 port $DNS; }; file "notify.test.zone"; allow-notify { 127.0.0.1; }; };
EOF
    cat > "$WORK/slave/rndc.conf" <<EOF
options { default-server 127.0.0.1; default-port $SLAVE_RNDC; default-key "rndc-key"; };
server 127.0.0.1 { key "rndc-key"; };
key "rndc-key" { algorithm hmac-sha256; secret "1111111111111111111111111111111111111111111111111111111111111111"; };
EOF
    named-checkconf "$WORK/slave/named.conf" || { bad "G-05 slave named.conf"; return 1; }
    named -c "$WORK/slave/named.conf" -g -f > "$WORK/slave/named.log" 2>&1 &
    PIDS+=("$!")
    local i a
    for i in $(seq 1 40); do
        a=$(digs www.notify.test A +short)
        [ "$a" = "192.0.2.10" ] && break
        sleep 0.25
    done
    expect "G-05 slave 初次 AXFR 成功" "$a" '^192\.0\.2\.10$'

    # 主区改动 → NOTIFY → 从区数秒内更新（不靠 SOA refresh：从区 refresh=900s）
    post /api/dns/records '{"zone":"notify.test","name":"www2","rtype":"A","ttl":300,"rdata":"192.0.2.20"}' >/dev/null
    local t0=$SECONDS got="" ser_master ser_slave
    for i in $(seq 1 40); do
        got=$(digs www2.notify.test A +short)
        [ "$got" = "192.0.2.20" ] && break
        sleep 0.25
    done
    expect "G-05 slave 收到 NOTIFY 并更新（<10s）" "$got" '^192\.0\.2\.20$'
    echo "  notify→transfer latency: $((SECONDS - t0))s"
    expect "G-05 slave 日志有 notify/transfer" "$(cat "$WORK/slave/named.log")" 'notify|transfer.*notify\.test|Transferred serial'
    ser_master=$(digq notify.test SOA +short | awk '{print $3}')
    # slave 落盘是异步的；轮询到 serial 追平（最多 5s）
    for i in $(seq 1 20); do
        ser_slave=$(digs notify.test SOA +short | awk '{print $3}')
        [ -n "$ser_slave" ] && [ "$ser_slave" = "$ser_master" ] && break
        sleep 0.25
    done
    [ -n "$ser_slave" ] && [ "$ser_slave" = "$ser_master" ] && ok "G-05 master/slave serial 一致（$ser_master）" \
        || bad "G-05 serial mismatch master=$ser_master slave=$ser_slave"
    stop_server g05
    for p in $(pgrep -f "$WORK/slave/named.conf" 2>/dev/null || true); do kill "$p" 2>/dev/null || true; done
}

# ---------------------------------------------------------------- G-09 ns/glue
stage_g09() {
    echo "===== G-09: 自动 NS/胶水可配置（ns_name / ns_glue，含关闭） ====="
    write_base_config g09 ""
    start_server g09 || { bad "g09 server start"; return 1; }
    local modes='{"enabled":true,"root":false,"recursive":false,"authoritative":true,"ecs":true'
    post /api/dns/zones '{"action":"add","name":"ns.test","kind":"master"}' >/dev/null
    # 1) 自定义相对名 + 自定义 IPv4 胶水
    expect "G-09 保存 ns_name/ns_glue" \
        "$(post /api/dns/modes "$modes,\"ns_name\":\"ns-custom\",\"ns_glue\":\"192.0.2.53\"}")" '"ok":true'
    sleep 1
    local zf; zf=$(ls "$WORK/g09/zones"/ns_test.*.zone 2>/dev/null | head -1)
    local text; text=$(cat "$zf" 2>/dev/null)
    expect "G-09 zone 文件 SOA MNAME=ns-custom.ns.test." "$text" '@ IN SOA ns-custom\.ns\.test\. hostmaster\.ns\.test\.'
    expect "G-09 zone 文件 NS=ns-custom.ns.test." "$text" '@ IN NS ns-custom\.ns\.test\.'
    expect "G-09 zone 文件胶水 192.0.2.53" "$text" 'ns-custom\.ns\.test\. IN A 192\.0\.2\.53'
    expect "G-09 dig NS" "$(wait_dig '^ns-custom\.ns\.test\.$' ns.test NS +short)" '^ns-custom\.ns\.test\.$'
    expect "G-09 dig 胶水 A" "$(wait_dig '^192\.0\.2\.53$' ns-custom.ns.test A +short)" '^192\.0\.2\.53$'
    cp "$zf" "$WORK/evidence/g09-1-custom-relative.zone"
    # 2) 关闭胶水 + **相对** NS：必须保存前拒绝（in-bailiwick NS 无胶水会让 BIND
    #    拒载整区并继续服务旧版本 —— 真机实测过的静默失败）。
    expect "G-09 相对 NS 关闭胶水被拒（fail-closed）" \
        "$(post /api/dns/modes "$modes,\"ns_name\":\"ns-custom\",\"ns_glue\":\"\"}")" \
        'out-of-zone 绝对名|in-bailiwick'
    # 3) 关闭胶水 + out-of-zone 绝对 NS：合法，不生成胶水，区正常加载
    expect "G-09 绝对 NS + 关闭胶水" \
        "$(post /api/dns/modes "$modes,\"ns_name\":\"ns1.example.net.\",\"ns_glue\":\"\"}")" '"ok":true'
    sleep 1
    text=$(cat "$zf")
    expect "G-09 关闭后 NS 仍在" "$text" '@ IN NS ns1\.example\.net\.'
    expect_not "G-09 关闭后无胶水行" "$text" 'example\.net\. IN A'
    expect "G-09 关闭后 dig NS" "$(wait_dig '^ns1\.example\.net\.$' ns.test NS +short)" '^ns1\.example\.net\.$'
    expect "G-09 关闭胶水后区已加载（serial=文件）" "$(rndc -c "$WORK/g09/etc/rndc.conf" zonestatus ns.test | awk '/^serial:/{print $2}')" \
        "^$(awk '/serial/{print $1; exit}' "$zf")$"
    cp "$zf" "$WORK/evidence/g09-2-glue-off-outofzone.zone"
    rndc -c "$WORK/g09/etc/rndc.conf" zonestatus ns.test > "$WORK/evidence/g09-zonestatus.txt" 2>&1
    # 4) 绝对 NS + 自定义胶水（out-of-zone 不写胶水，属正常）
    expect "G-09 绝对 NS 保存" "$(post /api/dns/modes "$modes,\"ns_name\":\"ns1.example.net.\",\"ns_glue\":\"192.0.2.54\"}")" '"ok":true'
    sleep 1
    text=$(cat "$zf")
    expect "G-09 绝对 NS 写入" "$text" '@ IN NS ns1\.example\.net\.'
    expect_not "G-09 out-of-zone 不写胶水" "$text" '192\.0\.2\.54'
    cp "$zf" "$WORK/evidence/g09-3-outofzone-glue.zone"
    # 4) 非法值保存前拒绝
    expect "G-09 非法 ns_glue 被拒" "$(post /api/dns/modes "$modes,\"ns_name\":\"ns1\",\"ns_glue\":\"not-an-ip\"}")" 'bad ns_glue'
    # 恢复默认，供后续阶段使用
    post /api/dns/modes "$modes,\"ns_name\":\"ns1\",\"ns_glue\":\"127.0.0.1\"}" >/dev/null
    stop_server g09
}

# ---------------------------------------------------------------- G-23 legacy names
stage_g23() {
    echo "===== G-23: 旧库绝对记录名一次性迁移 ==="
    write_base_config g23 ""
    start_server g23 || { bad "g23 server start"; return 1; }
    post /api/dns/zones '{"action":"add","name":"legacy.test","kind":"master"}' >/dev/null
    post /api/dns/records '{"zone":"legacy.test","name":"www","rtype":"A","ttl":300,"rdata":"192.0.2.10"}' >/dev/null
    # 直接写库模拟旧版本留下的「绝对名」行（写入路径已归一，只能用 SQL 造）
    python3 - "$WORK/g23/db/dns.sqlite" <<'PY'
import sqlite3,sys
c=sqlite3.connect(sys.argv[1])
c.execute("INSERT INTO records(zone,line,name,rtype,ttl,rdata) VALUES('legacy.test','','hello.legacy.test','A',300,'192.0.2.77')")
c.execute("INSERT INTO records(zone,line,name,rtype,ttl,rdata) VALUES('legacy.test','','www.legacy.test','A',300,'192.0.2.10')")
c.commit()
PY
    post /api/dns/reload '{}' >/dev/null
    local i a
    for i in $(seq 1 20); do
        a=$(digq hello.legacy.test A +short)
        [ "$a" = "192.0.2.77" ] && break
        sleep 0.25
    done
    expect "G-23 迁移后原名单后缀可解析" "$a" '^192\.0\.2\.77$'
    expect_not "G-23 不再有双后缀记录" "$(digq hello.legacy.test.legacy.test A +short)" '192\.0\.2\.77'
    expect "G-23 日志记录迁移" "$(cat "$WORK/g23/server.log")" '迁移旧绝对记录名'
    local names
    names=$(python3 - "$WORK/g23/db/dns.sqlite" <<'PY'
import sqlite3,sys
c=sqlite3.connect(sys.argv[1])
print(",".join(r[0] for r in c.execute("SELECT name FROM records WHERE zone='legacy.test' ORDER BY name")))
PY
)
    expect "G-23 DB 行已改写为 hello" "$names" '(^|,)hello(,|$)'
    expect "G-23 重复旧行被去重（唯一 www）" "$names" '^hello,www$'
    local zf; zf=$(ls "$WORK/g23/zones"/legacy_test.*.zone 2>/dev/null | head -1)
    expect "G-23 zone 文件无双后缀" "$(grep -c 'legacy.test.legacy.test' "$zf" 2>/dev/null)" '^0$'
    cp "$zf" "$WORK/evidence/g23-legacy.zone"
    grep '迁移旧绝对记录名' "$WORK/g23/server.log" > "$WORK/evidence/g23-migration.log" 2>/dev/null
    python3 - "$WORK/g23/db/dns.sqlite" > "$WORK/evidence/g23-records.txt" <<'PY2'
import sqlite3,sys
c=sqlite3.connect(sys.argv[1])
for r in c.execute("SELECT id,name,rtype,rdata FROM records WHERE zone='legacy.test' ORDER BY id"):
    print(r)
PY2
    # 幂等：再 reload 一次不应再报迁移
    post /api/dns/reload '{}' >/dev/null
    expect "G-23 迁移幂等（第二次无迁移日志增量）" \
        "$(grep -c '迁移旧绝对记录名' "$WORK/g23/server.log")" '^[12]$'
    stop_server g23
}

# ---------------------------------------------------------------- G-06 rotation_days=0
stage_g06() {
    echo "===== G-06: rotation_days=0 = 立即轮换一次（KASP lifetime 钳 30d） ====="
    local extra='[dns.dnssec]
enabled = true
algorithm = "ECDSAP256SHA256"
rotation_enabled = true
rotation_days = 30
nsec3 = true
nsec3_iterations = 0
nsec3_optout = false
cds = false'
    write_base_config g06 "$extra"
    start_server g06 || { bad "g06 server start"; return 1; }
    post /api/dns/zones '{"action":"add","name":"signed.test","kind":"master"}' >/dev/null
    post /api/dns/records '{"zone":"signed.test","name":"www","rtype":"A","ttl":300,"rdata":"192.0.2.31"}' >/dev/null
    local i n
    for i in $(seq 1 60); do
        n=$(digq signed.test DNSKEY +noall +answer | wc -l | tr -d ' ')
        [ "$n" -ge 2 ] && break
        sleep 0.5
    done
    expect "G-06 KASP 初始出 key（>=2 DNSKEY）" "$n" '^[2-9]$'
    local keys_before dns_before ser_before
    keys_before=$(ls "$WORK/g06/keys"/Ksigned.test.+*.key 2>/dev/null | wc -l | tr -d ' ')
    dns_before=$(digq signed.test DNSKEY +noall +answer | wc -l | tr -d ' ')
    ser_before=$(digq signed.test SOA +short | awk '{print $3}')
    echo "  before: keys=$keys_before DNSKEY=$dns_before serial=$ser_before"

    # rotation_days=1 仍必须被拒（防 BIND 拒载）
    local pol1='{"action":"policy","dnssec":{"enabled":true,"algorithm":"ECDSAP256SHA256","rotation_enabled":true,"rotation_days":1,"ksk_lifetime_days":null,"keys":[],"nsec3":true,"nsec3_iterations":0,"nsec3_optout":false,"cds":false}}'
    expect "G-06 rotation_days=1 仍被拒" "$(post /api/dns/dnssec "$pol1")" 'rotation_days=1 太小'

    # 查询循环：轮换期间不能有 SERVFAIL/超时
    python3 - "$DNS" "$WORK/g06/qloop.out" <<'PY' &
import socket,sys,time
port=int(sys.argv[1]); out=sys.argv[2]
q=bytes.fromhex('12340100000100000000000003777777067369676e656404746573740000010001')
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(2)
bad=0; n=0; t0=time.time()
while time.time()-t0 < 38:
    try:
        s.sendto(q,('127.0.0.1',port)); m,_=s.recvfrom(65535); n+=1
        if (m[3]&0xf)!=0: bad+=1
    except Exception:
        bad+=1
    time.sleep(0.1)
open(out,'w').write('n=%d bad=%d\n'%(n,bad))
PY
    PIDS+=("$!")
    local pol0='{"action":"policy","dnssec":{"enabled":true,"algorithm":"ECDSAP256SHA256","rotation_enabled":true,"rotation_days":0,"ksk_lifetime_days":null,"keys":[],"nsec3":true,"nsec3_iterations":0,"nsec3_optout":false,"cds":false}}'
    expect "G-06 设置 rotation_days=0 成功" "$(post_long /api/dns/dnssec "$pol0")" '"ok":true'
    expect "G-06 KASP lifetime 钳到 30d（不是 0d）" "$(cat "$WORK/g06/etc/named.conf")" 'zsk lifetime 30d'
    expect_not "G-06 named.conf 无 lifetime 0d" "$(cat "$WORK/g06/etc/named.conf")" 'lifetime 0d'
    local j keys_after dns_after ser_after got=""
    for j in $(seq 1 60); do
        got=$(grep -c 'rotation_days=0 → immediate one-shot' "$WORK/g06/server.log" 2>/dev/null || true)
        [ "${got:-0}" -ge 1 ] && break
        sleep 0.5
    done
    expect "G-06 立即轮换日志" "$got" '^[1-9]'
    for j in $(seq 1 40); do
        dns_after=$(digq signed.test DNSKEY +noall +answer | wc -l | tr -d ' ')
        [ "$dns_after" -gt "$dns_before" ] && break
        sleep 0.5
    done
    keys_after=$(ls "$WORK/g06/keys"/Ksigned.test.+*.key 2>/dev/null | wc -l | tr -d ' ')
    ser_after=$(digq signed.test SOA +short | awk '{print $3}')
    echo "  after:  keys=$keys_after DNSKEY=$dns_after serial=$ser_after"
    [ "$keys_after" -gt "$keys_before" ] && ok "G-06 新 ZSK 出现（keys $keys_before → $keys_after）" \
        || bad "G-06 未生成新 key（$keys_before → $keys_after）"
    [ "$dns_after" -gt "$dns_before" ] && ok "G-06 DNSKEY 双签发布（$dns_before → $dns_after）" \
        || bad "G-06 DNSKEY 数量未增（$dns_before → $dns_after）"
    [ -n "$ser_before" ] && [ -n "$ser_after" ] && [ "$ser_after" -gt "$ser_before" ] \
        && ok "G-06 serial 变化（$ser_before → $ser_after）" \
        || bad "G-06 serial 未变（$ser_before → $ser_after）"
    local rrsig
    rrsig=$(digq nope.signed.test A +dnssec +noall +authority | grep -c 'RRSIG')
    echo "  NXDOMAIN authority RRSIG count=$rrsig（多 ZSK 双签证据）"
    [ "$rrsig" -ge 1 ] && ok "G-06 轮换后仍正常签名（RRSIG=$rrsig）" || bad "G-06 无 RRSIG"
    # one-shot 不重复：再等 8s 不应再生成
    sleep 8
    local keys_settle; keys_settle=$(ls "$WORK/g06/keys"/Ksigned.test.+*.key 2>/dev/null | wc -l | tr -d ' ')
    [ "$keys_settle" = "$keys_after" ] && ok "G-06 哨兵只触发一次（keys 稳定在 $keys_settle）" \
        || bad "G-06 one-shot 重复触发（$keys_after → $keys_settle）"
    # 设回 30 → named.conf 恢复，且"重新武装"
    local pol30='{"action":"policy","dnssec":{"enabled":true,"algorithm":"ECDSAP256SHA256","rotation_enabled":true,"rotation_days":30,"ksk_lifetime_days":null,"keys":[],"nsec3":true,"nsec3_iterations":0,"nsec3_optout":false,"cds":false}}'
    expect "G-06 设回 rotation_days=30" "$(post_long /api/dns/dnssec "$pol30")" '"ok":true'
    expect "G-06 named.conf 恢复 30d" "$(cat "$WORK/g06/etc/named.conf")" 'zsk lifetime 30d'
    local armed; armed=$(python3 - "$WORK/g06/db/dns.sqlite" <<'PY'
import sqlite3,sys
c=sqlite3.connect(sys.argv[1])
r=c.execute("SELECT v FROM meta WHERE k='dnssec_rotate_once_armed'").fetchone()
print(r[0] if r else "")
PY
)
    expect "G-06 设回 30 后哨兵重新武装" "$armed" '^0$'
    # 查询循环跑满 38s 才写结果，等它落盘（否则读到空文件产生假 FAIL）。
    local q
    for q in $(seq 1 100); do [ -s "$WORK/g06/qloop.out" ] && break; sleep 0.5; done
    expect "G-06 轮换期间 0 SERVFAIL/超时" "$(cat "$WORK/g06/qloop.out" 2>/dev/null)" 'bad=0'
    cp "$WORK/g06/qloop.out" "$WORK/evidence/g06-qloop.out" 2>/dev/null || true
    grep -E 'dnssec-policy|ksk lifetime|zsk lifetime' "$WORK/g06/etc/named.conf" > "$WORK/evidence/g06-kasp.txt" 2>/dev/null || true
    stop_server g06
}

# ---------------------------------------------------------------- G-24 UI + backend SOA
stage_g24() {
    echo "===== G-24: 记录类型下拉不含 SOA；后端仍拒绝用户写 SOA（400） ====="
    write_base_config g24 ""
    start_server g24 || { bad "g24 server start"; return 1; }
    post /api/dns/zones '{"action":"add","name":"ui.test","kind":"master"}' >/dev/null
    local res code body
    res=$(post_code /api/dns/records '{"zone":"ui.test","name":"@","rtype":"SOA","ttl":300,"rdata":"ns1.ui.test. host.ui.test. 1 2 3 4 5"}')
    code=${res%%$'\t'*}; body=${res#*$'\t'}
    [ "$code" = "400" ] && ok "G-24 面板/API 保存 SOA → HTTP 400" || bad "G-24 SOA 返回 $code（期望 400）"
    expect "G-24 错误信息说明 SOA 自动生成" "$body" 'SOA 由 DNS 模块自动生成'
    local ui; ui=$(curl -s -u "$AUTH" "http://127.0.0.1:$WEB/__admin/")
    expect_not "G-24 UI 记录类型下拉无 SOA option" "$ui" '<option>SOA</option>'
    expect_not "G-24 UI 表格类型表无 SOA" "$ui" "DNS_RTYPES=\[[^]]*'SOA'"
    stop_server g24
}

# ---------------------------------------------------------------- G-25 ACME HTML log
stage_g25() {
    echo "===== G-25: ACME 失败 stderr 中的 HTML 错误页 → 可读摘要 ==="
    local home="$WORK/g25-home"
    local extra='[dns.acme]
enabled = true
domain = "gap.crucible.test"
email = "admin@example.com"
renew_days = 60
server = "https://127.0.0.1:1/dir"
insecure = true
http_port = '"$ACME_HTTP"'
challenge = "http-01"'
    # 注意顺序：write_base_config 会清空该阶段的 state/home（避免旧运行污染），
    # 假 acme.sh 必须在它**之后**写。
    write_base_config g25 "$extra"
    mkdir -p "$home/.acme.sh"
    cat > "$home/.acme.sh/acme.sh" <<'EOS'
#!/bin/sh
cat >&2 <<'EOF'
<!DOCTYPE html>
<html><head><title>502 Bad Gateway</title></head>
<body><h1>502 Bad Gateway</h1><hr><center>nginx</center></body></html>
[Mon Oct 20] Please add '--debug' or '--log'.
[Mon Oct 20] Error code: 7
[Mon Oct 20] Detail: Fetching https://127.0.0.1:1/dir: Connection refused
EOF
exit 1
EOS
    chmod +x "$home/.acme.sh/acme.sh"
    start_server g25 "$home" || { bad "g25 server start"; return 1; }
    post /api/dns/zones '{"action":"add","name":"crucible.test","kind":"master"}' >/dev/null
    post /api/dns/records '{"zone":"crucible.test","name":"gap","rtype":"A","ttl":300,"rdata":"127.0.0.1"}' >/dev/null
    sleep 1
    local out; out=$(post_long /api/dns/acme/issue '{}')
    expect "G-25 面板错误含可读 Error code" "$out" 'Error code: 7'
    expect "G-25 面板错误含 Detail" "$out" 'Detail: Fetching'
    expect_not "G-25 面板错误不含 HTML 标签" "$out" '<html|<!DOCTYPE|<body>|<h1>'
    local logline; logline=$(grep 'acme.sh --issue 退出失败' "$WORK/g25/server.log" | tail -1)
    expect "G-25 日志保留 error code 行" "$logline" 'Error code: 7'
    expect "G-25 日志保留 detail 行" "$logline" 'Connection refused'
    expect_not "G-25 日志不含 HTML 标签" "$logline" '<html|<!DOCTYPE|<body>|<h1>'
    echo "  panel error: $(printf '%s' "$out" | head -c 300)"
    echo "  log line:    $(printf '%s' "$logline" | head -c 300)"
    stop_server g25
}

# ---------------------------------------------------------------- G-07 dns-01 + pebble
stage_g07() {
    echo "===== G-07: ACME dns-01（pebble + 本机权威区 TXT）首签 + 续期 ====="
    if ! need pebble; then skip "G-07 缺 pebble（~/local/usr/bin/pebble）"; return 0; fi
    if ! need acme.sh; then skip "G-07 缺 acme.sh"; return 0; fi
    local home="$WORK/g07-home"
    local extra='[dns.acme]
enabled = false
domain = "acme.crucible.test"
email = "admin@example.com"
renew_days = 60
server = "https://127.0.0.1:'"$PEBBLE"'/dir"
insecure = true
http_port = '"$ACME_HTTP"'
challenge = "dns-01"'
    # 注意顺序：write_base_config 会清空该阶段的 home（避免旧运行残留），
    # acme.sh 必须在它**之后**复制。
    write_base_config g07 "$extra"
    mkdir -p "$home/.acme.sh"
    cp -L "$(command -v acme.sh)" "$home/.acme.sh/acme.sh"
    chmod +x "$home/.acme.sh/acme.sh"

    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
        -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
        -keyout "$WORK/g07-pebble-key.pem" -out "$WORK/g07-pebble-cert.pem" >/dev/null 2>&1
    cat > "$WORK/pebble.json" <<EOF
{"pebble":{"listenAddress":"127.0.0.1:$PEBBLE","managementListenAddress":"127.0.0.1:$PEBBLE_MGMT",
"certificate":"$WORK/g07-pebble-cert.pem","privateKey":"$WORK/g07-pebble-key.pem",
"httpPort":$ACME_HTTP,"tlsPort":$((ACME_HTTP - 1)),"ocspResponderURL":"",
"externalAccountBindingRequired":false,"certificateValidityPeriod":7776000}}
EOF
    # pebble 的 DNS 解析指向**本模块的 named**（dns-01 的 TXT 在这里）
    PEBBLE_VA_NOSLEEP=1 pebble -config "$WORK/pebble.json" -dnsserver "127.0.0.1:$DNS" -strict=false \
        > "$WORK/pebble.log" 2>&1 &
    PIDS+=("$!")
    sleep 2
    curl -sk "https://127.0.0.1:$PEBBLE_MGMT/roots/0" > "$WORK/g07-pebble-root.pem" || { bad "G-07 pebble root fetch"; return 1; }

    start_server g07 "$home" || { bad "g07 server start"; return 1; }
    post /api/dns/zones '{"action":"add","name":"crucible.test","kind":"master"}' >/dev/null
    post /api/dns/records '{"zone":"crucible.test","name":"acme","rtype":"A","ttl":300,"rdata":"192.0.2.50"}' >/dev/null
    # 通过面板打开 acme（enabled=false 启动 ⇒ 没有后台签发循环，签发完全由面板触发，
    # 便于观察「TXT 在签发窗口内真的写进了权威区」）。
    local cfgj; cfgj=$(api /api/dns/config)
    cfgj=$(printf '%s' "$cfgj" | python3 -c 'import json,sys;d=json.load(sys.stdin);d["acme"]["enabled"]=True;print(json.dumps(d))')
    expect "G-07 面板启用 ACME(dns-01)" "$(post /api/dns/config "$cfgj")" '"ok":true'
    expect "G-07 named.conf 不再需要动态更新策略" "$(grep -c 'update-policy' "$WORK/g07/etc/named.conf")" '^0$'
    expect "G-07 签发前业务记录已可解析" "$(wait_dig '^192\.0\.2\.50$' acme.crucible.test A +short)" '^192\.0\.2\.50$'

    # 挑战记录观察器：签发窗口内每 100ms 查一次 `_acme-challenge.<domain>` TXT。
    ( : > "$WORK/g07/challenge-seen.txt"
      while [ ! -f "$WORK/g07/stop-watch" ]; do
          v=$(digq _acme-challenge.acme.crucible.test TXT +short 2>/dev/null)
          [ -n "$v" ] && printf '%s\n' "$v" >> "$WORK/g07/challenge-seen.txt"
          sleep 0.1
      done ) &
    local watcher=$!
    PIDS+=("$watcher")

    # 签发/续期期间持续查询权威区（dns-01 的 TXT 与业务记录共存）：
    # 20s 内 0 SERVFAIL/超时才算「服务不中断」。
    python3 - "$DNS" "$WORK/g07/qloop.out" <<'PY' &
import socket,sys,time
port=int(sys.argv[1]); out=sys.argv[2]
q=bytes.fromhex('1234010000010000000000000461636d65086372756369626c6504746573740000010001')
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(2)
bad=0; n=0; t0=time.time()
while time.time()-t0 < 20:
    try:
        s.sendto(q,('127.0.0.1',port)); m,_=s.recvfrom(65535); n+=1
        if (m[3]&0xf)!=0 or int.from_bytes(m[6:8],'big')<1: bad+=1
    except Exception:
        bad+=1
    time.sleep(0.1)
open(out,'w').write('n=%d bad=%d\n'%(n,bad))
PY
    PIDS+=("$!")

    local cert="$WORK/g07/acme/acme.crucible.test/fullchain.pem"
    local r; r=$(post_long /api/dns/acme/issue '{}')
    expect "G-07 面板签发（dns-01）成功" "$r" '"ok":true'
    local i
    for i in $(seq 1 20); do [ -s "$cert" ] && break; sleep 0.5; done
    [ -s "$cert" ] && ok "G-07 首签证书落盘" || { bad "G-07 证书未落盘（$(tail -5 "$WORK/g07/server.log")）"; }
    expect "G-07 fullchain=leaf+intermediate" "$(grep -c 'BEGIN CERTIFICATE' "$cert" 2>/dev/null)" '^2$'
    expect "G-07 pebble 记录 Issued certificate" "$(cat "$WORK/pebble.log")" 'Issued certificate'
    local issuer ser1
    issuer=$(openssl x509 -in "$cert" -noout -issuer 2>/dev/null)
    ser1=$(openssl x509 -in "$cert" -noout -serial 2>/dev/null)
    expect "G-07 issuer 是 Pebble" "$issuer" 'Pebble'
    echo "  issued: $ser1 / $issuer"
    expect_empty "G-07 首签后 TXT 挑战记录已清理" "$(digq _acme-challenge.acme.crucible.test TXT +short)"
    expect "G-07 签发窗口内权威区确实出现过挑战 TXT" "$(cat "$WORK/g07/challenge-seen.txt" 2>/dev/null | head -3)" '"[-_A-Za-z0-9]{43}"'
    cp "$WORK/g07/challenge-seen.txt" "$WORK/evidence/g07-challenge-seen.txt" 2>/dev/null || true
    expect "G-07 DB 无残留挑战 TXT" "$(python3 - "$WORK/g07/db/dns.sqlite" <<'PY'
import sqlite3,sys
c=sqlite3.connect(sys.argv[1])
print(c.execute("SELECT COUNT(*) FROM records WHERE rtype='TXT' AND name LIKE '_acme-challenge.%'").fetchone()[0])
PY
)" '^0$'
    expect "G-07 日志走 zone API（非 nsupdate）" "$(cat "$WORK/g07/server.log")" 'dns-01 挑战经模块 zone API'
    expect "G-07 dnsapi hook 命中" "$(cat "$WORK/g07/server.log")" 'dnsapi hook .*dns_crucible\.sh|Found domain API file'
    expect "G-07 worker 实际写入了 TXT（acme.sh 日志）" "$(cat "$home/.acme.sh/acme.sh.log" 2>/dev/null)" 'successfully added|Adding TXT value'

    # 续期：换成 10 天自签（<30d 阈值）+ 删除 acme.sh 缓存 → 面板立即签发
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 10 \
        -subj "/CN=acme.crucible.test" -addext "subjectAltName=DNS:acme.crucible.test" \
        -keyout "$WORK/g07-short-key.pem" -out "$WORK/g07-short.pem" >/dev/null 2>&1
    cp "$WORK/g07-short.pem" "$cert"; cp "$WORK/g07-short-key.pem" "$WORK/g07/acme/acme.crucible.test/privkey.pem"
    rm -rf "$home/.acme.sh/acme.crucible.test_ecc" "$home/.acme.sh/acme.crucible.test"
    : > "$WORK/g07/challenge-seen.txt"
    r=$(post_long /api/dns/acme/issue '{}')
    expect "G-07 续期（dns-01）成功" "$r" '"ok":true'
    local ser2; ser2=$(openssl x509 -in "$cert" -noout -serial 2>/dev/null)
    [ -n "$ser2" ] && [ "$ser1" != "$ser2" ] && ok "G-07 续期替换证书（$ser1 → $ser2）" \
        || bad "G-07 续期未替换证书（$ser1 / $ser2）"
    expect_empty "G-07 续期后 TXT 清理" "$(digq _acme-challenge.acme.crucible.test TXT +short)"
    expect "G-07 续期 issuer 仍是 Pebble" "$(openssl x509 -in "$cert" -noout -issuer 2>/dev/null)" 'Pebble'

    touch "$WORK/g07/stop-watch"
    local q
    for q in $(seq 1 100); do [ -s "$WORK/g07/qloop.out" ] && break; sleep 0.5; done
    expect "G-07 签发/续期期间权威区 0 SERVFAIL/超时" "$(cat "$WORK/g07/qloop.out" 2>/dev/null)" 'bad=0'
    cp "$WORK/g07/qloop.out" "$WORK/evidence/g07-qloop.out" 2>/dev/null || true
    expect "G-07 签发后权威区正常（acme A）" "$(wait_dig '^192\.0\.2\.50$' acme.crucible.test A +short)" '^192\.0\.2\.50$'
    stop_server g07
    for p in $(pgrep -f "pebble -config $WORK/pebble.json" 2>/dev/null || true); do kill "$p" 2>/dev/null || true; done
}

# ---------------------------------------------------------------- main
command -v named >/dev/null 2>&1 || { echo "FATAL: named 不在 PATH（eval \"\$(/home/dev123/bin/aptlocal.sh env)\"）" >&2; exit 2; }
[ -x "$BIN" ] || { echo "FATAL: webserver 二进制不存在：$BIN" >&2; exit 2; }
for p in "$DNS" "$RNDC" "$WEB" "$SLAVE" "$SLAVE_RNDC" "$PEBBLE" "$PEBBLE_MGMT" "$ACME_HTTP"; do
    if ! port_free "$p"; then
        # 只有要用到的阶段才强制要求空闲；仍直接失败，避免端口冲突产生假结果
        echo "FATAL: port $p in use（换 DNSG_BASE）" >&2; exit 2
    fi
done
mkdir -p "$WORK/evidence"
echo "binary: $BIN"; echo "work:   $WORK"; echo "base:   $BASE (dns=$DNS slave=$SLAVE web=$WEB pebble=$PEBBLE)"
want g05 && stage_g05
want g09 && stage_g09
want g23 && stage_g23
want g06 && stage_g06
want g24 && stage_g24
want g25 && stage_g25
want g07 && stage_g07
echo "=================================================================="
echo "DNS gap verification: PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
[ "$FAIL" -eq 0 ]
