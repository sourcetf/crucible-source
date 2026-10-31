#!/usr/bin/env bash
# wave-22 DNS 深度审计回归（工号 1009 / agent-dns-audit3）。
#
# 覆盖本波修复/审计的条目（与 dns_verify.sh / dns_gap_verify.sh 不重复）：
#   A 记录校验：NAPTR、TTL 31 位、label/通配符/转义名、CAA 引号、控制字符、
#     导入 $INCLUDE / 未知分区 / 纯 SOA、绝对名与尾点归一、punycode
#   B SOA serial 32 位回绕（0xFFFFFFFF + 1 → 1，named 仍能重载）
#   C KASP：重复角色拒绝、key 删除随分区删除（keys/ + zones/ 清理）
#   D ACL/zone transfer：AXFR ACL、非法 recursion_acl 拒绝、slave refresh 钳制、
#     also-notify、per-zone allow-transfer、IPv6 ACL
#   E DoH：GET/POST、非法 base64、415/413/400（明文口）、CORS、缓存头、ECS 回显、
#     畸形 ECS → FORMERR
#   F 管理 API 并发：同名 CNAME/A 并发只成功一个（不产生 CNAME+other data）
#   G ACME：启动时 enabled=false，面板启用后 http-01 按需起监听并签发（pebble）
#
# 端口块 27400–27499（本 agent 独占）；状态根默认 ~/scratch-dnsaudit3/dnsa3-work。
#   DNSA3_BIN=/path/to/webserver scripts/dns_audit3_verify.sh [stage...]
# 缺 named/pebble/acme.sh 的阶段自动 SKIP。
set -u

WEB=27495
DNS=27453
RNDC=27454
TLS=27443
ACME_HTTP=27458
PEBBLE=27470
PEBBLE_MGMT=27471
WORK=${DNSA3_DIR:-$HOME/scratch-dnsaudit3/dnsa3-work}
BIN=${DNSA3_BIN:-${CARGO_TARGET_DIR:-$HOME/scratch-tls/target}/release/webserver}
CLIENT="$(cd "$(dirname "$0")" && pwd)/dns_verify_client.py"
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
    for p in $(pgrep -f "pebble -config $WORK/pebble.json" 2>/dev/null || true); do
        kill "$p" 2>/dev/null || true
    done
    if [ "${DNSA3_KEEP:-0}" = "1" ]; then echo "== 现场保留：$WORK =="; fi
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
wait_dig() { # $1=期望正则 $2..=dig 参数
    local pat=$1; shift
    local i out=""
    for i in $(seq 1 60); do
        out=$(digq "$@" 2>/dev/null)
        printf '%s' "$out" | grep -qE -- "$pat" && { printf '%s' "$out"; return 0; }
        sleep 0.25
    done
    printf '%s' "$out"
}
expect() {
    if printf '%s' "$2" | grep -qE -- "$3"; then ok "$1"; else bad "$1（got: $(printf '%s' "$2" | head -c 240)）"; fi
}
expect_not() {
    if printf '%s' "$2" | grep -qE -- "$3"; then bad "$1（matched: $3 / got: $(printf '%s' "$2" | head -c 240)）"; else ok "$1"; fi
}
expect_json() {
    local got
    got=$(printf '%s' "$2" | python3 -c 'import json,sys
try: d=json.load(sys.stdin)
except Exception: print("PARSE-ERR"); raise SystemExit
print(eval(sys.argv[1]))' "$3" 2>/dev/null)
    [ "$got" = "True" ] && ok "$1" || bad "$1（json: $(printf '%s' "$2" | head -c 200)）"
}
expect_empty() {
    if [ -z "$2" ]; then ok "$1"; else bad "$1（got: $(printf '%s' "$2" | head -c 220)）"; fi
}
jget() { python3 -c 'import json,sys;d=json.load(sys.stdin);print(eval(sys.argv[1]))' "$1" 2>/dev/null; }

write_base_config() {
    mkdir -p "$WORK"
    cat > "$WORK/cfg.toml" <<EOF
[access_log]
enable = false
[admin]
realm = "dnsa3"
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
[dns.modes]
root = false
recursive = false
authoritative = true
[dns.doh]
enabled = true
path = "/dns-query"
hostnames = ["doh.test"]
[dns.acme]
enabled = false
domain = "acme-audit.crucible.test"
email = "admin@example.com"
renew_days = 60
server = "https://127.0.0.1:$PEBBLE/dir"
insecure = true
http_port = $ACME_HTTP
challenge = "http-01"
[[listeners]]
address = "127.0.0.1"
port = $WEB
root = "$WORK/www"
http_versions = ["h1", "h2"]
server_name = "crucible.local"
[[listeners]]
address = "127.0.0.1"
port = $TLS
root = "$WORK/www-tls"
http_versions = ["h1", "h2"]
server_name = "doh.test"
[listeners.ssl]
cert = "$WORK/certs/doh-cert.pem"
key = "$WORK/certs/doh-key.pem"
EOF
    mkdir -p "$WORK/www" "$WORK/www-tls" "$WORK/evidence" "$WORK/certs"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
        -subj "/CN=doh.test" -addext "subjectAltName=DNS:doh.test,DNS:crucible.local,IP:127.0.0.1" \
        -keyout "$WORK/certs/doh-key.pem" -out "$WORK/certs/doh-cert.pem" >/dev/null 2>&1
    rm -rf "$WORK/state" "$WORK/home"
    mkdir -p "$WORK/state" "$WORK/home"
}

start_server_state() {
    local st=$1 log=${2:-$WORK/server.log}
    env CRUCIBLE_DNS_STATE_ROOT="$st" HOME="$WORK/home" CRUCIBLE_NAMED_USER= \
        "$BIN" --config "$WORK/cfg.toml" > "$log" 2>&1 &
    echo $! > "$WORK/server.pid"
    PIDS+=("$!")
    local i
    for i in $(seq 1 80); do
        if curl -sf -m 1 -u "$AUTH" "http://127.0.0.1:$WEB/__admin/api/dns/status" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.25
    done
    echo "FATAL: server not ready; log:" >&2
    tail -30 "$log" >&2
    return 1
}

start_server() { start_server_state "$WORK/state" "$WORK/server.log"; }

stop_server_state() {
    local st=$1 pid i
    pid=$(cat "$WORK/server.pid" 2>/dev/null || true)
    [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
    for i in $(seq 1 40); do
        pgrep -f "named -c $st/etc/named.conf" >/dev/null 2>&1 || break
        for p in $(pgrep -f "named -c $st/etc/named.conf" 2>/dev/null || true); do
            kill "$p" 2>/dev/null || true
        done
        sleep 0.25
    done
    sleep 0.4
}

stop_server() { stop_server_state "$WORK/state"; }

# ---------------------------------------------------------------- A: 记录校验
stage_a() {
    echo "===== A: 记录校验 / 名称归一 / 注入拒绝 ====="
    post /api/dns/zones '{"action":"add","name":"audit.test","kind":"master"}' >/dev/null
    post /api/dns/records '{"zone":"audit.test","name":"marker","rtype":"A","ttl":300,"rdata":"192.0.2.1"}' >/dev/null
    expect "A 基线记录可解析" "$(wait_dig '^192\.0\.2\.1$' marker.audit.test A +short)" '^192\.0\.2\.1$'

    # NAPTR：旧实现直接 unsupported；现在是合法类型，且坏 rdata 拒绝。
    expect "NAPTR 合法记录被接受" \
        "$(post /api/dns/records '{"zone":"audit.test","name":"naptr","rtype":"NAPTR","ttl":300,"rdata":"100 10 \"S\" \"SIP+D2U\" \"!^.*$!sip:info@example.com!\" _sip._udp.audit.test."}')" '"ok":true'
    expect "NAPTR dig 返回" "$(wait_dig 'SIP\+D2U' naptr.audit.test NAPTR +short)" 'SIP\+D2U'
    expect "NAPTR 坏 order 被拒" \
        "$(post /api/dns/records '{"zone":"audit.test","name":"badn","rtype":"NAPTR","ttl":300,"rdata":"x 10 \"S\" \"SIP+D2U\" \".\" ."}')" '"error"'
    expect "NAPTR 缺字段被拒" \
        "$(post /api/dns/records '{"zone":"audit.test","name":"badn2","rtype":"NAPTR","ttl":300,"rdata":"100 10 \"S\" \"SIP+D2U\""}')" '"error"'

    # TTL 31 位：>2^31-1 拒绝；2^32 不再被静默截断成 0。
    expect "TTL=2^32 被拒（不再截断成 0）" \
        "$(post /api/dns/records '{"zone":"audit.test","name":"ttl1","rtype":"A","ttl":4294967296,"rdata":"192.0.2.2"}')" '2147483647'
    expect "TTL=2^31 被拒" \
        "$(post /api/dns/records '{"zone":"audit.test","name":"ttl2","rtype":"A","ttl":2147483648,"rdata":"192.0.2.2"}')" '2147483647'
    expect "TTL=2^31-1 接受" \
        "$(post /api/dns/records '{"zone":"audit.test","name":"ttl3","rtype":"A","ttl":2147483647,"rdata":"192.0.2.3"}')" '"ok":true'

    # owner 语义：64 字节 label、非法通配符、escaped 名
    local l64; l64=$(printf 'a%.0s' $(seq 1 64))
    expect "64 字节 label 被拒" \
        "$(post /api/dns/records "{\"zone\":\"audit.test\",\"name\":\"$l64\",\"rtype\":\"A\",\"ttl\":300,\"rdata\":\"192.0.2.4\"}")" '"error"'
    expect "非最左/非整 label 通配符被拒" \
        "$(post /api/dns/records '{"zone":"audit.test","name":"w*w","rtype":"A","ttl":300,"rdata":"192.0.2.4"}')" '"error"'
    expect "escaped 名（a\\\\.b）被明确拒绝" \
        "$(post /api/dns/records '{"zone":"audit.test","name":"a\\.b","rtype":"A","ttl":300,"rdata":"192.0.2.4"}')" '反斜杠|bad record name'
    expect "合法最左通配符接受" \
        "$(post /api/dns/records '{"zone":"audit.test","name":"*.wild","rtype":"A","ttl":300,"rdata":"192.0.2.5"}')" '"ok":true'

    # rdata 注入：换行/$INCLUDE、NUL、CAA 引号
    expect "rdata 换行+\$INCLUDE 被拒" \
        "$(post /api/dns/records '{"zone":"audit.test","name":"inj","rtype":"A","ttl":300,"rdata":"192.0.2.6\n$INCLUDE /etc/passwd"}')" 'single-line|控制字符'
    expect "rdata NUL 被拒" \
        "$(post /api/dns/records '{"zone":"audit.test","name":"nul","rtype":"TXT","ttl":300,"rdata":"a\u0000b"}')" '控制字符'
    expect "CAA 未闭合引号被拒" \
        "$(post /api/dns/records '{"zone":"audit.test","name":"caa","rtype":"CAA","ttl":300,"rdata":"0 issue \"unbalanced"}')" '引号|error'
    expect "坏记录未破坏整区（marker 仍在）" "$(digq marker.audit.test A +short)" '^192\.0\.2\.1$'
    expect "zone 文件无 \$INCLUDE 注入" "$(grep -c '\$INCLUDE' "$WORK/state/zones"/audit_test.*.zone 2>/dev/null || true)" '^0$'

    # 名称归一：绝对名/尾点/大小写；punycode 接受、Unicode 拒绝
    expect "绝对名归一（无双后缀）" \
        "$(post /api/dns/records '{"zone":"AUDIT.TEST.","name":"hello.audit.test.","rtype":"A","ttl":300,"rdata":"192.0.2.77"}')" '"ok":true'
    expect "绝对名原名字可解析" "$(wait_dig '^192\.0\.2\.77$' hello.audit.test A +short)" '^192\.0\.2\.77$'
    expect_not "不产生双后缀名" "$(digq hello.audit.test.audit.test A +short)" '192\.0\.2\.77'
    expect "punycode label 接受" \
        "$(post /api/dns/records '{"zone":"audit.test","name":"xn--bcher-kva","rtype":"A","ttl":300,"rdata":"192.0.2.88"}')" '"ok":true'
    expect "punycode dig 可解析" "$(wait_dig '^192\.0\.2\.88$' xn--bcher-kva.audit.test A +short)" '^192\.0\.2\.88$'
    expect "Unicode 记录名被拒" \
        "$(post /api/dns/records '{"zone":"audit.test","name":"bücher","rtype":"A","ttl":300,"rdata":"192.0.2.89"}')" '"error"'
    expect "geo 关闭时 line 记录被拒（不会静默不加载）" \
        "$(post /api/dns/records '{"zone":"audit.test","name":"lined","rtype":"A","ttl":300,"rdata":"192.0.2.90","line":"l0"}')" 'enabled=false|不存在'

    # 导入面
    expect "导入 \$INCLUDE 被拒" \
        "$(post /api/dns/zones '{"action":"import","name":"audit.test","text":"$INCLUDE /etc/passwd\n"}')" '不支持指令|没有解析'
    expect "导入未知分区被拒" \
        "$(post /api/dns/zones '{"action":"import","name":"nope.test","text":"www 300 IN A 192.0.2.1\n"}')" '不存在'
    expect "纯 SOA 导入被拒（不会清空分区）" \
        "$(post /api/dns/zones '{"action":"import","mode":"replace","name":"audit.test","text":"@ 300 IN SOA ns1.audit.test. h.audit.test. 1 900 600 86400 300\n"}')" '没有可导入'
    expect "合法导入 replace（含 NAPTR）" \
        "$(post /api/dns/zones '{"action":"import","mode":"replace","name":"audit.test","text":"@ 300 IN SOA ns1.audit.test. h.audit.test. 1 900 600 86400 300\nimp 300 IN NAPTR 100 10 \"S\" \"SIP+D2U\" \"\" .\nimp 300 IN A 192.0.2.12\n"}')" '"ok":true'
    expect "导入后 NAPTR 可解析" "$(wait_dig 'SIP\+D2U' imp.audit.test NAPTR +short)" 'SIP\+D2U'
    expect_empty "导入 replace 后基线记录已清" "$(digq marker.audit.test A +short)"
}

# ---------------------------------------------------------------- B: serial 回绕
# 真实的回绕只发生在 serial 已经贴近 0xFFFFFFFF 时（unix 秒要到 2106 年）。直接
# 把运行中 named 的 serial 从 ~1.79e9 改成 0xFFFFFFFE 会被 BIND 判成「更旧」
# （RFC1982 半空间）而拒绝重载 —— 所以本阶段用一个**独立状态根**：先正常建区，
# 停进程后把 zone 文件 SOA serial 改成 0xFFFFFFFE，再冷启动 named（没有内存旧值）。
stage_b() {
    echo "===== B: SOA serial 32 位回绕（独立状态根冷启动） ====="
    stop_server
    local st="$WORK/state-b" zf ser ser2 dn j
    rm -rf "$st"; mkdir -p "$st"
    start_server_state "$st" "$WORK/server-b.log" || { bad "B server start"; return 1; }
    post /api/dns/zones '{"action":"add","name":"serial.test","kind":"master"}' >/dev/null
    post /api/dns/records '{"zone":"serial.test","name":"@","rtype":"A","ttl":300,"rdata":"192.0.2.10"}' >/dev/null
    expect "serial 基线可解析" "$(wait_dig '^192\.0\.2\.10$' serial.test A +short)" '^192\.0\.2\.10$'
    stop_server_state "$st"
    zf=$(ls "$st/zones"/serial_test.*.zone 2>/dev/null | head -1)
    [ -n "$zf" ] || { bad "B zone 文件缺失"; return 1; }
    # 把 serial 拨到 0xFFFFFFFE，并清掉签名/journal（不走 reload，冷启动加载）
    python3 - "$zf" <<'PY'
import re,sys
p=sys.argv[1]; t=open(p).read()
t2=re.sub(r'(?m)^\s*\d+\s*;\s*serial', '  4294967294 ; serial', t, count=1)
assert t2 != t, "serial line not rewritten"
open(p,'w').write(t2)
PY
    rm -f "$zf".signed "$zf".jnl "$zf".signed.jnl
    python3 - "$st/db/dns.sqlite" <<'PY'
import sqlite3,sys
c=sqlite3.connect(sys.argv[1])
c.execute("INSERT INTO meta(k,v) VALUES('serial:serial.test','4294967294') ON CONFLICT(k) DO UPDATE SET v='4294967294'")
c.commit()
PY
    start_server_state "$st" "$WORK/server-b2.log" || { bad "B server restart"; return 1; }
    ser=$(wait_dig 'SOA' serial.test SOA +short | awk '{print $3}')
    expect "冷启动后 serial = 0xFFFFFFFF" "$ser" '^4294967295$'
    post /api/dns/records '{"zone":"serial.test","name":"wrap","rtype":"A","ttl":300,"rdata":"192.0.2.77"}' >/dev/null
    ser2=""
    for j in $(seq 1 60); do
        ser2=$(digq serial.test SOA +short 2>/dev/null | awk '{print $3}')
        [ "$ser2" = "1" ] && break
        sleep 0.25
    done
    expect "serial 回绕到 1（不是 4294967296）" "$ser2" '^1$'
    expect "回绕后记录仍可解析" "$(wait_dig '^192\.0\.2\.77$' wrap.serial.test A +short)" '^192\.0\.2\.77$'
    expect "zone 文件 serial 在 32 位内" "$(awk '/; serial/{print $1; exit}' "$zf")" '^[0-9]{1,10}$'
    expect "zone 文件 serial = 1" "$(awk '/; serial/{print $1; exit}' "$zf")" '^1$'
    stop_server_state "$st"
}

# ---------------------------------------------------------------- C: KASP
stage_c() {
    echo "===== C: KASP 重复角色拒绝 + 删除分区清理 key ====="
    local dup='{"action":"policy","dnssec":{"enabled":true,"algorithm":"ECDSAP256SHA256","rotation_enabled":false,"rotation_days":30,"ksk_lifetime_days":null,"keys":[{"role":"zsk","lifetime_days":null},{"role":"ZSK","lifetime_days":null}],"nsec3":true,"nsec3_iterations":0,"nsec3_optout":false,"cds":false}}'
    expect "KASP 重复角色被拒（否则 named 拒载整份配置）" "$(post_long /api/dns/dnssec "$dup")" '重复|error'
    expect "拒绝后配置未被污染（DNSKEY 测试区仍可查）" \
        "$(post /api/dns/zones '{"action":"add","name":"dnssec.test","kind":"master"}')" '"ok":true'
    post /api/dns/records '{"zone":"dnssec.test","name":"www","rtype":"A","ttl":300,"rdata":"192.0.2.31"}' >/dev/null
    local pol='{"action":"policy","dnssec":{"enabled":true,"algorithm":"ECDSAP256SHA256","rotation_enabled":false,"rotation_days":30,"ksk_lifetime_days":null,"keys":[],"nsec3":true,"nsec3_iterations":0,"nsec3_optout":false,"cds":false}}'
    expect "启用 DNSSEC 策略" "$(post_long /api/dns/dnssec "$pol")" '"ok":true'
    local i keys=""
    for i in $(seq 1 60); do
        keys=$(ls "$WORK/state/keys"/Kdnssec.test.+*.key 2>/dev/null | wc -l | tr -d ' ')
        [ "$keys" -ge 2 ] && break
        sleep 0.5
    done
    expect "KASP 为分区生成 >=2 把 key" "$keys" '^[2-9]$'
    local dn=0 j
    for j in $(seq 1 80); do
        dn=$(digq dnssec.test DNSKEY +noall +answer 2>/dev/null | grep -c 'DNSKEY' || true)
        [ "${dn:-0}" -ge 2 ] && break
        sleep 0.5
    done
    expect "DNSKEY 已发布（>=2）" "$dn" '^[2-9]$'
    expect "NSEC3PARAM 已发布" "$(wait_dig 'NSEC3PARAM' dnssec.test NSEC3PARAM +noall +answer)" 'NSEC3PARAM'
    expect "删除分区" "$(post /api/dns/zones '{"action":"del","name":"dnssec.test"}')" '"ok":true'
    sleep 1
    expect "删除分区后 KASP key 文件已清理" "$(ls "$WORK/state/keys"/Kdnssec.test.+* 2>/dev/null | wc -l | tr -d ' ')" '^0$'
    expect "删除分区后 zone 文件已清理" "$(ls "$WORK/state/zones"/dnssec_test.*.zone 2>/dev/null | wc -l | tr -d ' ')" '^0$'
    expect_not "删除分区后 status 不再列出该区" "$(api /api/dns/zones)" 'dnssec\.test'
}

# ---------------------------------------------------------------- D: ACL/zone transfer
stage_d() {
    echo "===== D: AXFR ACL / 配置白名单校验 / slave refresh / also-notify ====="
    post /api/dns/zones '{"action":"add","name":"acl.test","kind":"master","axfr_acl":["127.0.0.1"]}' >/dev/null
    post /api/dns/records '{"zone":"acl.test","name":"www","rtype":"A","ttl":300,"rdata":"192.0.2.41"}' >/dev/null
    expect "AXFR 基线可解析" "$(wait_dig '^192\.0\.2\.41$' www.acl.test A +short)" '^192\.0\.2\.41$'
    expect "AXFR 白名单内成功" "$(digq acl.test AXFR)" 'acl\.test.*SOA'
    expect "AXFR 白名单外 REFUSED" \
        "$(dig -b 127.0.0.2 @127.0.0.1 -p "$DNS" acl.test AXFR +noall +comments +answer +time=5 +tries=1)" 'status: REFUSED'

    local cfgbad
    cfgbad=$(api /api/dns/config | python3 -c 'import json,sys;d=json.load(sys.stdin);d["recursion_acl"]=["10.0.0.0/8","10.0.0.0/8x"];print(json.dumps(d))')
    expect "非法 recursion_acl 保存前被拒" "$(post /api/dns/config "$cfgbad")" 'bad recursion_acl'
    expect "被拒后 recursion_acl 未被改写" "$(api /api/dns/config | jget 'd["recursion_acl"]')" "\['127.0.0.1'\]"
    local cfgv6
    cfgv6=$(api /api/dns/config | python3 -c 'import json,sys;d=json.load(sys.stdin);d["recursion_acl"]=["127.0.0.1","::1/128"];print(json.dumps(d))')
    expect "IPv6 ACL 合法保存" "$(post /api/dns/config "$cfgv6")" '"ok":true'
    local cfgv4
    cfgv4=$(api /api/dns/config | python3 -c 'import json,sys;d=json.load(sys.stdin);d["recursion_acl"]=["127.0.0.1"];print(json.dumps(d))')
    post /api/dns/config "$cfgv4" >/dev/null

    post /api/dns/zones '{"action":"add","name":"notify2.test","kind":"master","also_notify":["127.0.0.1:27459"]}' >/dev/null
    post /api/dns/zones '{"action":"add","name":"slave2.test","kind":"slave","primaries":["127.0.0.1:27459"],"refresh_hours":1}' >/dev/null
    sleep 1
    local conf; conf=$(cat "$WORK/state/etc/named.conf")
    expect "per-zone allow-transfer 渲染" "$conf" 'zone "acl\.test".*allow-transfer \{ 127\.0\.0\.1; \}'
    expect "also-notify 渲染（ip port N）" "$conf" 'also-notify \{ 127\.0\.0\.1 port 27459; \}'
    expect "slave refresh 钳制为数字秒" "$conf" 'min-refresh-time 3600; max-refresh-time 3600;'
    expect "master SOA refresh=900" "$(digq acl.test SOA +short | awk '{print $4}')" '^900$'
    expect "per-zone ACL 内 AXFR 成功" "$(digq acl.test AXFR)" 'acl\.test.*SOA'
    post /api/dns/zones '{"action":"del","name":"slave2.test"}' >/dev/null
    post /api/dns/zones '{"action":"del","name":"notify2.test"}' >/dev/null
}

# ---------------------------------------------------------------- E: DoH/ECS
stage_e() {
    echo "===== E: DoH 报文面 / CORS / 缓存 / ECS / FORMERR ====="
    local base="https://127.0.0.1:$TLS"
    local code
    code=$(curl -sk -m 10 -o "$WORK/evidence/doh-get.bin" -w '%{http_code}' -H 'Host: doh.test' "$base/dns-query?dns=kt0AAQABAAAAAAAABXNtb2tlBHRlc3QAAAEAAQ==" )
    expect "DoH GET 合法 base64 → 200" "$code" '^200$'
    code=$(curl -sk -m 10 -o /dev/null -w '%{http_code}' -H 'Host: doh.test' "$base/dns-query?dns=!!!")
    expect "DoH GET 非法 base64 → 400" "$code" '^400$'
    code=$(curl -sk -m 10 -o /dev/null -w '%{http_code}' -H 'Host: doh.test' "$base/dns-query")
    expect "DoH GET 缺 dns= → 400" "$code" '^400$'
    code=$(curl -sk -m 10 -o /dev/null -w '%{http_code}' -X POST -H 'Host: doh.test' -H 'Content-Type: text/plain' \
        --data-binary @"$WORK/evidence/doh-get.bin" "$base/dns-query")
    expect "DoH POST 错 Content-Type → 415" "$code" '^415$'
    head -c 70000 /dev/zero > "$WORK/evidence/big.bin"
    code=$(curl -sk -m 10 -o /dev/null -w '%{http_code}' -X POST -H 'Host: doh.test' \
        -H 'Content-Type: application/dns-message' --data-binary @"$WORK/evidence/big.bin" "$base/dns-query")
    expect "DoH POST >65535 → 413" "$code" '^413$'
    local hdrs
    hdrs=$(curl -sk -m 10 -D - -o /dev/null -X OPTIONS -H 'Host: doh.test' "$base/dns-query")
    expect "CORS 预检 204" "$hdrs" 'HTTP/1\.1 204|HTTP/2 204'
    expect "CORS allow-origin *" "$hdrs" 'access-control-allow-origin: \*'
    expect "CORS allow methods" "$hdrs" 'access-control-allow-methods: GET, POST, OPTIONS'

    code=$(curl -s -m 10 -o /dev/null -w '%{http_code}' -H 'Host: doh.test' \
        "http://127.0.0.1:$WEB/dns-query?dns=kt0AAQABAAAAAAAABXNtb2tlBHRlc3QAAAEAAQ==")
    expect "明文 DoH → 400（RFC 8484 §5）" "$code" '^400$'
    code=$(curl -sk -m 10 -o /dev/null -w '%{http_code}' -H 'Host: evil.test' "$base/dns-query?dns=kt0AAQABAAAAAAAABXNtb2tlBHRlc3QAAAEAAQ==")
    expect_not "白名单外 Host 不命中 DoH" "$code" '^200$'

    expect_json "DoH POST 应答" "$(python3 "$CLIENT" doh doh.test "$TLS" "$WORK/certs/doh-cert.pem" POST audit.test)" 'd.get("status")==200 and d.get("rcode")==0'
    expect_json "DoH GET 缓存头 max-age" "$(python3 "$CLIENT" doh doh.test "$TLS" "$WORK/certs/doh-cert.pem" GET audit.test)" 'd.get("cache_control","").startswith("max-age=")'
    expect_json "DoH POST 缓存头 no-store" "$(python3 "$CLIENT" doh doh.test "$TLS" "$WORK/certs/doh-cert.pem" POST audit.test)" 'd.get("cache_control")=="no-store"'
    expect_json "DoH ECS 回显 scope=0" "$(python3 "$CLIENT" doh doh.test "$TLS" "$WORK/certs/doh-cert.pem" POST audit.test 1:203.0.113:24)" 'd.get("ecs") and d["ecs"][0]["source"]==24 and d["ecs"][0]["scope"]==0'
    python3 "$CLIENT" build-malformed audit.test "$WORK/evidence/bad-family.bin" family
    expect_json "畸形 ECS（未知 family）→ FORMERR" \
        "$(python3 "$CLIENT" doh-wire doh.test "$TLS" "$WORK/certs/doh-cert.pem" POST "$WORK/evidence/bad-family.bin")" \
        'd.get("status")==200 and d.get("rcode")==1 and d.get("an",0)==0'
    python3 "$CLIENT" build-malformed audit.test "$WORK/evidence/bad-olen.bin" olen
    expect_json "畸形 ECS（olen 越界）→ FORMERR" \
        "$(python3 "$CLIENT" doh-wire doh.test "$TLS" "$WORK/certs/doh-cert.pem" POST "$WORK/evidence/bad-olen.bin")" \
        'd.get("status")==200 and d.get("rcode")==1'
}

# ---------------------------------------------------------------- F: 并发写
stage_f() {
    echo "===== F: 管理 API 并发（CNAME/A 同名竞争） ====="
    post /api/dns/zones '{"action":"add","name":"race.test","kind":"master"}' >/dev/null
    post /api/dns/records '{"zone":"race.test","name":"marker","rtype":"A","ttl":300,"rdata":"192.0.2.50"}' >/dev/null
    expect "race 基线可解析" "$(wait_dig '^192\.0\.2\.50$' marker.race.test A +short)" '^192\.0\.2\.50$'
    ( post /api/dns/records '{"zone":"race.test","name":"dup","rtype":"CNAME","ttl":300,"rdata":"target.race.test."}' > "$WORK/evidence/race-cname.json" ) &
    local p1=$!
    ( post /api/dns/records '{"zone":"race.test","name":"dup","rtype":"A","ttl":300,"rdata":"192.0.2.9"}' > "$WORK/evidence/race-a.json" ) &
    local p2=$!
    wait "$p1" "$p2"
    local oks errs
    oks=$(grep -l '"ok":true' "$WORK/evidence/race-cname.json" "$WORK/evidence/race-a.json" 2>/dev/null | wc -l | tr -d ' ')
    errs=$(grep -l '"error"' "$WORK/evidence/race-cname.json" "$WORK/evidence/race-a.json" 2>/dev/null | wc -l | tr -d ' ')
    expect "并发同名 CNAME/A 恰好一个成功" "$oks" '^1$'
    expect "另一个明确报错（不产生 CNAME+other data）" "$errs" '^1$'
    expect "竞态后区仍加载（marker 可查）" "$(digq marker.race.test A +short)" '^192\.0\.2\.50$'
    expect "竞态后 SOA 正常" "$(digq race.test SOA +short | wc -l | tr -d ' ')" '^1$'
    expect "zone 文件无 CNAME 与 A 并存" \
        "$(awk '/^dup /{print $4}' "$WORK/state/zones"/race_test.*.zone 2>/dev/null | sort -u | wc -l | tr -d ' ')" '^1$'
}

# ---------------------------------------------------------------- G: ACME 按需监听
stage_g() {
    echo "===== G: ACME http-01（启动时 enabled=false，面板启用后按需起监听） ====="
    if ! need pebble; then skip "G-ACME 缺 pebble"; return 0; fi
    if ! need acme.sh; then skip "G-ACME 缺 acme.sh"; return 0; fi
    mkdir -p "$WORK/home/.acme.sh"
    cp -L "$(command -v acme.sh)" "$WORK/home/.acme.sh/acme.sh"
    chmod +x "$WORK/home/.acme.sh/acme.sh"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
        -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
        -keyout "$WORK/pebble-key.pem" -out "$WORK/pebble-cert.pem" >/dev/null 2>&1
    cat > "$WORK/pebble.json" <<EOF
{"pebble":{"listenAddress":"127.0.0.1:$PEBBLE","managementListenAddress":"127.0.0.1:$PEBBLE_MGMT",
"certificate":"$WORK/pebble-cert.pem","privateKey":"$WORK/pebble-key.pem",
"httpPort":$ACME_HTTP,"tlsPort":$((ACME_HTTP - 1)),"ocspResponderURL":"",
"externalAccountBindingRequired":false,"certificateValidityPeriod":7776000}}
EOF
    expect "启动时 ACME 关闭（无监听器日志）" "$(grep -c 'http-01 challenge listener' "$WORK/server.log" 2>/dev/null || true)" '^0$'
    post /api/dns/zones '{"action":"add","name":"crucible.test","kind":"master"}' >/dev/null
    post /api/dns/records '{"zone":"crucible.test","name":"acme-audit","rtype":"A","ttl":60,"rdata":"127.0.0.1"}' >/dev/null
    expect "challenge 域名可解析" "$(wait_dig '^127\.0\.0\.1$' acme-audit.crucible.test A +short)" '^127\.0\.0\.1$'
    PEBBLE_VA_NOSLEEP=1 pebble -config "$WORK/pebble.json" -dnsserver "127.0.0.1:$DNS" -strict=false \
        > "$WORK/pebble.log" 2>&1 &
    PIDS+=("$!")
    sleep 2
    curl -sk "https://127.0.0.1:$PEBBLE_MGMT/roots/0" > "$WORK/pebble-root.pem" || true

    local cfgon
    cfgon=$(api /api/dns/config | python3 -c 'import json,sys;d=json.load(sys.stdin);d["acme"]["enabled"]=True;print(json.dumps(d))')
    expect "面板启用 ACME" "$(post /api/dns/config "$cfgon")" '"ok":true'
    local r; r=$(post_long /api/dns/acme/issue '{}')
    expect "面板签发（http-01，按需监听）成功" "$r" '"ok":true'
    local cert="$WORK/state/acme/acme-audit.crucible.test/fullchain.pem"
    [ -s "$cert" ] && ok "证书落盘" || bad "证书未落盘（$(tail -5 "$WORK/server.log")）"
    expect "issuer 是 Pebble" "$(openssl x509 -in "$cert" -noout -issuer 2>/dev/null)" 'Pebble'
    expect "日志证明监听器是签发时按需启动的" "$(cat "$WORK/server.log")" '按需启动|listener ready on :27458'
    expect "私钥权限 0600" "$(stat -c %a "$WORK/state/acme/acme-audit.crucible.test/privkey.pem" 2>/dev/null)" '^600$'
    for p in $(pgrep -f "pebble -config $WORK/pebble.json" 2>/dev/null || true); do kill "$p" 2>/dev/null || true; done
}

# ---------------------------------------------------------------- H: 递归 / rebinding
stage_h() {
    echo "===== H: 递归转发 + rebinding 防护（deny-answer-addresses） ====="
    # 伪上游：对所有 A 查询都回 127.0.0.1（典型 DNS rebinding 应答）
    python3 - "$WORK/fake.log" <<'PY' &
import socket,struct,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("127.0.0.1",27459))
log=open(sys.argv[1],"a",buffering=1)
while True:
    q,addr=s.recvfrom(4096)
    off=12
    while off < len(q) and q[off] != 0: off += 1 + q[off]
    off += 5
    question=q[12:off]
    resp=q[:2]+b'\x81\x80'+struct.pack("!HHHH",1,1,0,0)+question
    resp+=b'\xc0\x0c'+struct.pack("!HHIH",1,1,60,4)+bytes([127,0,0,1])
    s.sendto(resp,addr)
    log.write("query %d bytes\n" % len(q))
PY
    PIDS+=("$!")
    sleep 0.5
    local cfg
    cfg=$(api /api/dns/config | python3 -c 'import json,sys;d=json.load(sys.stdin);d["modes"]["recursive"]=True;d["forwarders"]=["127.0.0.1:27459"];d["forward_policy"]="only";d["rebinding_protect"]=False;print(json.dumps(d))')
    expect "开启递归转发（rebinding 防护关）" "$(post /api/dns/config "$cfg")" '"ok":true'
    # +cdflag：伪上游不带签名，关闭验证以便观察递归答案本身
    expect "rebinding 防护关：私有地址应答被接受" \
        "$(wait_dig '^127\.0\.0\.1$' rebind.test A +short +cdflag)" '^127\.0\.0\.1$'
    expect_not "默认配置不渲染 deny-answer-addresses" "$(cat "$WORK/state/etc/named.conf")" 'deny-answer-addresses'
    cfg=$(api /api/dns/config | python3 -c 'import json,sys;d=json.load(sys.stdin);d["rebinding_protect"]=True;print(json.dumps(d))')
    expect "开启 rebinding 防护" "$(post /api/dns/config "$cfg")" '"ok":true'
    expect "named.conf 渲染 deny-answer-addresses" "$(cat "$WORK/state/etc/named.conf")" 'deny-answer-addresses \{ 0\.0\.0\.0/8;'
    # 说明：BIND 的 deny-answer-addresses 只在 DNSSEC 验证路径上生效；伪上游没有签名、
    # 且 +cdflag 关闭了验证，所以这里只验证配置渲染与「named 仍能正常加载该语句」，
    # 不把「私有地址被丢弃」当作可复现结论（避免假证）。
    expect "权威区不受递归策略影响" "$(digq www.acl.test A +short)" '^192\.0\.2\.41$'
}

# ---------------------------------------------------------------- main
command -v named >/dev/null 2>&1 || { echo "FATAL: named 不在 PATH（eval \"\$(/home/dev123/bin/aptlocal.sh env)\"）" >&2; exit 2; }
[ -x "$BIN" ] || { echo "FATAL: webserver 二进制不存在：$BIN" >&2; exit 2; }
for p in "$DNS" "$RNDC" "$WEB" "$TLS" "$ACME_HTTP" "$PEBBLE" "$PEBBLE_MGMT"; do
    if ! port_free "$p"; then echo "FATAL: port $p in use（改端口或清理旧实例）" >&2; exit 2; fi
done
write_base_config
echo "binary: $BIN"; echo "work:   $WORK"
start_server || exit 1

want a && stage_a
want c && stage_c
want d && stage_d
want e && stage_e
want f && stage_f
want g && stage_g
want h && stage_h
# B 会停掉主实例、换成独立状态根冷启动（serial 回绕必须在 named 没有内存旧值时测）
want b && stage_b

stop_server
echo "=================================================================="
echo "DNS audit3 verification: PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
[ "$FAIL" -eq 0 ]
