#!/usr/bin/env bash
# 真机 DNS 全量验证（BIND9 named/dig/dnssec-* + pebble ACME）。
#
# 一条命令：
#   scripts/dns_verify.sh --real
# 或：
#   scripts/dns_bind_verify.sh
#
# 环境要求（无需 root）：
#   - named/dig/rndc/dnssec-keygen/dnssec-signzone/named-checkzone/named-checkconf
#     （缺：/home/dev123/bin/aptlocal.sh install-deps bind9 bind9-utils bind9-dnsutils）
#   - python3、curl、openssl
#   - ACME 阶段需要 pebble + pebble-challtestsrv + acme.sh；缺则 SKIP（不判 FAIL）
#   - 已构建的 webserver：DNSV_BIN=/path/to/webserver（默认 target/release/webserver）
#
# 所有端口从 DNSV_BASE（默认 23500）派生，避开 53/853/24000/26000/28000/29000/31000/32000/36xxx。
# 每个阶段使用独立 CRUCIBLE_DNS_STATE_ROOT；退出时清理所有进程。
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BASE=${DNSV_BASE:-23500}
DNS=$((BASE + 53))
RNDC=$((BASE + 453))
WEB=$((BASE + 95))
TLS=$((BASE + 43))
DOT=$((BASE + 353))
ACME_HTTP=$((BASE + 2))
PEBBLE=$((BASE + 200))
PEBBLE_MGMT=$((BASE + 201))
CHALL_DNS=$((BASE + 58))
UP=$((BASE + 54))
ROOTM=$((BASE + 56))
HTTP_ROOT=$((BASE + 80))
WORK=${DNSV_DIR:-${TMPDIR:-/tmp}/dnsbind-verify-$$}
# 优先用当前 cargo target（buildenv.sh 设置的 CARGO_TARGET_DIR），再退回仓库 target。
BIN=${DNSV_BIN:-${CARGO_TARGET_DIR:-$ROOT/target}/release/webserver}
CLIENT="$ROOT/scripts/dns_verify_client.py"
AUTH="admin:admin"
PASS=0
FAIL=0
SKIP=0
PIDS=()

ok() { PASS=$((PASS + 1)); echo "PASS: $1"; }
bad() { FAIL=$((FAIL + 1)); echo "FAIL: $1"; }
skip() { SKIP=$((SKIP + 1)); echo "SKIP: $1"; }
need() { command -v "$1" >/dev/null 2>&1; }

cleanup() {
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
  for st in basic dnssec acme; do
    for p in $(pgrep -f "named -c $WORK/$st/etc/named.conf" 2>/dev/null || true); do
      kill "$p" 2>/dev/null || true
    done
  done
  for p in $(pgrep -f "pebble -config $WORK/pebble-config.json" 2>/dev/null || true); do
    kill "$p" 2>/dev/null || true
  done
  for p in $(pgrep -f "http.server $HTTP_ROOT" 2>/dev/null || true); do
    kill "$p" 2>/dev/null || true
  done
  for p in $(pgrep -f "udp_fake.py|dns_verify_client.py fake" 2>/dev/null || true); do
    kill "$p" 2>/dev/null || true
  done
  # DNSV_KEEP=1 保留现场（named.conf/zone/日志/acme 材料），便于报告取证。
  if [ "${DNSV_KEEP:-0}" = "1" ]; then
    echo "== 现场保留（DNSV_KEEP=1）：$WORK =="
  else
    rm -rf "$WORK"
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
for p in "$DNS" "$RNDC" "$WEB" "$TLS" "$DOT" "$ACME_HTTP" "$PEBBLE" "$PEBBLE_MGMT" "$CHALL_DNS" "$UP" "$ROOTM" "$HTTP_ROOT"; do
  if ! port_free "$p"; then echo "FATAL: port $p is in use（用 DNSV_BASE 换一段）" >&2; exit 2; fi
done

mkdir -p "$WORK"/{certs,www,www-tls,home,rootweb,signkeys,signwork,upstream,zones}

preflight() {
  local missing=()
  for t in named dig rndc dnssec-keygen dnssec-signzone named-checkzone named-checkconf python3 curl openssl; do
    need "$t" || missing+=("$t")
  done
  if [ ${#missing[@]} -gt 0 ]; then
    echo "FATAL: missing tools: ${missing[*]}" >&2
    echo "  install: /home/dev123/bin/aptlocal.sh install-deps bind9 bind9-utils bind9-dnsutils" >&2
    echo "  then:    eval \"\$(/home/dev123/bin/aptlocal.sh env)\"" >&2
    exit 2
  fi
  [ -x "$BIN" ] || { echo "FATAL: webserver binary not found/executable: $BIN（先 cargo build --release --bin webserver --features tls,tls_boring）" >&2; exit 2; }
  echo "tools: $(named -v | head -1) / $(dig -v 2>&1 | head -1)"
  echo "binary: $BIN ($(stat -c %s "$BIN" 2>/dev/null || echo '?') bytes)"
}

# 自签 DoH/DoT 证书（ACME 阶段会覆盖 DoT 为 pebble 证书）
mkcerts() {
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
    -subj "/CN=doh.test" -addext "subjectAltName=DNS:doh.test,DNS:crucible.local,IP:127.0.0.1" \
    -keyout "$WORK/certs/doh-key.pem" -out "$WORK/certs/doh-cert.pem" >/dev/null 2>&1
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
    -subj "/CN=dot.test" -addext "subjectAltName=DNS:dot.test,IP:127.0.0.1" \
    -keyout "$WORK/certs/dot-key.pem" -out "$WORK/certs/dot-cert.pem" >/dev/null 2>&1
}

write_base_config() {
  # $1=state dir, $2=extra [dns] body, $3=DoT cert spec, $4=DoT key spec, $5=acme block
  local st=$1 extra=$2 dotcert=$3 dotkey=$4 acme=$5
  cat > "$WORK/cfg-$st.toml" <<EOF
[access_log]
enable = false
[admin]
realm = "dnsbind"
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
$extra
[dns.modes]
root = false
recursive = false
authoritative = true
[dns.doh]
enabled = true
path = "/dns-query"
hostnames = ["doh.test"]
[dns.dot]
enabled = true
port = $DOT
cert = "$dotcert"
key = "$dotkey"
allow = ["127.0.0.1"]
rate_per_sec = 1000
burst = 1000
$acme
[[listeners]]
address = "127.0.0.1"
port = $WEB
root = "$WORK/www"
http_versions = ["h1", "h2"]
server_name = "crucible.local"
status_path = "/__status"
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
}

start_server() {
  local st=$1
  env CRUCIBLE_DNS_STATE_ROOT="$WORK/$st" HOME="$WORK/home" CRUCIBLE_NAMED_USER= \
    "$BIN" --config "$WORK/cfg-$st.toml" > "$WORK/$st/server.log" 2>&1 &
  echo $! > "$WORK/$st/server.pid"
  PIDS+=("$!")
  local i
  for i in $(seq 1 60); do
    if curl -sf -m 1 -u "$AUTH" "http://127.0.0.1:$WEB/__admin/api/dns/status" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.5
  done
  echo "FATAL: server ($st) did not become ready; log tail:" >&2
  tail -20 "$WORK/$st/server.log" >&2
  return 1
}

stop_server() {
  local st=$1 pid
  pid=$(cat "$WORK/$st/server.pid" 2>/dev/null || true)
  [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
  for p in $(pgrep -f "named -c $WORK/$st/etc/named.conf" 2>/dev/null || true); do
    kill "$p" 2>/dev/null || true
  done
  sleep 0.5
}

api() { curl -s -m 30 -u "$AUTH" "http://127.0.0.1:$WEB/__admin$1"; }
post() { curl -s -m 60 -u "$AUTH" -H 'Content-Type: application/json' -d "$2" "http://127.0.0.1:$WEB/__admin$1"; }
post_long() { curl -s -m 220 -u "$AUTH" -H 'Content-Type: application/json' -d "${2:-}" "http://127.0.0.1:$WEB/__admin$1"; }
wait_port() {
  local i
  for i in $(seq 1 40); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; then exec 3>&- 3<&-; return 0; fi
    sleep 0.5
  done
  return 1
}
jget() { python3 -c 'import json,sys;d=json.load(sys.stdin);print(eval(sys.argv[1]))' "$1" 2>/dev/null; }
digq() { dig @127.0.0.1 -p "$DNS" "$@" +time=5 +tries=1; }
expect() { # label, output, pattern
  if printf '%s' "$2" | grep -qE -- "$3"; then ok "$1"; else bad "$1（got: $(printf '%s' "$2" | head -c 160)）"; fi
}
expect_json() { # label, json, python expr
  if [ "$(printf '%s' "$2" | jget "$3")" = "True" ]; then ok "$1"; else bad "$1（json: $(printf '%s' "$2" | head -c 200)）"; fi
}

# ---------------------------------------------------------------- fixtures
start_upstream() {
  mkdir -p "$WORK/upstream/zones"
  cat > "$WORK/upstream/named.conf" <<EOF
options { directory "$WORK/upstream/zones"; listen-on port $UP { 127.0.0.1; }; listen-on-v6 port $UP { none; }; recursion no; allow-transfer { 127.0.0.1; }; ixfr-from-differences yes; };
controls { inet 127.0.0.1 port $((UP + 400)) allow { 127.0.0.1; } keys { "rndc-key"; }; };
key "rndc-key" { algorithm hmac-sha256; secret "1111111111111111111111111111111111111111111111111111111111111111"; };
zone "slave.test" { type primary; file "slave.test.zone"; allow-transfer { 127.0.0.1; }; also-notify { 127.0.0.1 port $DNS; }; };
EOF
  cat > "$WORK/upstream/rndc.conf" <<EOF
options { default-server 127.0.0.1; default-port $((UP + 400)); default-key "rndc-key"; };
server 127.0.0.1 { key "rndc-key"; };
key "rndc-key" { algorithm hmac-sha256; secret "1111111111111111111111111111111111111111111111111111111111111111"; };
EOF
  cat > "$WORK/upstream/zones/slave.test.zone" <<'EOF'
$ORIGIN slave.test.
$TTL 300
@ IN SOA ns1.slave.test. hostmaster.slave.test. ( 100 60 60 86400 300 )
@ IN NS ns1.slave.test.
ns1 IN A 127.0.0.1
www IN A 192.0.2.201
EOF
  named-checkconf "$WORK/upstream/named.conf" || return 1
  named -c "$WORK/upstream/named.conf" -g -f > "$WORK/upstream/named.log" 2>&1 &
  PIDS+=("$!")
  sleep 1
}

start_rootmaster() {
  mkdir -p "$WORK/rootmaster/zones"
  cat > "$WORK/rootmaster/named.conf" <<EOF
options { directory "$WORK/rootmaster/zones"; listen-on port $ROOTM { 127.0.0.1; }; listen-on-v6 port $ROOTM { none; }; recursion no; allow-transfer { 127.0.0.1; }; ixfr-from-differences yes; };
controls { inet 127.0.0.1 port $((ROOTM + 400)) allow { 127.0.0.1; } keys { "rndc-key"; }; };
key "rndc-key" { algorithm hmac-sha256; secret "2222222222222222222222222222222222222222222222222222222222222222"; };
zone "." { type primary; file "root.zone"; allow-transfer { 127.0.0.1; }; };
EOF
  cat > "$WORK/rootmaster/rndc.conf" <<EOF
options { default-server 127.0.0.1; default-port $((ROOTM + 400)); default-key "rndc-key"; };
server 127.0.0.1 { key "rndc-key"; };
key "rndc-key" { algorithm hmac-sha256; secret "2222222222222222222222222222222222222222222222222222222222222222"; };
EOF
  python3 - "$WORK/rootmaster/zones/root.zone" <<'PY'
import sys
p=sys.argv[1]
lines=['$ORIGIN .','. 86400 IN SOA a.root-servers.test. noc.test. ( 2026110100 1800 900 604800 86400 )','. 518400 IN NS a.root-servers.test.','a.root-servers.test. 86400 IN A 127.0.0.1']
for i in range(300):
    lines.append(f'n{i:03d}.test. 3600 IN A 192.0.2.{i%250+1}')
open(p,'w').write('\n'.join(lines)+'\n')
PY
  named-checkconf "$WORK/rootmaster/named.conf" || return 1
  named -c "$WORK/rootmaster/named.conf" -g -f > "$WORK/rootmaster/named.log" 2>&1 &
  PIDS+=("$!")
  sleep 1
}

# ---------------------------------------------------------------- Stage A
stage_a() {
  echo "===== Stage A: 三模式 / 权威 RR / 坏 rdata / AXFR-IXFR / slave / root / ECS / DoT-DoH ====="
  write_base_config basic "" "$WORK/certs/dot-cert.pem" "$WORK/certs/dot-key.pem" ""
  mkdir -p "$WORK/basic"
  start_server basic || return 1
  local st
  st=$(api /api/dns/status)
  expect "named_running=true" "$st" '"named_running":true'

  post /api/dns/zones '{"action":"add","name":"verify.test","kind":"master"}' >/dev/null
  local r
  for r in \
    '{"zone":"verify.test","name":"@","rtype":"A","ttl":300,"rdata":"192.0.2.10"}' \
    '{"zone":"verify.test","name":"@","rtype":"AAAA","ttl":300,"rdata":"2001:db8::10"}' \
    '{"zone":"verify.test","name":"www","rtype":"CNAME","ttl":300,"rdata":"verify.test."}' \
    '{"zone":"verify.test","name":"@","rtype":"MX","ttl":300,"rdata":"10 mail.verify.test."}' \
    '{"zone":"verify.test","name":"@","rtype":"TXT","ttl":300,"rdata":"v=spf1 -all"}' \
    '{"zone":"verify.test","name":"_sip._tcp","rtype":"SRV","ttl":300,"rdata":"10 20 5060 sip.verify.test."}' \
    '{"zone":"verify.test","name":"sub","rtype":"NS","ttl":300,"rdata":"ns1.verify.test."}' \
    '{"zone":"verify.test","name":"@","rtype":"CAA","ttl":300,"rdata":"0 issue \"letsencrypt.org\""}'; do
    post /api/dns/records "$r" >/dev/null
  done
  sleep 1
  expect "A" "$(digq verify.test A +short)" '^192\.0\.2\.10$'
  expect "AAAA" "$(digq verify.test AAAA +short)" '2001:db8::10'
  expect "CNAME" "$(digq www.verify.test A +short)" 'verify\.test\.'
  expect "MX" "$(digq verify.test MX +short)" 'mail\.verify\.test'
  expect "TXT" "$(digq verify.test TXT +short)" 'spf1'
  expect "SRV" "$(digq _sip._tcp.verify.test SRV +short)" '5060'
  expect "NS" "$(digq verify.test NS +short)" 'ns1\.verify\.test'
  expect "SOA" "$(digq verify.test SOA +short)" 'ns1\.verify\.test'

  # 坏 rdata：A/MX/SRV/DS 走按类型校验；CAA 走 named-checkzone（BIND 权威判据）
  for t in \
    '{"zone":"verify.test","name":"bad","rtype":"A","ttl":300,"rdata":"hello"}' \
    '{"zone":"verify.test","name":"bad","rtype":"MX","ttl":300,"rdata":"10"}' \
    '{"zone":"verify.test","name":"bad","rtype":"SRV","ttl":300,"rdata":"x y z sip"}' \
    '{"zone":"verify.test","name":"bad","rtype":"DS","ttl":300,"rdata":"1 13 2 ABC"}' \
    '{"zone":"verify.test","name":"bad","rtype":"CAA","ttl":300,"rdata":"0 issue lets encrypt"}'; do
    local out; out=$(post /api/dns/records "$t")
    expect "bad rdata rejected: $(printf '%s' "$t" | head -c 60)" "$out" '"error"'
  done

  # AXFR：白名单内成功、非白名单 REFUSED
  expect "AXFR in-ACL" "$(digq verify.test AXFR)" 'verify\.test.*SOA'
  expect "AXFR non-ACL REFUSED" "$(dig -b 127.0.0.2 @127.0.0.1 -p "$DNS" verify.test AXFR +noall +comments +answer +time=5 +tries=1)" 'status: REFUSED'
  # IXFR：加一条记录后请求旧 serial
  local ser ser2
  ser=$(digq verify.test SOA +short | awk '{print $3}')
  sleep 1
  post /api/dns/records '{"zone":"verify.test","name":"ixfr1","rtype":"A","ttl":300,"rdata":"192.0.2.99"}' >/dev/null
  ser2=$(digq verify.test SOA +short | awk '{print $3}')
  expect "IXFR diff" "$(dig @127.0.0.1 -p "$DNS" verify.test IXFR="$ser" +tcp +noall +answer +time=5 +tries=1)" 'ixfr1\.verify\.test'
  [ "$ser" != "$ser2" ] && ok "serial monotonic ($ser -> $ser2)" || bad "serial did not advance"

  # slave：上游 named + also-notify；面板读从区文件（masterfile-format text）
  start_upstream || bad "upstream fixture start"
  post /api/dns/zones "{\"action\":\"add\",\"name\":\"slave.test\",\"kind\":\"slave\",\"primaries\":[\"127.0.0.1:$UP\"],\"axfr_acl\":[\"127.0.0.1\"],\"refresh_hours\":1}" >/dev/null
  local i
  for i in $(seq 1 20); do
    [ "$(digq www.slave.test A +short)" = "192.0.2.201" ] && break
    sleep 0.5
  done
  expect "slave AXFR transfer" "$(digq www.slave.test A +short)" '192\.0\.2\.201'
  expect "panel reads slave records" "$(api '/api/dns/records?zone=slave.test')" '"rtype":"A"'
  python3 - "$WORK/upstream/zones/slave.test.zone" <<'PY'
import sys
p=sys.argv[1]; s=open(p).read().replace('( 100 ', '( 101 ').replace('www IN A 192.0.2.201','www IN A 192.0.2.202')
open(p,'w').write(s.replace('ns1 IN A 127.0.0.1','ns1 IN A 127.0.0.1\nnew IN A 192.0.2.203'))
PY
  rndc -c "$WORK/upstream/rndc.conf" reload >/dev/null 2>&1
  for i in $(seq 1 20); do
    [ "$(digq www.slave.test A +short)" = "192.0.2.202" ] && break
    sleep 0.5
  done
  expect "slave NOTIFY + incremental" "$(digq www.slave.test A +short)" '192\.0\.2\.202'
  expect "slave new record" "$(digq new.slave.test A +short)" '192\.0\.2\.203'

  # root zone：AXFR 全量 + IXFR 增量 + 坏内容拒绝
  start_rootmaster || bad "rootmaster fixture start"
  python3 -m http.server "$HTTP_ROOT" --bind 127.0.0.1 --directory "$WORK/rootweb" >/dev/null 2>&1 & PIDS+=("$!")
  cp "$WORK/rootmaster/zones/root.zone" "$WORK/rootweb/root.zone"
  local cfg
  cfg=$(api /api/dns/config)
  cfg=$(printf '%s' "$cfg" | python3 -c 'import json,sys;d=json.load(sys.stdin);d["modes"]={"root":True,"recursive":False,"authoritative":False};d["rootzone"]["axfr_servers"]=["127.0.0.1:'"$ROOTM"'"];d["rootzone"]["url"]="http://127.0.0.1:'"$HTTP_ROOT"'/root.zone";d["rootzone"]["refresh_hours"]=24;d["rootzone"]["enabled"]=True;print(json.dumps(d))')
  post /api/dns/config "$cfg" >/dev/null
  sleep 1
  post /api/dns/rootzone '{"action":"refresh"}' >/dev/null
  sleep 1
  expect "root zone full AXFR" "$(digq . SOA +short)" '2026110100'
  python3 - "$WORK/rootmaster/zones/root.zone" <<'PY'
import sys
p=sys.argv[1]; s=open(p).read().replace('2026110100','2026110101').replace('n299.test. 3600 IN A 192.0.2.50','n299.test. 3600 IN A 192.0.2.99')
open(p,'w').write(s+'rootnew.test. 3600 IN A 192.0.2.123\n')
PY
  rndc -c "$WORK/rootmaster/rndc.conf" reload >/dev/null 2>&1
  post /api/dns/rootzone '{"action":"refresh"}' >/dev/null
  sleep 1
  expect "root zone IXFR/AXFR update" "$(digq . SOA +short)" '2026110101'
  expect "root zone new record" "$(digq rootnew.test A +short)" '192\.0\.2\.123'
  # 关掉 AXFR 源，强制走 HTTP 下载分支（否则 rootzone_refresh 会先走 IXFR 成功）
  cfg=$(api /api/dns/config)
  cfg=$(printf '%s' "$cfg" | python3 -c 'import json,sys;d=json.load(sys.stdin);d["rootzone"]["axfr_servers"]=[];print(json.dumps(d))')
  post /api/dns/config "$cfg" >/dev/null
  sleep 1
  echo garbage > "$WORK/rootweb/root.zone"
  local before after
  before=$(md5sum "$WORK/basic/zones/root.zone" | awk '{print $1}')
  local rr; rr=$(post /api/dns/rootzone '{"action":"refresh"}')
  after=$(md5sum "$WORK/basic/zones/root.zone" | awk '{print $1}')
  expect "root zone bad content rejected" "$rr" '"error"'
  [ "$before" = "$after" ] && ok "root.zone unchanged on bad content" || bad "root.zone was overwritten by bad content"
  expect "root zone no tmp leftovers" "$(find "$WORK/basic/zones" -name '*.tmp*' | wc -l)" '^0$'

  # 恢复权威模式（root zone 模式会抢走公共域名查询）
  post /api/dns/modes '{"root":false,"recursive":false,"authoritative":true,"enabled":true}' >/dev/null
  sleep 1
  expect "authoritative mode restored" "$(digq verify.test A +short)" '192\.0\.2\.10'

  # DoH h1/h2 + ECS 接收
  python3 "$CLIENT" build verify.test "$WORK/q.bin"
  local h2
  h2=$(curl -s -m 10 -o "$WORK/resp.bin" -w '%{http_code} %{http_version} %{content_type}' \
    --resolve "doh.test:$TLS:127.0.0.1" -k --http2 -H 'Content-Type: application/dns-message' \
    --data-binary @"$WORK/q.bin" "https://doh.test:$TLS/dns-query")
  expect "DoH h2 200 + dns-message" "$h2" '^200 2 '
  expect_json "DoH h2 answer" "$(python3 "$CLIENT" doh doh.test "$TLS" "$WORK/certs/doh-cert.pem" POST verify.test)" 'd.get("rcode")==0 and d.get("an",0)>=1'
  expect_json "DoH no-ECS response has no ECS" "$(python3 "$CLIENT" doh doh.test "$TLS" "$WORK/certs/doh-cert.pem" POST verify.test)" 'd.get("ecs")==[]'
  expect_json "DoH ECS query echoes scope 0" "$(python3 "$CLIENT" doh doh.test "$TLS" "$WORK/certs/doh-cert.pem" POST verify.test 1:203.0.113:24)" 'd.get("ecs") and d["ecs"][0]["source"]==24 and d["ecs"][0]["scope"]==0'
  expect "authoritative ECS receive (dig)" "$(digq verify.test A +subnet=203.0.113.0/24 +noall +comments)" 'CLIENT-SUBNET: 203\.0\.113\.0/24/0'

  # DoT + ECS
  wait_port "$DOT" || bad "DoT port $DOT not listening"
  expect_json "DoT answer" "$(python3 "$CLIENT" dot "$DOT" "$WORK/certs/dot-cert.pem" dot.test verify.test)" 'd.get("rcode")==0 and d.get("an",0)>=1'
  expect_json "DoT no-ECS response has no ECS" "$(python3 "$CLIENT" dot "$DOT" "$WORK/certs/dot-cert.pem" dot.test verify.test)" 'd.get("ecs")==[]'
  expect_json "DoT ECS echoes scope 0" "$(python3 "$CLIENT" dot "$DOT" "$WORK/certs/dot-cert.pem" dot.test verify.test 1:203.0.113:24)" 'd.get("ecs") and d["ecs"][0]["source"]==24'

  # ECS 发送（出站 wire）。**不能**再用 geo 把查询引到 127.0.0.2 上的伪上游：
  # 测试模式现在也会让 named 监听 127.0.0.(2+i)（否则 geo 线路上的 DoT/DoH 会
  # ICMP 不可达），且 BIND 9.20 在递归/转发时会丢弃未知 EDNS option（ECS 到不了
  # 真实上游 —— 见报告里的负控）。这里验证的是**本进程 DoT/DoH 层注入的 ECS**：
  # 停掉 named，让伪上游直接占用 `[dns] port`，DoT/DoH 的转发目标就是它。
  rndc -c "$WORK/basic/etc/rndc.conf" stop >/dev/null 2>&1 || true
  for i in $(seq 1 40); do port_free "$DNS" && break; sleep 0.25; done
  python3 "$CLIENT" fake 127.0.0.1 "$DNS" "$WORK/ecs-capture.log" >/dev/null 2>&1 & PIDS+=("$!")
  sleep 1
  python3 "$CLIENT" doh doh.test "$TLS" "$WORK/certs/doh-cert.pem" POST verify.test 1:203.0.113:24 >/dev/null 2>&1
  python3 "$CLIENT" dot "$DOT" "$WORK/certs/dot-cert.pem" dot.test verify.test 1:203.0.113:24 >/dev/null 2>&1
  sleep 1
  for p in $(pgrep -f "dns_verify_client.py fake" 2>/dev/null || true); do kill "$p" 2>/dev/null || true; done
  local captured
  captured=$(python3 "$CLIENT" decode "$WORK/ecs-capture.log")
  [ "$(printf '%s\n' "$captured" | grep -c '"ecs": \[{"family": 1, "source": 24')" -ge 2 ] \
    && ok "ECS injected for DoH+DoT (injector wire capture /24)" \
    || bad "ECS injection capture: $captured"
  # 拉起 named（面板 reload 走 reconcile）
  post /api/dns/reload '{}' >/dev/null
  for i in $(seq 1 40); do
    api /api/dns/status | grep -q '"named_running":true' && break; sleep 0.25
  done
  expect "named restored after ECS injector test" "$(api /api/dns/status)" '"named_running":true'

  # 递归模式 + ACL
  post /api/dns/forwarders "{\"forwarders\":[\"127.0.0.1:$UP\"],\"forward_policy\":\"only\"}" >/dev/null
  post /api/dns/modes '{"root":false,"recursive":true,"authoritative":false,"enabled":true}' >/dev/null
  sleep 1
  expect "recursive forwarders port rendered" "$(cat "$WORK/basic/etc/named.conf")" "forwarders \\{ 127\\.0\\.0\\.1 port $UP; \\}"
  expect "recursive non-ACL REFUSED" "$(dig -b 127.0.0.2 @127.0.0.1 -p "$DNS" www.slave.test A +time=5 +tries=1)" 'status: REFUSED'
  post /api/dns/modes '{"root":false,"recursive":false,"authoritative":true,"enabled":true}' >/dev/null

  stop_server basic
}

# ---------------------------------------------------------------- Stage B DNSSEC
stage_b() {
  echo "===== Stage B: DNSSEC KASP / NSEC3 / CDS / keygen / dnssec-signzone / rotation ====="
  local extra='[dns.dnssec]
enabled = true
algorithm = "ECDSAP256SHA256"
rotation_enabled = true
rotation_days = 30
ksk_lifetime_days = 365
nsec3 = true
nsec3_iterations = 0
nsec3_optout = false
cds = true'
  write_base_config dnssec "$extra" "$WORK/certs/dot-cert.pem" "$WORK/certs/dot-key.pem" ""
  mkdir -p "$WORK/dnssec"
  start_server dnssec || return 1
  post /api/dns/zones '{"action":"add","name":"signed.test","kind":"master"}' >/dev/null
  post /api/dns/records '{"zone":"signed.test","name":"@","rtype":"A","ttl":300,"rdata":"192.0.2.10"}' >/dev/null
  post /api/dns/records '{"zone":"signed.test","name":"www","rtype":"A","ttl":300,"rdata":"192.0.2.11"}' >/dev/null
  local i
  for i in $(seq 1 30); do
    [ "$(digq signed.test DNSKEY +noall +answer | wc -l)" -ge 2 ] && break
    sleep 0.5
  done
  expect "KASP auto keys (>=2 DNSKEY)" "$(digq signed.test DNSKEY +noall +answer | wc -l | tr -d ' ')" '^[2-9]$'
  expect "RRSIG" "$(digq www.signed.test A +dnssec +noall +answer)" 'RRSIG.*A 13'
  expect "NSEC3PARAM" "$(digq signed.test NSEC3PARAM +noall +answer)" 'NSEC3PARAM 1 0 0'
  expect "NXDOMAIN NSEC3 proof" "$(digq nope.signed.test A +dnssec +noall +authority)" 'NSEC3'

  # CDS/CDNSKEY：默认 PublishCDS 在 +1d；把 KSK state 的 PublishCDS 拨到过去并 loadkeys
  local ksk
  ksk=$(grep -l 'KSK: yes' "$WORK/dnssec/keys"/*.state | head -1)
  [ -n "$ksk" ] && sed -i 's/^PublishCDS: .*/PublishCDS: 20260101000000 (Thu Jan  1 00:00:00 2026)/; s/^DSState: hidden/DSState: rumoured/' "$ksk"
  rndc -c "$WORK/dnssec/etc/rndc.conf" loadkeys signed.test >/dev/null 2>&1
  sleep 2
  expect "CDS published" "$(digq signed.test CDS +noall +answer)" 'CDS'
  expect "CDNSKEY published" "$(digq signed.test CDNSKEY +noall +answer)" 'CDNSKEY'
  # dnssec-dsfromkey 会在**当前目录**写 dsset-<zone>. 文件：在 $WORK 下跑，
  # 否则每轮验证都会往仓库根丢一个未跟踪文件（本波真机跑出现过 dsset-signed.test.）。
  expect "DS from KSK" "$(cd "$WORK" && dnssec-dsfromkey -2 "${ksk%.state}.key")" 'IN DS'

  # keygen API：zsk（ECDSAP256SHA256）→ loadkeys → DNSKEY 增加
  local before after kg
  before=$(digq signed.test DNSKEY +noall +answer | wc -l)
  kg=$(post /api/dns/dnssec '{"action":"keygen","zone":"signed.test","role":"zsk","algorithm":"ECDSAP256SHA256"}')
  expect "keygen zsk" "$kg" '"ok":true'
  rndc -c "$WORK/dnssec/etc/rndc.conf" loadkeys signed.test >/dev/null 2>&1
  sleep 2
  after=$(digq signed.test DNSKEY +noall +answer | wc -l)
  [ "$after" -gt "$before" ] && ok "generated key published ($before -> $after)" || bad "generated key not published ($before -> $after)"

  # dnssec-signzone：用仓库生成的 zone 文本 + 外部 KSK/ZSK 签名并验证
  local zf
  zf=$(ls "$WORK/dnssec/zones"/signed_test.*.zone | head -1)
  cp "$zf" "$WORK/signwork/signed.test.zone"
  dnssec-keygen -K "$WORK/signkeys" -a ECDSAP256SHA256 -f KSK signed.test >/dev/null 2>&1
  dnssec-keygen -K "$WORK/signkeys" -a ECDSAP256SHA256 signed.test >/dev/null 2>&1
  expect "dnssec-signzone fully signs" "$(dnssec-signzone -S -3 - -K "$WORK/signkeys" -o signed.test -f "$WORK/signwork/signed.test.signed" "$WORK/signwork/signed.test.zone" 2>&1)" 'Zone fully signed'
  expect "dnssec-verify OK" "$(dnssec-verify -o signed.test "$WORK/signwork/signed.test.signed" 2>&1)" 'Zone fully signed'
  expect "signed file has RRSIG/NSEC3" "$(grep -cE 'RRSIG|NSEC3' "$WORK/signwork/signed.test.signed")" '^[1-9][0-9]*$'

  # 轮换：把 ZSK Active 拨到 2026-08-01（age > 30d-7d），等维护循环（<=35s），
  # 同时持续查询验证无中断。
  python3 - "$WORK/dnssec/keys" <<'PY'
import glob,re,sys
for p in glob.glob(sys.argv[1]+'/Ksigned.test.+013+*.state'):
    s=open(p).read()
    if 'ZSK: yes' in s:
        open(p,'w').write(re.sub(r'^Active: \d{14}','Active: 20260801000000',s,flags=re.M))
PY
  python3 - "$DNS" "$WORK/qloop.out" <<'PY' &
import socket,struct,sys,time
sys.path.insert(0,'.')
# 直接构造 A 查询 www.signed.test
port=int(sys.argv[1]); out=sys.argv[2]
q=bytes.fromhex('12340100000100000000000003777777067369676e656404746573740000010001')
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(2)
bad=0; n=0
t0=time.time()
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
  sleep 40
  expect "rotation generated replacement" "$(cat "$WORK/dnssec/server.log")" 'generated new (ZSK|CSK)'
  expect "rotation query loop no SERVFAIL/timeouts" "$(cat "$WORK/qloop.out" 2>/dev/null)" 'bad=0'
  expect "DNSKEY count after rotation" "$(digq signed.test DNSKEY +noall +answer | wc -l | tr -d ' ')" '^[3-9]$'

  # 自定义私钥导入
  local ck
  ck=$(dnssec-keygen -K "$WORK/signkeys" -a ECDSAP256SHA256 -f KSK custom.test 2>/dev/null | tail -1)
  post /api/dns/zones '{"action":"add","name":"custom.test","kind":"master"}' >/dev/null
  for ext in key private; do
    local f="$ck.$ext" b
    b=$(base64 -w0 "$WORK/signkeys/$f" 2>/dev/null || base64 < "$WORK/signkeys/$f")
    expect "upload custom.$ext" "$(post /api/dns/dnssec "{\"action\":\"upload\",\"filename\":\"$f\",\"b64\":\"$b\"}")" '"ok":true'
  done
  expect "custom private key 0600" "$(stat -c %a "$WORK/dnssec/keys/$ck.private" 2>/dev/null)" '^600$'
  rndc -c "$WORK/dnssec/etc/rndc.conf" loadkeys custom.test >/dev/null 2>&1
  sleep 1
  expect "custom key published" "$(digq custom.test DNSKEY +noall +answer | wc -l | tr -d ' ')" '^[1-9]'

  stop_server dnssec
}

# ---------------------------------------------------------------- Stage C ACME
stage_c() {
  echo "===== Stage C: pebble ACME 签发 / 落盘 / DoT / 续期 / 失败可定位 ====="
  if ! need pebble || ! need pebble-challtestsrv || ! need acme.sh; then
    skip "ACME：缺 pebble/pebble-challtestsrv/acme.sh（aptlocal.sh install-deps pebble acme.sh）"
    return 0
  fi
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
    -keyout "$WORK/certs/pebble-key.pem" -out "$WORK/certs/pebble-cert.pem" >/dev/null 2>&1
  cat > "$WORK/pebble-config.json" <<EOF
{"pebble":{"listenAddress":"127.0.0.1:$PEBBLE","managementListenAddress":"127.0.0.1:$PEBBLE_MGMT",
"certificate":"$WORK/certs/pebble-cert.pem","privateKey":"$WORK/certs/pebble-key.pem",
"httpPort":$ACME_HTTP,"tlsPort":$((ACME_HTTP - 1)),"ocspResponderURL":"",
"externalAccountBindingRequired":false,"certificateValidityPeriod":7776000}}
EOF
  pebble-challtestsrv -dns01 "127.0.0.1:$CHALL_DNS" -http01 "" -https01 "" -tlsalpn01 "" -doh "" \
    -management "127.0.0.1:$((CHALL_DNS + 1))" -defaultIPv4 127.0.0.1 > "$WORK/challtestsrv.log" 2>&1 &
  PIDS+=("$!")
  sleep 1
  PEBBLE_VA_NOSLEEP=1 pebble -config "$WORK/pebble-config.json" -dnsserver "127.0.0.1:$CHALL_DNS" -strict=false \
    > "$WORK/pebble.log" 2>&1 &
  PIDS+=("$!")
  sleep 2
  curl -sk "https://127.0.0.1:$PEBBLE_MGMT/roots/0" > "$WORK/certs/pebble-root.pem" || { bad "pebble root fetch"; return 0; }
  mkdir -p "$WORK/home/.acme.sh"
  cp -L "$(command -v acme.sh)" "$WORK/home/.acme.sh/acme.sh"
  chmod +x "$WORK/home/.acme.sh/acme.sh"
  cat > "$WORK/acme-extra" <<EOF
[dns.acme]
enabled = true
domain = "acme.crucible.test"
email = "admin@example.com"
renew_days = 60
server = "https://127.0.0.1:$PEBBLE/dir"
insecure = true
http_port = $ACME_HTTP
EOF
  write_base_config acme "" "acme:acme.crucible.test" "acme:acme.crucible.test" "$(cat "$WORK/acme-extra")"
  mkdir -p "$WORK/acme"
  start_server acme || return 1
  post /api/dns/zones '{"action":"add","name":"crucible.test","kind":"master"}' >/dev/null
  post /api/dns/records '{"zone":"crucible.test","name":"acme","rtype":"A","ttl":300,"rdata":"192.0.2.50"}' >/dev/null
  local i cert
  cert="$WORK/acme/acme/acme.crucible.test/fullchain.pem"
  for i in $(seq 1 60); do
    [ -s "$cert" ] && break
    sleep 0.5
  done
  [ -s "$cert" ] && ok "ACME first issuance installed" || bad "ACME first issuance (log: $(tail -3 "$WORK/acme/server.log"))"
  expect "ACME status issued" "$(api /api/dns/acme)" '"issued":true'
  expect "pebble issued cert" "$(cat "$WORK/pebble.log")" 'Issued certificate'
  expect "fullchain has leaf+intermediate" "$(grep -c 'BEGIN CERTIFICATE' "$cert")" '^2$'
  # ACME 签发完成后 DoT supervisor 在 1s 内 bind；等端口真的在听
  wait_port "$DOT" || bad "DoT port $DOT not listening after ACME"
  expect_json "DoT with pebble cert verified" "$(python3 "$CLIENT" dot "$DOT" "$WORK/certs/pebble-root.pem" acme.crucible.test acme.crucible.test)" 'd.get("rcode")==0 and d.get("peer_issuer") is not None'
  local ser1
  ser1=$(openssl x509 -in "$cert" -noout -serial)
  # 续期：把已装证书换成 10 天自签（<30 天阈值），删 acme.sh 域名缓存 → 面板立即签发
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 10 \
    -subj "/CN=acme.crucible.test" -addext "subjectAltName=DNS:acme.crucible.test" \
    -keyout "$WORK/certs/short-key.pem" -out "$WORK/certs/short.pem" >/dev/null 2>&1
  cp "$WORK/certs/short.pem" "$cert"; cp "$WORK/certs/short-key.pem" "$WORK/acme/acme/acme.crucible.test/privkey.pem"
  rm -rf "$WORK/home/.acme.sh/acme.crucible.test_ecc"
  expect "ACME renewal via panel" "$(post /api/dns/acme/issue '{}')" '"ok":true'
  local ser2
  ser2=$(openssl x509 -in "$cert" -noout -serial)
  [ "$ser1" != "$ser2" ] && ok "renewal replaced cert ($ser1 -> $ser2)" || bad "renewal did not replace cert"
  expect "DoT serves renewed cert" "$(openssl s_client -connect "127.0.0.1:$DOT" -servername acme.crucible.test -CAfile "$WORK/certs/pebble-root.pem" </dev/null 2>/dev/null | openssl x509 -noout -serial 2>/dev/null)" "$ser2"
  # 失败路径：停 pebble → 面板签发失败、错误可定位、旧证书不被破坏
  for p in $(pgrep -f "pebble -config $WORK/pebble-config.json" 2>/dev/null || true); do kill "$p" 2>/dev/null || true; done
  sleep 1
  cp "$WORK/certs/short.pem" "$cert"; rm -rf "$WORK/home/.acme.sh/acme.crucible.test_ecc"
  local failout
  failout=$(post_long /api/dns/acme/issue '{}')
  expect "ACME failure reported to panel" "$failout" '"error".*ACME 客户端'
  expect "ACME failure leaves cert intact" "$(openssl x509 -in "$cert" -noout -serial)" "$(openssl x509 -in "$WORK/certs/short.pem" -noout -serial)"
  expect "ACME failure logged (可定位)" "$(cat "$WORK/acme/server.log")" 'acme\.sh --issue 退出失败|ACME 客户端已找到但执行失败'
  stop_server acme
}

# ---------------------------------------------------------------- Stage D geo（netns）
# 分线路的 fwd view 依赖 named 在 127.0.0.(2+i) 上真的有 socket。Linux 上这些地址
# 不是 `ip addr` 列出的接口地址，BIND 会**静默跳过**（真机：named.conf 写了
# 127.0.0.2，`ss` 里只有 127.0.0.1）；OpenBSD 由 reconcile 里的 ifconfig alias 补。
# 因此本机验证在 user+net namespace 里补 alias 后跑完整链路（named → fwd view）。
stage_d_geo() {
  echo "===== Stage D: geo 分线路（named view 端到端，netns） ====="
  if ! need unshare || ! need ip || ! unshare -Urn true 2>/dev/null; then
    skip "geo netns：unshare -Urn / ip 不可用（生产 OpenBSD 用 ifconfig lo0 alias，见报告）"
    return 0
  fi
  cat > "$WORK/netns-geo.sh" <<EOS
#!/bin/bash
set -u
ip link set lo up
for i in 2 3 4; do ip addr add 127.0.0.\$i/32 dev lo 2>/dev/null || true; done
export PATH=/home/dev123/local/usr/bin:/home/dev123/local/usr/sbin:\$PATH
export LD_LIBRARY_PATH=/home/dev123/local/usr/lib/x86_64-linux-gnu:/home/dev123/local/usr/lib\${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}
T="$WORK/netns"; mkdir -p \$T/{www,www-tls,home,state}
API=http://127.0.0.1:25595/__admin
post(){ curl -s -u admin:admin -H 'Content-Type: application/json' -d "\$2" "\$API\$1"; echo; }
cat > \$T/cfg.toml <<EOF
[access_log]
enable = false
[admin]
realm = "dnsbind"
path = "/__admin"
[[admin.users]]
username = "admin"
password_hash = "\\\$argon2id\\\$v=19\\\$m=19456,t=2,p=1\\\$E/RLobwgix2BWMRMT++urA\\\$yEympjJtiDh0ezwSQsnkbsfYAoSzeDAHYw3EsUMBsj4"
[dns]
enabled = true
listen_addr = "127.0.0.1"
port = 25553
rndc_port = 25953
test_mode = true
recursion_acl = ["127.0.0.0/8"]
axfr_out_acl = ["127.0.0.1"]
[dns.modes]
root = false
recursive = false
authoritative = true
[dns.dot]
enabled = true
port = 25555
cert = "$WORK/certs/dot-cert.pem"
key = "$WORK/certs/dot-key.pem"
allow = ["127.0.0.0/8"]
rate_per_sec = 1000
burst = 1000
[[listeners]]
address = "127.0.0.1"
port = 25595
root = "\$T/www"
http_versions = ["h1"]
EOF
CRUCIBLE_DNS_STATE_ROOT=\$T/state HOME=\$T/home CRUCIBLE_NAMED_USER= "$BIN" --config \$T/cfg.toml > \$T/server.log 2>&1 &
SP=\$!
trap 'kill \$SP 2>/dev/null; rndc -c \$T/state/etc/rndc.conf stop >/dev/null 2>&1 || true' EXIT
for i in \$(seq 1 40); do curl -sf -m 1 -u admin:admin \$API/api/dns/status >/dev/null && break; sleep 0.5; done
post /api/dns/zones '{"action":"add","name":"geo.test","kind":"master"}' >/dev/null
# 运行时启用 geo：必须触发 named 重启并 bind 127.0.0.2/.3
post /api/dns/geo '{"geo":{"enabled":true,"lines":[{"name":"l0","cidrs":["127.0.0.1/32"]},{"name":"l1","cidrs":["127.0.0.3/32"]}]}}' >/dev/null
for i in \$(seq 1 30); do grep -q "restarting named" \$T/server.log && break; sleep 0.5; done
sleep 6
got=\$(ss -lunp 2>/dev/null | grep 25553 | awk '{print \$4}' | sort -u | tr '\n' ' ')
case "\$got" in *127.0.0.2:25553*) echo "PASS: geo named binds 127.0.0.2";; *) echo "FAIL: geo listeners: \$got";; esac
case "\$got" in *127.0.0.3:25553*) echo "PASS: geo named binds 127.0.0.3";; *) echo "FAIL: geo listeners: \$got";; esac
post /api/dns/records '{"zone":"geo.test","name":"www","rtype":"A","ttl":300,"rdata":"192.0.2.10","line":"l0"}' >/dev/null
post /api/dns/records '{"zone":"geo.test","name":"www","rtype":"A","ttl":300,"rdata":"192.0.2.11","line":"l1"}' >/dev/null
post /api/dns/records '{"zone":"geo.test","name":"www","rtype":"A","ttl":300,"rdata":"192.0.2.99"}' >/dev/null
a1=\$(dig -b 127.0.0.1 @127.0.0.1 -p 25553 www.geo.test A +short +time=3 +tries=1)
a2=\$(dig -b 127.0.0.3 @127.0.0.1 -p 25553 www.geo.test A +short +time=3 +tries=1)
a3=\$(dig -b 127.0.0.4 @127.0.0.1 -p 25553 www.geo.test A +short +time=3 +tries=1)
[ "\$a1" = "192.0.2.10" ] && echo "PASS: view l0 (.1) -> \$a1" || echo "FAIL: view l0 (.1) -> \$a1"
[ "\$a2" = "192.0.2.11" ] && echo "PASS: view l1 (.3) -> \$a2" || echo "FAIL: view l1 (.3) -> \$a2"
[ "\$a3" = "192.0.2.99" ] && echo "PASS: default (.4) -> \$a3" || echo "FAIL: default (.4) -> \$a3"
# DoT .1（源地址即 peer IP）走 fwd-l0
python3 "$CLIENT" dot 25555 "$WORK/certs/dot-cert.pem" dot.test www.geo.test > "\$T/dot1.json" 2>&1
grep -q '"c000020a"' "\$T/dot1.json" && echo "PASS: DoT .1 -> 192.0.2.10" || echo "FAIL: DoT .1: \$(cat \$T/dot1.json)"
# DoT .3 需要源地址绑定
python3 - <<'PY' > "\$T/dot3.json" 2>&1
import socket,ssl,struct,sys
sys.path.insert(0,'$ROOT/scripts')
import dns_verify_client as c
w=c.build_query('www.geo.test')
s=socket.socket(); s.bind(('127.0.0.3',0)); s.settimeout(5); s.connect(('127.0.0.1',25555))
ctx=ssl._create_unverified_context(); t=ctx.wrap_socket(s,server_hostname='dot.test')
t.sendall(struct.pack('>H',len(w))+w)
h=t.recv(2); n=struct.unpack('>H',h)[0]; d=b''
while len(d)<n: d+=t.recv(n-len(d))
t.close(); print(c.parse(d))
PY
grep -q 'c000020b' "\$T/dot3.json" && echo "PASS: DoT .3 -> 192.0.2.11" || echo "FAIL: DoT .3: \$(cat \$T/dot3.json)"
EOS
  chmod +x "$WORK/netns-geo.sh"
  if ! unshare -Urn bash "$WORK/netns-geo.sh" > "$WORK/netns-geo.log" 2>&1; then
    bad "geo netns e2e 运行失败（见 $WORK/netns-geo.log）"
  elif grep -q '^FAIL' "$WORK/netns-geo.log"; then
    bad "geo netns e2e（见 $WORK/netns-geo.log）"
  else
    ok "geo netns e2e（named l0/l1/default + DoT 源地址分流）"
  fi
  sed -n '1,20p' "$WORK/netns-geo.log" | sed 's/^/  /'
}

# ---------------------------------------------------------------- main
preflight
mkcerts
stage_a || true
stage_b || true
stage_c || true
stage_d_geo || true
echo "=================================================================="
echo "DNS real-machine verification: PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
if [ "${DNSV_KEEP:-0}" = "1" ]; then echo "work dir kept: $WORK"; else echo "work dir: $WORK (removed on exit)"; fi
[ "$FAIL" -eq 0 ]
