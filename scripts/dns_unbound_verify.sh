#!/usr/bin/env bash
# Unbound 递归后端真机验证（G-01：ECS 端到端）。
#
# 一条命令：
#   scripts/dns_verify.sh --real unbound
# 或直接：
#   scripts/dns_unbound_verify.sh
#
# 验证内容：
#   A. unbound 模式
#      - dns::reconcile 生成 unbound.conf 并拉起 Unbound（主端口）+ BIND（内部权威端口）
#      - DoT/DoH → Unbound → 伪上游：上游必须看到客户端 ECS（family/source/address）
#      - 反向：ecs=false 时上游看不到 ECS、应答不带 ECS
#      - 权威区（A/AAAA/MX/TXT/SRV/CAA/NS/SOA）经主端口（auth-zone 镜像）可查
#      - 递归 ACL：127.0.0.2 递归 REFUSED、权威仍可查；127.0.0.1 递归可用
#      - 缓存：同一查询第二次不再打上游
#      - 畸形 ECS → FORMERR 且不转发上游
#      - RPZ override（nxdomain + A）经主端口生效
#      - DNSSEC：BIND 内部权威端口有 DNSKEY/RRSIG/NSEC3（KASP 仍由 BIND 负责）
#      - 面板加记录后 auth-zone 热载（无需重启 unbound）
#   B. bind 模式负控（同一条链路）
#      - DoT 带 ECS → 本机 BIND 递归 → 伪上游；上游只看到 COOKIE，**没有 ECS**
#
# 环境（无需 root）：
#   - unbound / unbound-checkconf / unbound-control / unbound-control-setup
#     （/home/dev123/bin/aptlocal.sh install-deps unbound）
#   - named/rndc/dig/dnssec-*（aptlocal.sh install-deps bind9 bind9-utils bind9-dnsutils）
#   - python3、curl、openssl；已构建 webserver（DNSV_BIN 或 $CARGO_TARGET_DIR/release/webserver）
#
# 端口从 DNSV_UNBOUND_BASE（默认 42000）派生；退出时清理本脚本拉起的全部进程。
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BASE=${DNSV_UNBOUND_BASE:-42000}
U=$((BASE + 53))        # unbound 主端口
A=$((BASE + 54))        # BIND 内部权威端口
C=$((BASE + 55))        # unbound-control
RNDC=$((BASE + 453))
WEB=$((BASE + 95))
TLS=$((BASE + 43))
DOT=$((BASE + 353))
UP=$((BASE + 64))       # 伪上游（UDP）
BM=$((BASE + 160))      # bind 负控：主端口
BR=$((BASE + 460))      # bind 负控：rndc
BW=$((BASE + 196))      # bind 负控：web
BT=$((BASE + 144))      # bind 负控：TLS
BD=$((BASE + 354))      # bind 负控：DoT
WORK=${DNSV_DIR:-${TMPDIR:-/tmp}/dns-unbound-verify-$$}
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
  for st in ub bind; do
    [ -f "$WORK/$st/run/unbound.pid" ] && kill "$(cat "$WORK/$st/run/unbound.pid")" 2>/dev/null || true
    for p in $(pgrep -f "named -c $WORK/$st/etc/named.conf" 2>/dev/null || true); do
      kill "$p" 2>/dev/null || true
    done
  done
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

api() { curl -s -m 60 -u "$AUTH" "http://127.0.0.1:$1/__admin$2"; }
post() { curl -s -m 90 -u "$AUTH" -H 'Content-Type: application/json' -d "${3:-}" "http://127.0.0.1:$1/__admin$2"; }
postj() { local data=${4:-$3}; curl -s -m 90 -u "$AUTH" -H 'Content-Type: application/json' -d "$data" "http://127.0.0.1:$1/__admin$2"; }
jget() { python3 -c 'import json,sys;d=json.load(sys.stdin);print(eval(sys.argv[1]))' "$1" 2>/dev/null; }
digq() { local name=$1 port=$2; shift 2; dig @127.0.0.1 -p "$port" "$name" "$@" +time=5 +tries=1; }
expect() {
  if printf '%s' "$2" | grep -qE -- "$3"; then ok "$1"; else bad "$1（got: $(printf '%s' "$2" | head -c 200)）"; fi
}
expect_json() {
  if [ "$(printf '%s' "$2" | jget "$3")" = "True" ]; then ok "$1"; else bad "$1（json: $(printf '%s' "$2" | head -c 240)）"; fi
}
fake_count() {
  if [ -f "$WORK/fake.log" ]; then grep -vc '^START' "$WORK/fake.log" 2>/dev/null || true; else echo 0; fi
}
# decode_capture <from_line> <to_line>：输出新增上行查询的 JSON（qname/ecs）
decode_capture() {
  python3 - "$WORK/fake.log" "$1" "$2" "$ROOT/scripts" <<'PY'
import json,os,sys
sys.path.insert(0,sys.argv[4])
import dns_verify_client as c
path,a,b=sys.argv[1],int(sys.argv[2]),int(sys.argv[3])
lines=[l.strip() for l in open(path) if l.strip() and not l.startswith('START')]
for l in lines[a:b]:
    r=c.parse(bytes.fromhex(l))
    print(json.dumps({"qname":r["qname"],"ecs":r["ecs"]}))
PY
}
# capture_has_ecs <from> <to> <address_hex>：至少一条新增查询带该 ECS
capture_has_ecs() {
  decode_capture "$1" "$2" | python3 -c '
import json,sys
want=sys.argv[1]
for line in sys.stdin:
    r=json.loads(line)
    for e in r.get("ecs",[]):
        if e.get("family")==1 and e.get("source")==24 and e.get("address")==want:
            raise SystemExit(0)
raise SystemExit(1)
' "$3"
}
capture_all_no_ecs() {
  decode_capture "$1" "$2" | python3 -c '
import json,sys
n=0
for line in sys.stdin:
    r=json.loads(line); n+=1
    if r.get("ecs"): raise SystemExit(1)
raise SystemExit(0 if n>0 else 1)
'
}
wait_api() {
  local i
  for i in $(seq 1 80); do
    curl -sf -m 1 -u "$AUTH" "http://127.0.0.1:$1/__admin/api/dns/status" >/dev/null 2>&1 && return 0
    sleep 0.5
  done
  return 1
}
wait_port() {
  local i
  for i in $(seq 1 40); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; then exec 3>&- 3<&-; return 0; fi
    sleep 0.5
  done
  return 1
}

preflight() {
  local missing=()
  for t in unbound unbound-checkconf unbound-control unbound-control-setup \
           named rndc dig dnssec-keygen python3 curl openssl; do
    need "$t" || missing+=("$t")
  done
  if [ ${#missing[@]} -gt 0 ]; then
    echo "FATAL: missing tools: ${missing[*]}" >&2
    echo "  install: /home/dev123/bin/aptlocal.sh install-deps unbound" >&2
    echo "           /home/dev123/bin/aptlocal.sh install-deps bind9 bind9-utils bind9-dnsutils" >&2
    exit 2
  fi
  [ -x "$BIN" ] || {
    echo "FATAL: webserver binary not found/executable: $BIN" >&2
    exit 2
  }
  local p
  for p in "$U" "$A" "$C" "$RNDC" "$WEB" "$TLS" "$DOT" "$UP" "$BM" "$BR" "$BW" "$BT" "$BD"; do
    if ! port_free "$p"; then echo "FATAL: port $p is in use（用 DNSV_UNBOUND_BASE 换一段）" >&2; exit 2; fi
  done
  echo "tools: $(unbound -V 2>&1 | head -1) / $(named -v | head -1)"
  echo "binary: $BIN ($(stat -c %s "$BIN" 2>/dev/null || echo '?') bytes)"
  echo "ports: unbound=$U auth=$A control=$C web=$WEB dot=$DOT fake=$UP bind-neg=$BM"
}

mkcerts() {
  mkdir -p "$WORK/certs"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
    -subj "/CN=doh.test" -addext "subjectAltName=DNS:doh.test,DNS:crucible.local,IP:127.0.0.1" \
    -keyout "$WORK/certs/doh-key.pem" -out "$WORK/certs/doh-cert.pem" >/dev/null 2>&1
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
    -subj "/CN=dot.test" -addext "subjectAltName=DNS:dot.test,IP:127.0.0.1" \
    -keyout "$WORK/certs/dot-key.pem" -out "$WORK/certs/dot-cert.pem" >/dev/null 2>&1
}

# write_cfg <name> <main> <rndc> <web> <tls> <dot> <recursor-block>
write_cfg() {
  local st=$1 main=$2 rndc=$3 web=$4 tls=$5 dot=$6 extra=$7
  mkdir -p "$WORK/$st"
  cat > "$WORK/cfg-$st.toml" <<EOF
[access_log]
enable = false
[admin]
realm = "dns-ub"
path = "/__admin"
[[admin.users]]
username = "admin"
password_hash = "\$argon2id\$v=19\$m=19456,t=2,p=1\$E/RLobwgix2BWMRMT++urA\$yEympjJtiDh0ezwSQsnkbsfYAoSzeDAHYw3EsUMBsj4"
[dns]
enabled = true
listen_addr = "127.0.0.1"
port = $main
rndc_port = $rndc
test_mode = true
recursion_acl = ["127.0.0.1"]
axfr_out_acl = ["127.0.0.1"]
ecs = true
forwarders = ["127.0.0.1:$UP"]
forward_policy = "only"
$extra
[dns.modes]
root = false
recursive = true
authoritative = true
[dns.doh]
enabled = true
path = "/dns-query"
hostnames = ["doh.test"]
[dns.dot]
enabled = true
port = $dot
cert = "$WORK/certs/dot-cert.pem"
key = "$WORK/certs/dot-key.pem"
allow = ["127.0.0.1"]
rate_per_sec = 1000
burst = 1000
[[listeners]]
address = "127.0.0.1"
port = $web
root = "$WORK/$st/www"
http_versions = ["h1", "h2"]
server_name = "crucible.local"
[[listeners]]
address = "127.0.0.1"
port = $tls
root = "$WORK/$st/www-tls"
http_versions = ["h1", "h2"]
server_name = "doh.test"
[listeners.ssl]
cert = "$WORK/certs/doh-cert.pem"
key = "$WORK/certs/doh-key.pem"
EOF
  mkdir -p "$WORK/$st/www" "$WORK/$st/www-tls"
}

start_server() {
  local st=$1
  env CRUCIBLE_DNS_STATE_ROOT="$WORK/$st" HOME="$WORK/$st/home" CRUCIBLE_NAMED_USER= \
    "$BIN" --config "$WORK/cfg-$st.toml" > "$WORK/$st/server.log" 2>&1 &
  echo $! > "$WORK/$st/server.pid"
  PIDS+=("$!")
}
stop_server() {
  local st=$1
  [ -f "$WORK/$st/server.pid" ] && kill "$(cat "$WORK/$st/server.pid")" 2>/dev/null || true
  sleep 0.5
}

# ---------------------------------------------------------------- Stage U
stage_unbound() {
  echo "===== Stage U: Unbound 递归后端 + ECS 端到端 ====="
  local extra
  extra=$(cat <<EOF
recursor = "unbound"
[dns.unbound]
auth_port = $A
control_port = $C
EOF
)
  write_cfg ub "$U" "$RNDC" "$WEB" "$TLS" "$DOT" "$extra"
  start_server ub
  if ! wait_api "$WEB"; then
    bad "server (ub) did not become ready"
    tail -20 "$WORK/ub/server.log" | sed 's/^/  /'
    return 1
  fi
  local st
  st=$(api "$WEB" /api/dns/status)
  expect "status recursor=unbound" "$st" '"recursor":"unbound"'
  expect "status named_running" "$st" '"named_running":true'
  expect "status unbound_running" "$st" '"unbound_running":true'
  expect "status named_port=main+1" "$st" "\"named_port\":$A"
  expect "unbound.conf send-client-subnet" "$(cat "$WORK/ub/etc/unbound.conf")" "send-client-subnet: 127\\.0\\.0\\.1"
  expect "unbound.conf subnetcache module" "$(cat "$WORK/ub/etc/unbound.conf")" 'module-config: "subnetcache iterator"'
  expect "unbound.conf forward-zone upstream" "$(cat "$WORK/ub/etc/unbound.conf")" "forward-addr: 127\\.0\\.0\\.1@$UP"
  expect "unbound-control status" "$(unbound-control -c "$WORK/ub/etc/unbound.conf" status 2>&1)" 'is running'

  # 权威区（经 Unbound 的 auth-zone 镜像）
  post "$WEB" /api/dns/zones '{"action":"add","name":"verify.test","kind":"master"}' >/dev/null
  local r
  for r in \
    '{"zone":"verify.test","name":"@","rtype":"A","ttl":300,"rdata":"192.0.2.10"}' \
    '{"zone":"verify.test","name":"@","rtype":"AAAA","ttl":300,"rdata":"2001:db8::10"}' \
    '{"zone":"verify.test","name":"@","rtype":"MX","ttl":300,"rdata":"10 mail.verify.test."}' \
    '{"zone":"verify.test","name":"@","rtype":"TXT","ttl":300,"rdata":"v=spf1 -all"}' \
    '{"zone":"verify.test","name":"_sip._tcp","rtype":"SRV","ttl":300,"rdata":"10 20 5060 sip.verify.test."}' \
    '{"zone":"verify.test","name":"@","rtype":"CAA","ttl":300,"rdata":"0 issue \"letsencrypt.org\""}'; do
    post "$WEB" /api/dns/records "$r" >/dev/null
  done
  sleep 2
  expect "auth-zone in unbound.conf" "$(cat "$WORK/ub/etc/unbound.conf")" 'auth-zone:'
  expect "A via unbound" "$(digq verify.test "$U" A +short)" '^192\.0\.2\.10$'
  expect "AAAA via unbound" "$(digq verify.test "$U" AAAA +short)" '2001:db8::10'
  expect "MX via unbound" "$(digq verify.test "$U" MX +short)" 'mail\.verify\.test'
  expect "TXT via unbound" "$(digq verify.test "$U" TXT +short)" 'spf1'
  expect "SRV via unbound" "$(digq _sip._tcp.verify.test "$U" SRV +short)" '5060'
  expect "CAA via unbound" "$(digq verify.test "$U" CAA +short)" 'letsencrypt'
  expect "SOA via unbound" "$(digq verify.test "$U" SOA +short)" 'ns1\.verify\.test'
  expect "NS via unbound" "$(digq verify.test "$U" NS +short)" 'ns1\.verify\.test'

  wait_port "$DOT" || bad "DoT port $DOT not listening"
  expect_json "DoT authoritative (unbound)" "$(python3 "$CLIENT" dot "$DOT" "$WORK/certs/dot-cert.pem" dot.test verify.test)" 'd.get("rcode")==0 and d.get("an",0)>=1'
  expect_json "DoH authoritative (unbound)" "$(python3 "$CLIENT" doh doh.test "$TLS" "$WORK/certs/doh-cert.pem" POST verify.test)" 'd.get("status")==200 and d.get("rcode")==0 and d.get("an",0)>=1'

  # 递归 + ECS（dig）
  local n0 n1
  n0=$(fake_count)
  digq example.com "$U" A +subnet=203.0.113.0/24 +noall +answer >/dev/null
  sleep 0.5
  n1=$(fake_count)
  [ "$n1" -gt "$n0" ] && ok "recursion reaches fake upstream" || bad "recursion did not reach upstream ($n0 -> $n1)"
  if capture_has_ecs "$n0" "$n1" cb0071; then
    ok "dig recursion: upstream saw client ECS 203.0.113/24"
  else
    bad "dig recursion: upstream ECS missing: $(decode_capture "$n0" "$n1" | head -3)"
  fi

  # 递归 + ECS（DoT/DoH）
  n0=$(fake_count)
  expect_json "DoT recursion ECS response" "$(python3 "$CLIENT" dot "$DOT" "$WORK/certs/dot-cert.pem" dot.test example.net 1:203.0.113:24)" 'd.get("rcode")==0 and d.get("ecs") and d["ecs"][0]["source"]==24 and d["ecs"][0]["address"]=="cb0071"'
  sleep 0.5
  n1=$(fake_count)
  capture_has_ecs "$n0" "$n1" cb0071 && ok "DoT recursion: upstream saw client ECS 203.0.113/24" || bad "DoT recursion: upstream ECS missing"

  n0=$(fake_count)
  expect_json "DoH recursion ECS response" "$(python3 "$CLIENT" doh doh.test "$TLS" "$WORK/certs/doh-cert.pem" POST example.org 1:203.0.113:24)" 'd.get("status")==200 and d.get("ecs") and d["ecs"][0]["source"]==24 and d["ecs"][0]["address"]=="cb0071"'
  sleep 0.5
  n1=$(fake_count)
  capture_has_ecs "$n0" "$n1" cb0071 && ok "DoH recursion: upstream saw client ECS 203.0.113/24" || bad "DoH recursion: upstream ECS missing"

  # 缓存：同一查询第二次不再打上游
  n0=$(fake_count)
  python3 "$CLIENT" dot "$DOT" "$WORK/certs/dot-cert.pem" dot.test cached.example.org >/dev/null 2>&1
  sleep 0.4
  n1=$(fake_count)
  python3 "$CLIENT" dot "$DOT" "$WORK/certs/dot-cert.pem" dot.test cached.example.org >/dev/null 2>&1
  sleep 0.4
  local n2; n2=$(fake_count)
  [ "$n2" -eq "$n1" ] && ok "unbound cache hit (upstream count $n1 -> $n2)" || bad "unbound cache miss ($n1 -> $n2)"

  # 递归 ACL
  expect "recursion ACL: 127.0.0.2 REFUSED" "$(dig -b 127.0.0.2 @127.0.0.1 -p "$U" acl-fresh.example A +time=5 +tries=1 +noall +comments)" 'status: REFUSED'
  expect "recursion ACL: 127.0.0.1 allowed" "$(dig @127.0.0.1 -p "$U" acl-fresh2.example A +time=5 +tries=1 +noall +comments)" 'status: NOERROR'
  expect "authority still public from 127.0.0.2" "$(dig -b 127.0.0.2 @127.0.0.1 -p "$U" verify.test A +short +time=5 +tries=1)" '192\.0\.2\.10'

  # 递归关闭（modes.recursive=false）：权威仍可查、递归明确 REFUSED
  postj "$WEB" /api/dns/modes '{"recursive":false,"enabled":true}' >/dev/null
  for i in $(seq 1 40); do
    grep -q 'forward-zone:' "$WORK/ub/etc/unbound.conf" 2>/dev/null || break
    sleep 0.25
  done
  sleep 1
  expect "recursive=false: no forward-zone" "$(grep -c 'forward-zone:' "$WORK/ub/etc/unbound.conf")" '^0$'
  expect "recursive=false: authority served" "$(digq verify.test "$U" A +short)" '^192\.0\.2\.10$'
  expect "recursive=false: recursion REFUSED" "$(dig @127.0.0.1 -p "$U" recurse-off.example A +time=5 +tries=1 +noall +comments)" 'status: REFUSED'
  postj "$WEB" /api/dns/modes '{"recursive":true,"enabled":true}' >/dev/null
  for i in $(seq 1 40); do
    grep -q 'forward-zone:' "$WORK/ub/etc/unbound.conf" 2>/dev/null && break
    sleep 0.25
  done
  sleep 1
  expect "recursive=true restored (forward-zone)" "$(cat "$WORK/ub/etc/unbound.conf")" 'forward-zone:'

  # 畸形 ECS → FORMERR，且不转发上游
  n0=$(fake_count)
  local q="$WORK/malformed.bin" k kind
  for kind in family dupe olen; do
    python3 "$CLIENT" build-malformed malformed.example "$q" "$kind"
    expect_json "malformed ECS ($kind) DoH → FORMERR" "$(python3 "$CLIENT" doh-wire doh.test "$TLS" "$WORK/certs/doh-cert.pem" POST "$q")" 'd.get("rcode")==1 and d.get("an",0)==0'
    expect_json "malformed ECS ($kind) DoT → FORMERR" "$(python3 "$CLIENT" dot-wire "$DOT" "$WORK/certs/dot-cert.pem" dot.test "$q")" 'd.get("rcode")==1 and d.get("an",0)==0'
  done
  sleep 0.5
  n1=$(fake_count)
  [ "$n1" -eq "$n0" ] && ok "malformed ECS not forwarded upstream" || bad "malformed ECS leaked upstream ($n0 -> $n1)"

  # ecs=false：应答不带 ECS、上游看不到 ECS
  # 用 GET→改 ecs→POST /api/dns/config（面板整体配置）。不要直接 sed panel.toml：
  # 此前没有面板写入时该文件不存在（配置只来自 cfg-ub.toml）。
  local cfgjson
  cfgjson=$(api "$WEB" /api/dns/config)
  cfgjson=$(printf '%s' "$cfgjson" | python3 -c 'import json,sys;d=json.load(sys.stdin);d["ecs"]=False;print(json.dumps(d))')
  postj "$WEB" /api/dns/config "$cfgjson" >/dev/null
  local i
  for i in $(seq 1 40); do
    grep -q 'module-config: "iterator"' "$WORK/ub/etc/unbound.conf" 2>/dev/null && break
    sleep 0.25
  done
  sleep 1
  expect "ecs=false: no send-client-subnet" "$(cat "$WORK/ub/etc/unbound.conf")" 'module-config: "iterator"'
  n0=$(fake_count)
  expect_json "ecs=false: DoT response has no ECS" "$(python3 "$CLIENT" dot "$DOT" "$WORK/certs/dot-cert.pem" dot.test noecs.example.net 1:203.0.113:24)" 'd.get("ecs")==[]'
  expect_json "ecs=false: DoH response has no ECS" "$(python3 "$CLIENT" doh doh.test "$TLS" "$WORK/certs/doh-cert.pem" POST noecs2.example.org 1:203.0.113:24)" 'd.get("ecs")==[]'
  sleep 0.5
  n1=$(fake_count)
  capture_all_no_ecs "$n0" "$n1" && ok "ecs=false: upstream saw no ECS" || bad "ecs=false: upstream saw ECS"

  # 恢复 ecs=true
  cfgjson=$(api "$WEB" /api/dns/config)
  cfgjson=$(printf '%s' "$cfgjson" | python3 -c 'import json,sys;d=json.load(sys.stdin);d["ecs"]=True;print(json.dumps(d))')
  postj "$WEB" /api/dns/config "$cfgjson" >/dev/null
  for i in $(seq 1 40); do
    grep -q 'send-client-subnet:' "$WORK/ub/etc/unbound.conf" 2>/dev/null && break
    sleep 0.25
  done
  sleep 1
  expect "ecs restored (send-client-subnet)" "$(cat "$WORK/ub/etc/unbound.conf")" 'send-client-subnet:'

  # RPZ override（unbound rpz: + answers auth-zone）
  postj "$WEB" /api/dns/override '{}' '{"name":"blocked.rpz.test","rtype":"nxdomain","value":""}' >/dev/null
  postj "$WEB" /api/dns/override '{}' '{"name":"aoverride.rpz.test","rtype":"a","value":"192.0.2.99"}' >/dev/null
  sleep 2
  expect "RPZ nxdomain via unbound" "$(digq blocked.rpz.test "$U" A +noall +comments)" 'status: NXDOMAIN'
  expect "RPZ A override via unbound" "$(digq aoverride.rpz.test "$U" A +short)" '192\.0\.2\.99'

  # DNSSEC：BIND 内部权威端口（KASP 仍由 BIND 负责；Unbound 镜像不签名）
  postj "$WEB" /api/dns/dnssec '{}' '{"dnssec":{"enabled":true,"algorithm":"ECDSAP256SHA256","rotation_enabled":false,"rotation_days":30,"ksk_lifetime_days":365,"keys":[],"nsec3":true,"nsec3_iterations":0,"nsec3_optout":false,"cds":true}}' >/dev/null
  for i in $(seq 1 40); do
    [ "$(digq verify.test "$A" DNSKEY +noall +answer | wc -l)" -ge 2 ] && break
    sleep 0.5
  done
  expect "BIND auth: DNSKEY (>=2)" "$(digq verify.test "$A" DNSKEY +noall +answer | wc -l | tr -d ' ')" '^[2-9]$'
  expect "BIND auth: RRSIG" "$(digq verify.test "$A" A +dnssec +noall +answer)" 'RRSIG.*A 13'
  expect "BIND auth: NSEC3 NXDOMAIN proof" "$(digq nope.verify.test "$A" A +dnssec +noall +authority)" 'NSEC3'
  expect "unbound mirror still serves A" "$(digq verify.test "$U" A +short)" '^192\.0\.2\.10$'

  # 面板加记录 → auth-zone 热载（不重启 unbound）
  local pid_before pid_after
  pid_before=$(cat "$WORK/ub/run/unbound.pid")
  post "$WEB" /api/dns/records '{"zone":"verify.test","name":"hot","rtype":"A","ttl":300,"rdata":"192.0.2.77"}' >/dev/null
  sleep 2
  pid_after=$(cat "$WORK/ub/run/unbound.pid")
  expect "hot reload: new record served" "$(digq hot.verify.test "$U" A +short)" '^192\.0\.2\.77$'
  [ "$pid_before" = "$pid_after" ] && ok "hot reload: unbound pid unchanged ($pid_before)" || bad "unbound restarted ($pid_before -> $pid_after)"

  stop_server ub
}

# ---------------------------------------------------------------- Stage B (bind negative control)
stage_bind_negative() {
  echo "===== Stage B: bind 模式负控（ECS 被 BIND 丢弃） ====="
  write_cfg bind "$BM" "$BR" "$BW" "$BT" "$BD" ""
  start_server bind
  if ! wait_api "$BW"; then
    bad "server (bind) did not become ready"
    tail -20 "$WORK/bind/server.log" | sed 's/^/  /'
    return 1
  fi
  local st
  st=$(api "$BW" /api/dns/status)
  expect "bind status recursor=bind" "$st" '"recursor":"bind"'
  expect "bind status named_running" "$st" '"named_running":true'
  expect "bind status unbound_running=false" "$st" '"unbound_running":false'
  wait_port "$BD" || bad "bind DoT port $BD not listening"

  local n0 n1 out
  n0=$(fake_count)
  out=$(python3 "$CLIENT" dot "$BD" "$WORK/certs/dot-cert.pem" dot.test bindneg.example.net 1:203.0.113:24)
  sleep 1
  n1=$(fake_count)
  # 客户端侧 Rust 层仍会回显 ECS（这是 DoT/DoH 层的行为，与递归传输无关）
  expect_json "bind: client response still echoes ECS" "$out" 'd.get("ecs") and d["ecs"][0]["address"]=="cb0071"'
  [ "$n1" -gt "$n0" ] && ok "bind: query reached upstream" || bad "bind: no upstream query ($n0 -> $n1)"
  if capture_all_no_ecs "$n0" "$n1"; then
    ok "bind negative control: upstream saw NO ECS (BIND 9.20 drops unknown EDNS option)"
  else
    bad "bind negative control: upstream unexpectedly saw ECS"
  fi
  stop_server bind
}

# ---------------------------------------------------------------- main
preflight
mkdir -p "$WORK"
mkcerts
python3 "$CLIENT" fake 127.0.0.1 "$UP" "$WORK/fake.log" >/dev/null 2>&1 &
PIDS+=("$!")
sleep 1
stage_unbound || true
stage_bind_negative || true
echo "=================================================================="
echo "DNS unbound verification: PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
if [ "${DNSV_KEEP:-0}" = "1" ]; then echo "work dir kept: $WORK"; else echo "work dir: $WORK (removed on exit)"; fi
[ "$FAIL" -eq 0 ]
