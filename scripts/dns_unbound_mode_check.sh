#!/usr/bin/env bash
# U-14 补充：本服务器 `[dns] recursor = "unbound"`（产品自管 Unbound）验证。
#
# 与 scripts/dns_unbound_signed_verify.sh（bind 模式 + 外置验证型 Unbound）互补：
# 那条证明「经本服务器得到 ad / 伪造签名 SERVFAIL」；这条证明 `recursor="unbound"`
# 开关本身可用：产品自管的 Unbound 占主端口、BIND 退到内部权威口、生成
# `state-dns/etc/unbound.conf`、ACL 生效、`modes.recursive` 热切换不回退。
#
# 同时记录一条**观察**（不是本脚本缺陷）：产品生成的 unbound.conf 的
# `module-config` 永远是 "iterator"/"subnetcache iterator"/"respip ..."，**不含
# `validator`**，因此产品自管的 Unbound 不做 DNSSEC 验证（转发得到 NOERROR+RRSIG
# 但 **ad=0**）。需要用「验证型递归器」时应按 dns_unbound_signed_verify.sh 的拓扑
# （产品 named 转发到外置 Unbound validator）。脚本会把 ad 的真值打印出来，不作门禁。
#
# 用法：
#   DNSUNBM_BIN=$CARGO_TARGET_DIR/release/webserver bash scripts/dns_unbound_mode_check.sh
# 依赖：unbound + unbound-checkconf、BIND named/dig、openssl、python3、curl、ss。
set -uo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN=${DNSUNBM_BIN:-${CARGO_TARGET_DIR:-$ROOT/target}/release/webserver}
WORK=${DNSUNBM_DIR:-$HOME/scratch-tlsmatrix/ubmode-check}
BASE=${DNSUNBM_BASE:-26710}
UB_PORT=$((BASE - 1))       # 外置验证型 Unbound（本脚本的「真实签名上游」）
SRV_DNS=$((BASE + 4))       # 本服务器 [dns].port（Unbound 占此口）
SRV_HTTP=$((BASE + 30))     # 本服务器明文口（admin API）

PASS=0; FAIL=0
pass() { PASS=$((PASS + 1)); echo "PASS: $*"; }
fail() { FAIL=$((FAIL + 1)); echo "FAIL: $*"; }

cleanup() {
  [ -n "${SRV_PID:-}" ] && kill -TERM "$SRV_PID" 2>/dev/null
  [ -n "${UB_PID:-}" ] && kill -TERM "$UB_PID" 2>/dev/null
  sleep 1
  # 产品自管的 unbound / named：按状态目录与配置路径定位（不要误杀别人的实例）
  [ -n "${SRV_PID:-}" ] && pkill -TERM -P "$SRV_PID" 2>/dev/null
  pkill -TERM -f -- "-c $WORK/state-dns/etc/unbound.conf" 2>/dev/null
  pkill -TERM -f -- "-c $WORK/state-dns/etc/named.conf" 2>/dev/null
  [ -n "${SRV_PID:-}" ] && kill -KILL "$SRV_PID" 2>/dev/null
  sleep 1
}
trap cleanup EXIT

if [ ! -x "$BIN" ]; then echo "webserver binary not found: $BIN" >&2; exit 2; fi
for t in unbound unbound-checkconf named dig openssl python3 curl ss; do
  command -v "$t" >/dev/null 2>&1 || { echo "missing tool: $t" >&2; exit 2; }
done

rm -rf "$WORK"; mkdir -p "$WORK/www" "$WORK/state-dns"
python3 -c 'open("'"$WORK"'/www/index.html","wb").write(b"y"*127)'

# 外置验证型 Unbound（真实签名上游：根锚 + TCP 迭代 + 显式 harden）
cp /home/dev123/local/usr/share/dns/root.key "$WORK/root.key" 2>/dev/null \
  || cp /usr/share/dns/root.key "$WORK/root.key"
chmod 644 "$WORK/root.key"
cat > "$WORK/ub.conf" <<EOF
server:
  interface: 127.0.0.1@$UB_PORT
  username: ""
  directory: "$WORK"
  access-control: 127.0.0.0/8 allow
  do-daemonize: no
  do-not-query-localhost: no
  pidfile: "$WORK/ub.pid"
  logfile: "$WORK/ub.log"
  verbosity: 2
  log-servfail: yes
  auto-trust-anchor-file: "$WORK/root.key"
  qname-minimisation: yes
  harden-dnssec-stripped: yes
  tcp-upstream: yes
  edns-tcp-keepalive: yes
  cache-min-ttl: 0
  cache-max-ttl: 60
EOF
unbound-checkconf "$WORK/ub.conf" >/dev/null 2>&1 || { echo "ub.conf invalid" >&2; exit 2; }
(unbound -c "$WORK/ub.conf" >/dev/null 2>&1 & echo $! > "$WORK/ub.pid")
UB_PID=$(cat "$WORK/ub.pid")
for _ in $(seq 1 40); do ss -lun 2>/dev/null | grep -q ":$UB_PORT " && break; sleep 0.5; done

# 验证器硬化项断言
for kv in "harden-dnssec-stripped yes" "qname-minimisation yes" "harden-below-nxdomain yes"; do
  k=${kv% *}; want=${kv#* }
  got=$(unbound-checkconf -o "$k" "$WORK/ub.conf" 2>/dev/null | tr -d '[:space:]')
  if [ "$got" = "$want" ]; then pass "validator config: $k=$got"; else fail "validator config: $k=$got (want $want)"; fi
done
[ -s "$WORK/root.key" ] && grep -q auto-trust-anchor-file "$WORK/ub.conf" \
  && pass "validator config: root trust anchor present ($(wc -c < "$WORK/root.key") bytes)" \
  || fail "validator root trust anchor missing"

# 外置验证器正控（真实互联网，TCP 迭代）
EXTAD=0
for _ in $(seq 1 20); do
  O=$(dig @127.0.0.1 -p "$UB_PORT" example.com A +dnssec +time=20 +tries=1 +noall +comments +answer 2>&1)
  echo "$O" | grep -q 'flags:.* ad' && echo "$O" | grep -q RRSIG && { EXTAD=1; break; }
  sleep 2
done
[ "$EXTAD" = 1 ] && pass "external validating Unbound: example.com -> ad + RRSIG (real signed chain)" \
  || fail "external Unbound did not validate example.com"

# 本服务器 recursor="unbound" → 指向上面这台外置验证器
ADMIN_HASH='$argon2id$v=19$m=19456,t=2,p=1$E/RLobwgix2BWMRMT++urA$yEympjJtiDh0ezwSQsnkbsfYAoSzeDAHYw3EsUMBsj4'
cat > "$WORK/conf.toml" <<EOF
[access_log]
enable = false
[admin]
path = "/__admin"
realm = "u14m"
[[admin.users]]
username = "admin"
password_hash = "$ADMIN_HASH"
[[listeners]]
address = "127.0.0.1"
port = $SRV_HTTP
root = "$WORK/www"
http_versions = ["h1"]
[dns]
enabled = true
test_mode = true
listen_addr = "127.0.0.1"
port = $SRV_DNS
rndc_port = $((BASE + 7))
recursion_acl = ["127.0.0.1"]
forwarders = ["127.0.0.1:$UB_PORT"]
forward_policy = "only"
recursor = "unbound"
[dns.modes]
authoritative = true
recursive = true
EOF

export CRUCIBLE_DNS_STATE_ROOT="$WORK/state-dns"
export CRUCIBLE_UNBOUND_BIN=$(command -v unbound)
export CRUCIBLE_UNBOUND_CONTROL_BIN=$(command -v unbound-control || true)
export CRUCIBLE_UNBOUND_CONTROL_SETUP_BIN=$(command -v unbound-control-setup || true)
export CRUCIBLE_UNBOUND_CHECKCONF_BIN=$(command -v unbound-checkconf)
"$BIN" --config "$WORK/conf.toml" > "$WORK/server.log" 2>&1 &
SRV_PID=$!
ok=0
for _ in $(seq 1 80); do curl -s -o /dev/null "http://127.0.0.1:$SRV_HTTP/" && { ok=1; break; }; sleep 0.5; done
[ "$ok" = 1 ] || { fail "server did not become ready"; tail -20 "$WORK/server.log"; }

# 产品自管 Unbound 的生成配置与端口
GEN="$WORK/state-dns/etc/unbound.conf"
[ -f "$GEN" ] && pass "product generated $GEN" || fail "generated unbound.conf missing"
if [ -f "$GEN" ] && unbound-checkconf "$GEN" >/dev/null 2>&1; then
  pass "generated unbound.conf passes unbound-checkconf"
else
  fail "generated unbound.conf rejected by unbound-checkconf"
fi
if ss -lun 2>/dev/null | grep -q ":$SRV_DNS "; then
  pass "product-managed Unbound listening on main port $SRV_DNS (named on $((SRV_DNS + 1)))"
else
  fail "nothing listening on main port $SRV_DNS"
fi
grep -q "recursor=unbound\|recursor = \"unbound\"\|unbound" "$WORK/server.log" \
  && pass "server log records recursor=unbound reconcile" || fail "no unbound reconcile line in server.log"

# 主端口服务的递归可用性（转发到外置验证器）
RESP=$(dig @127.0.0.1 -p "$SRV_DNS" example.com A +dnssec +time=30 +tries=1 +noall +comments +answer 2>&1)
if echo "$RESP" | grep -q 'status: NOERROR' && echo "$RESP" | grep -q RRSIG; then
  pass "dig @main: example.com NOERROR + RRSIG (recursion works via product-managed Unbound)"
else
  fail "dig @main did not return a signed answer: $(echo "$RESP" | head -4 | tr '\n' ' ')"
fi
AD=$(echo "$RESP" | grep -c 'flags:.* ad')
echo "NOTE: product-managed Unbound ad=$AD (0 expected: module-config has no 'validator'; see header)"
grep -q 'module-config' "$GEN" && ! grep -q 'validator' "$GEN" \
  && echo "NOTE: $(grep 'module-config' "$GEN" | tr -d ' ') — no validator module" \
  || true

# ACL 不回退
ACL=$(dig -b 127.0.0.2 @127.0.0.1 -p "$SRV_DNS" example.com A +time=5 +tries=1 +noall +comments 2>&1)
echo "$ACL" | grep -q 'status: REFUSED' \
  && pass "recursion_acl: 127.0.0.2 -> REFUSED" || fail "ACL regression: $(echo "$ACL" | head -2 | tr '\n' ' ')"

# modes.recursive 热切换（false → REFUSED，true → 恢复）
api() { curl -sS -u admin:admin -X POST -H 'content-type: application/json' -d "$2" \
        "http://127.0.0.1:$SRV_HTTP/__admin$1"; }
api /api/dns/modes '{"recursive":false,"authoritative":true}' >/dev/null; sleep 2
OFF=$(dig @127.0.0.1 -p "$SRV_DNS" example.com A +time=5 +tries=1 +noall +comments 2>&1)
echo "$OFF" | grep -qE 'status: (REFUSED|SERVFAIL)' \
  && pass "modes.recursive=false -> $(echo "$OFF" | grep -o 'status: [A-Z]*' | head -1)" \
  || fail "modes.recursive=false still recursive"
api /api/dns/modes '{"recursive":true,"authoritative":true}' >/dev/null; sleep 2
ON=0
for _ in $(seq 1 8); do
  R=$(dig @127.0.0.1 -p "$SRV_DNS" example.com A +time=10 +tries=1 +noall +comments 2>&1)
  echo "$R" | grep -q 'status: NOERROR' && { ON=1; break; }; sleep 1
done
[ "$ON" = 1 ] && pass "modes.recursive restored -> recursion works (hot, no restart)" \
  || fail "recursion did not recover"

echo
echo "U-14 recursor=unbound mode: PASS=$PASS FAIL=$FAIL"
[ "$FAIL" = 0 ]
