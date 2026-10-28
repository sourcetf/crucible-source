#!/usr/bin/env bash
# U-14 真机验证：Unbound 作为**真实签名上游**（验证递归器）。
#
# 拓扑：
#   dig/DoT ──> 本服务器 named（bind 模式，forward only）
#                 └──UDP/TCP──> Unbound（validator，auto-trust-anchor-file，
#                                 TCP 上游递归到根/TLD/权威）
#                                  ├─ "."         真实互联网（example.com）
#                                  └─ good.u14 / bogus.u14 → 本地权威 named
#
# 覆盖：
#   * dig 经本机 → Unbound 得到 `ad` 标志的答案（example.com）；
#   * 伪造签名（签名后篡改 A 记录）被 Unbound 判 bogus → SERVFAIL；
#   * 正控：同一条链上的良好签名 good.u14 得到 NOERROR（证明 SERVFAIL 是签名问题）；
#   * modes.recursive 热切换（false → REFUSED，true → 恢复 ad）；
#   * recursion_acl 不回归（127.0.0.2 来源 REFUSED，127.0.0.1 可用）；
#   * 同一实例的 DoT（独立端口 + 复用站点 TLS 端口）也返回 ad。
#
# 依赖：webserver（tls,tls_boring）、unbound + unbound-checkconf、
#       BIND named/dig/dnssec-*、openssl、python3。
# 用法：
#   DNSUNB_BIN=$CARGO_TARGET_DIR/release/webserver bash scripts/dns_unbound_signed_verify.sh
set -uo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN=${DNSUNB_BIN:-${CARGO_TARGET_DIR:-$ROOT/target}/release/webserver}
WORK=${DNSUNB_DIR:-$HOME/scratch-dot443/u14}
BASE=${DNSUNB_BASE:-44500}
UB_PORT=$((BASE + 53))   # Unbound（验证递归器）
UB_AUTH_PORT=$((BASE + 63)) # 本地权威（good/bogus 签名区）
DNS_PORT=$((BASE + 54))  # 本服务器 named
RNDC_PORT=$((BASE + 55))
DOT_PORT=$((BASE + 56))  # 本服务器独立 DoT
HTTP_PORT=$((BASE + 80)) # 本服务器明文（API）
TLS_PORT=$((BASE + 81))  # 本服务器站点 TLS（dot 复用）

PASS=0
FAIL=0
SKIP=0
pass() { PASS=$((PASS + 1)); echo "PASS: $*"; }
fail() { FAIL=$((FAIL + 1)); echo "FAIL: $*"; }
skip() { SKIP=$((SKIP + 1)); echo "SKIP: $*"; }

cleanup() {
  [ -n "${DNSUNB_KEEP:-}" ] && return 0
  [ -n "${SRV_PID:-}" ] && kill -TERM "$SRV_PID" 2>/dev/null
  [ -n "${UB_PID:-}" ] && kill -TERM "$UB_PID" 2>/dev/null
  [ -n "${AUTH_PID:-}" ] && kill -TERM "$AUTH_PID" 2>/dev/null
  [ -n "${SRV_PID:-}" ] && wait "$SRV_PID" 2>/dev/null
  [ -n "${UB_PID:-}" ] && wait "$UB_PID" 2>/dev/null
  [ -n "${AUTH_PID:-}" ] && wait "$AUTH_PID" 2>/dev/null
  pkill -TERM -f -- "-c $WORK/state-dns/etc/named.conf" 2>/dev/null
}
trap cleanup EXIT

if [ ! -x "$BIN" ]; then echo "webserver binary not found: $BIN" >&2; exit 2; fi
for t in unbound unbound-checkconf named dig dnssec-keygen dnssec-signzone dnssec-dsfromkey openssl python3 curl jq; do
  command -v "$t" >/dev/null 2>&1 || { echo "missing tool: $t" >&2; exit 2; }
done

rm -rf "$WORK"
mkdir -p "$WORK"/{auth,certs,state-dns,www,www-tls}
python3 -c 'open("'"$WORK"'/www/index.html","wb").write(b"y"*127)'
python3 -c 'open("'"$WORK"'/www-tls/index.html","wb").write(b"y"*127)'

ADMIN_HASH='$argon2id$v=19$m=19456,t=2,p=1$E/RLobwgix2BWMRMT++urA$yEympjJtiDh0ezwSQsnkbsfYAoSzeDAHYw3EsUMBsj4'

# ---------------------------------------------------------------- 本地权威：good/bogus
make_zone() { # name tamper(0/1)
  local z=$1 tamper=$2
  cat > "$WORK/auth/$z.zone" <<EOF
\$TTL 300
@	IN SOA	ns1.$z. admin.$z. 1 3600 600 86400 300
@	IN NS	ns1.$z.
ns1	IN A	127.0.0.1
www	IN A	192.0.2.7
EOF
  local ksk zsk
  # 关键：dnssec-keygen 把 K<zone>.* 写进**当前目录**（不是 -o/zone 目录），
  # 必须在 $WORK/auth 里执行，否则会污染调用者的 cwd。
  ksk=$(cd "$WORK/auth" && dnssec-keygen -a ECDSAP256SHA256 -n ZONE -f KSK "$z" 2>/dev/null)
  zsk=$(cd "$WORK/auth" && dnssec-keygen -a ECDSAP256SHA256 -n ZONE "$z" 2>/dev/null)
  cat "$WORK/auth/$ksk.key" "$WORK/auth/$zsk.key" >> "$WORK/auth/$z.zone"
  ( cd "$WORK/auth" && dnssec-signzone -o "$z" -N INCREMENT -S "$z.zone" >/dev/null 2>&1 )
  dnssec-dsfromkey -2 "$WORK/auth/$ksk.key" | awk '{print $4" "$5" "$6" "$7}' > "$WORK/auth/$z.ds"
  if [ "$tamper" = 1 ]; then
    # 签名**之后**改 A 记录：RRSIG 与 RRset 不再匹配 ⇒ 验证器必须判 bogus。
    python3 - "$WORK/auth/$z.zone.signed" <<'PY'
import sys
p = sys.argv[1]
lines = open(p).read().splitlines()
lines = [l.replace("192.0.2.7", "192.0.2.99") if l.startswith("www.") else l for l in lines]
open(p, "w").write("\n".join(lines) + "\n")
PY
  fi
}
make_zone good.u14 0
make_zone bogus.u14 1

cat > "$WORK/auth/named.conf" <<EOF
options {
  listen-on port $UB_AUTH_PORT { 127.0.0.1; };
  listen-on-v6 { none; };
  directory "$WORK/auth";
  pid-file "$WORK/auth/named.pid";
  session-keyfile "$WORK/auth/session.key";
  recursion no;
  dnssec-validation no;
  minimal-responses no;
};
zone "good.u14"  { type primary; file "$WORK/auth/good.u14.zone.signed"; };
zone "bogus.u14" { type primary; file "$WORK/auth/bogus.u14.zone.signed"; };
EOF

# ---------------------------------------------------------------- Unbound 验证递归器
cp /home/dev123/local/usr/share/dns/root.key "$WORK/root.key" 2>/dev/null || true
[ -s "$WORK/root.key" ] || cp /usr/share/dns/root.key "$WORK/root.key"
chmod 644 "$WORK/root.key"
DS_GOOD=$(cat "$WORK/auth/good.u14.ds")
DS_BOGUS=$(cat "$WORK/auth/bogus.u14.ds")
cat > "$WORK/unbound.conf" <<EOF
server:
  interface: 127.0.0.1@$UB_PORT
  username: ""
  directory: "$WORK"
  access-control: 127.0.0.0/8 allow
  do-daemonize: no
  do-not-query-localhost: no
  pidfile: "$WORK/unbound.pid"
  logfile: "$WORK/unbound.log"
  verbosity: 2
  log-servfail: yes
  auto-trust-anchor-file: "$WORK/root.key"
  trust-anchor: "good.u14. DS $DS_GOOD"
  trust-anchor: "bogus.u14. DS $DS_BOGUS"
  module-config: "validator iterator"
  # 本环境 UDP:53 到根/权威被屏蔽，但 TCP:53 可达；Unbound 用 TCP 做完整迭代
  # （仍是真实 DNSSEC 链验证，不是转发给公共解析器）。
  tcp-upstream: yes
  edns-tcp-keepalive: yes
  cache-min-ttl: 0
  cache-max-ttl: 600

forward-zone:
  name: "good.u14"
  forward-addr: 127.0.0.1@$UB_AUTH_PORT

forward-zone:
  name: "bogus.u14"
  forward-addr: 127.0.0.1@$UB_AUTH_PORT
EOF

# ---------------------------------------------------------------- 证书（DoT/TLS）
CA="$WORK/certs/ca.pem"
openssl req -x509 -newkey rsa:2048 -nodes -days 3 \
  -keyout "$WORK/certs/ca.key" -out "$CA" -subj "/CN=u14 test CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1
for n in dot site; do
  cn=$([ "$n" = dot ] && echo dot.example || echo site.example)
  openssl req -newkey rsa:2048 -nodes -keyout "$WORK/certs/$n.key" \
    -out "$WORK/certs/$n.csr" -subj "/CN=$cn" >/dev/null 2>&1
  printf 'subjectAltName=DNS:%s,DNS:localhost,IP:127.0.0.1\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n' "$cn" > "$WORK/certs/$n.ext"
  openssl x509 -req -in "$WORK/certs/$n.csr" -CA "$CA" -CAkey "$WORK/certs/ca.key" \
    -CAcreateserial -days 3 -extfile "$WORK/certs/$n.ext" -out "$WORK/certs/$n.pem" >/dev/null 2>&1
  cat "$WORK/certs/$n.pem" "$CA" > "$WORK/certs/$n-full.pem"
done

# ---------------------------------------------------------------- 本服务器配置
cat > "$WORK/conf.toml" <<EOF
[access_log]
enable = false

[admin]
path = "/__admin"
realm = "u14"

[[admin.users]]
username = "admin"
password_hash = "$ADMIN_HASH"

[[listeners]]
address = "127.0.0.1"
port = $HTTP_PORT
root = "$WORK/www"
http_versions = ["h1", "h2"]

[[listeners]]
address = "127.0.0.1"
port = $TLS_PORT
root = "$WORK/www-tls"
http_versions = ["h1", "h2"]
server_name = "site.example"

[listeners.ssl]
cert = "$WORK/certs/site-full.pem"
key = "$WORK/certs/site.key"

[dns]
enabled = true
test_mode = true
listen_addr = "127.0.0.1"
port = $DNS_PORT
rndc_port = $RNDC_PORT
recursion_acl = ["127.0.0.1"]
forwarders = ["127.0.0.1:$UB_PORT"]
forward_policy = "only"
ecs = false

[dns.modes]
authoritative = true
recursive = true

[dns.dot]
enabled = true
port = $DOT_PORT
cert = "$WORK/certs/dot-full.pem"
key = "$WORK/certs/dot.key"
allow = ["127.0.0.1"]
reuse_tls_port = true
sni = ["dot.example"]

[dns.doh]
enabled = true
path = "/dns-query"
hostnames = ["site.example"]
EOF

# ---------------------------------------------------------------- 客户端（DoT with ad）
cat > "$WORK/client.py" <<'PY'
import json, socket, ssl, struct, sys

def name_wire(name):
    out = b""
    for lab in name.rstrip(".").split("."):
        out += bytes([len(lab)]) + lab.encode()
    return out + b"\x00"

def build_query(name, do=False):
    w = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 1)
    w += name_wire(name) + struct.pack("!HH", 1, 1)
    # OPT: root, type 41, payload 4096, TTL=0x00008000 (DO), rdlen 0
    w += b"\x00" + struct.pack("!HH", 41, 4096) + struct.pack("!I", 0x00008000 if do else 0) + b"\x00\x00"
    return w

def skipname(m, o):
    while True:
        l = m[o]
        if l & 0xC0 == 0xC0:
            return o + 2
        if l == 0:
            return o + 1
        o += 1 + l

def parse(m):
    out = {"rcode": m[3] & 0xF, "an": struct.unpack("!H", m[6:8])[0],
           "ad": bool(struct.unpack("!H", m[2:4])[0] & 0x20), "addrs": []}
    qd = struct.unpack("!H", m[4:6])[0]
    o = 12
    for _ in range(qd):
        o = skipname(m, o) + 4
    for _ in range(out["an"]):
        o = skipname(m, o)
        rtype, _rc, _ttl, rdlen = struct.unpack("!HHIH", m[o:o + 10])
        o += 10
        if rtype == 1 and rdlen == 4:
            out["addrs"].append(".".join(str(b) for b in m[o:o + 4]))
        o += rdlen
    return out

def main():
    port, ca, sni, alpn, name = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
    ctx = ssl.create_default_context(cafile=ca)
    if alpn != "-":
        ctx.set_alpn_protocols([alpn])
    s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=15),
                        server_hostname=sni)
    out = {"alpn": s.selected_alpn_protocol()}
    w = build_query(name, True)
    s.sendall(struct.pack("!H", len(w)) + w)
    hdr = s.recv(2)
    n = struct.unpack("!H", hdr)[0]
    data = b""
    while len(data) < n:
        data += s.recv(n - len(data))
    out.update(parse(data))
    s.close()
    print(json.dumps(out))

main()
PY

# ---------------------------------------------------------------- 起进程
named -c "$WORK/auth/named.conf" -f >"$WORK/auth/named.log" 2>&1 &
AUTH_PID=$!
echo "$AUTH_PID" > "$WORK/auth/named.pid"
sleep 1
unbound-checkconf "$WORK/unbound.conf" >/dev/null 2>&1 || { echo "unbound.conf invalid" >&2; exit 2; }
(unbound -c "$WORK/unbound.conf" >"$WORK/ub.out" 2>&1 & echo $! > "$WORK/unbound.pid")
UB_PID=$(cat "$WORK/unbound.pid")
sleep 1

export CRUCIBLE_DNS_STATE_ROOT="$WORK/state-dns"
"$BIN" --config "$WORK/conf.toml" >"$WORK/server.log" 2>&1 &
SRV_PID=$!
for _ in $(seq 1 60); do
  curl -s -o /dev/null "http://127.0.0.1:$HTTP_PORT/" && break
  sleep 0.5
done
sleep 1

# ---------------------------------------------------------------- 0) 基础连通
if dig @127.0.0.1 -p "$UB_PORT" www.good.u14 A +dnssec +time=15 +tries=1 +noall +comments 2>/dev/null | grep -q 'flags:.* ad'; then
  pass "Unbound validator: www.good.u14 NOERROR + ad (valid signature accepted)"
else
  fail "Unbound did not validate good.u14"; dig @127.0.0.1 -p "$UB_PORT" www.good.u14 A +dnssec +time=5 +tries=1 2>&1 | head -8
fi

# ---------------------------------------------------------------- 1) dig 经本机 → Unbound：ad
AD_OK=0
for _ in $(seq 1 10); do
  OUT=$(dig @127.0.0.1 -p "$DNS_PORT" example.com A +dnssec +time=15 +tries=1 +noall +comments +answer 2>&1)
  if echo "$OUT" | grep -q 'flags:.* ad' && echo "$OUT" | grep -q 'RRSIG'; then AD_OK=1; break; fi
  sleep 1
done
if [ "$AD_OK" = 1 ]; then
  pass "dig @127.0.0.1:$DNS_PORT example.com +dnssec -> ad flag + RRSIG (through named -> Unbound)"
else
  fail "dig example.com did not get AD"; echo "$OUT" | head -12
fi

# ---------------------------------------------------------------- 2) bogus → SERVFAIL
BOGUS=$(dig @127.0.0.1 -p "$DNS_PORT" www.bogus.u14 A +dnssec +time=15 +tries=1 +noall +comments 2>&1)
if echo "$BOGUS" | grep -q 'status: SERVFAIL'; then
  pass "forged signature www.bogus.u14 -> SERVFAIL (bogus rejected by Unbound)"
else
  fail "bogus.u14 not rejected: $(echo "$BOGUS" | head -3 | tr '\n' ' ')"
fi

# 直接查 Unbound：良好签名 good.u14 = ad/NOERROR，伪造签名 bogus.u14 = SERVFAIL。
# 说明：BIND（本服务器）没有 good.u14 的信任锚（自定义 TLD 不在根链上），它的
# 验证器对 good.u14 会给出 "broken trust chain"；因此正控取 Unbound 本体，端到端
# 只断言「bogus 经本机得到 SERVFAIL」+ Unbound 日志里的 validation failure。
GOOD_DIRECT=$(dig @127.0.0.1 -p "$UB_PORT" www.good.u14 A +dnssec +time=10 +tries=1 +noall +comments +answer 2>&1)
if echo "$GOOD_DIRECT" | grep -q 'status: NOERROR' && echo "$GOOD_DIRECT" | grep -q 'flags:.* ad'; then
  pass "control: Unbound accepts valid signature www.good.u14 -> NOERROR + ad"
else
  fail "control good.u14 at Unbound failed: $(echo "$GOOD_DIRECT" | head -4 | tr '\n' ' ')"
fi
BOGUS_DIRECT=$(dig @127.0.0.1 -p "$UB_PORT" www.bogus.u14 A +dnssec +time=10 +tries=1 +noall +comments 2>&1)
if echo "$BOGUS_DIRECT" | grep -q 'status: SERVFAIL'; then
  pass "Unbound validator: forged RRSIG www.bogus.u14 -> SERVFAIL (direct)"
else
  fail "Unbound did not reject bogus directly: $(echo "$BOGUS_DIRECT" | head -3 | tr '\n' ' ')"
fi
if grep -qiE '(validation failure|servfail).*bogus\.u14|bogus\.u14.*(validation failure|servfail)' "$WORK/unbound.log"; then
  pass "Unbound log records the bogus verdict: $(grep -iE '(validation failure|servfail).*bogus\.u14|bogus\.u14.*(validation failure|servfail)' "$WORK/unbound.log" | head -1 | cut -c1-200)"
else
  # 没有专门日志行也不改变结论（SERVFAIL 已在两处观察到），但如实标注。
  echo "note: unbound.log 没有单独的 validation failure 行（verbosity=2 + log-servfail=yes）"
  fail "no servfail/validation-failure line for bogus.u14 in unbound.log"
fi

# ---------------------------------------------------------------- 3) recursion ACL
ACL=$(dig -b 127.0.0.2 @127.0.0.1 -p "$DNS_PORT" example.com A +dnssec +time=5 +tries=1 +noall +comments 2>&1)
if echo "$ACL" | grep -q 'status: REFUSED'; then
  pass "recursion_acl: source 127.0.0.2 -> REFUSED (127.0.0.1 remains allowed)"
else
  fail "ACL regression: $(echo "$ACL" | head -3 | tr '\n' ' ')"
fi

# ---------------------------------------------------------------- 4) modes.recursive 热切换
api() { curl -sS -u admin:admin -X POST -H 'content-type: application/json' -d "$2" "http://127.0.0.1:$HTTP_PORT/__admin$1"; }
api /api/dns/modes '{"recursive":false,"authoritative":true}' >/dev/null
sleep 2
REC_OFF=$(dig @127.0.0.1 -p "$DNS_PORT" example.com A +dnssec +time=5 +tries=1 +noall +comments 2>&1)
if echo "$REC_OFF" | grep -qE 'status: (REFUSED|SERVFAIL)'; then
  pass "modes.recursive=false -> example.com $(echo "$REC_OFF" | grep -o 'status: [A-Z]*' | head -1) (no recursion)"
else
  fail "modes.recursive=false still recursive: $(echo "$REC_OFF" | head -3 | tr '\n' ' ')"
fi
api /api/dns/modes '{"recursive":true,"authoritative":true}' >/dev/null
sleep 2
REC_ON=0
for _ in $(seq 1 8); do
  OUT=$(dig @127.0.0.1 -p "$DNS_PORT" example.com A +dnssec +time=10 +tries=1 +noall +comments 2>&1)
  if echo "$OUT" | grep -q 'flags:.* ad'; then REC_ON=1; break; fi
  sleep 1
done
if [ "$REC_ON" = 1 ]; then
  pass "modes.recursive restored -> ad flag back (hot reload, no restart)"
else
  fail "recursion did not recover after modes.recursive=true"
fi

# ---------------------------------------------------------------- 5) DoT 两条路径也拿到 ad
for _ in $(seq 1 20); do ss -ltn 2>/dev/null | grep -q ":$DOT_PORT " && break; sleep 0.5; done
if ! ss -ltn 2>/dev/null | grep -q ":$DOT_PORT "; then
  fail "dedicated DoT port $DOT_PORT not listening"; grep -iE "dot" "$WORK/server.log" | tail -5
fi
DOT_DED=$(python3 "$WORK/client.py" "$DOT_PORT" "$CA" dot.example - example.com 2>"$WORK/dot-ded.err")
if [ "$(echo "$DOT_DED" | jq -r '.ad' 2>/dev/null)" = "true" ]; then
  pass "dedicated DoT :$DOT_PORT example.com -> ad=true (rcode=$(echo "$DOT_DED" | jq -r .rcode))"
else
  fail "dedicated DoT did not return ad: $DOT_DED $(tail -2 "$WORK/dot-ded.err" 2>/dev/null | tr '\n' ' ')"
fi
DOT_REUSE=$(python3 "$WORK/client.py" "$TLS_PORT" "$CA" dot.example dot example.com 2>"$WORK/dot-reuse.err")
if [ "$(echo "$DOT_REUSE" | jq -r '.ad' 2>/dev/null)" = "true" ] \
   && [ "$(echo "$DOT_REUSE" | jq -r '.alpn' 2>/dev/null)" = "dot" ]; then
  pass "DoT over reused site TLS :$TLS_PORT (ALPN dot) example.com -> ad=true"
else
  fail "reused-port DoT did not return ad: $DOT_REUSE $(tail -2 "$WORK/dot-reuse.err" 2>/dev/null | tr '\n' ' ')"
fi

# ---------------------------------------------------------------- 6) DoH 也拿到 ad（TLS + Host 白名单）
DOH=""
for _ in $(seq 1 3); do
DOH=$(python3 - "$WORK/certs/ca.pem" "$TLS_PORT" <<'PY'
import base64, http.client, json, ssl, struct, sys
ca, port = sys.argv[1], int(sys.argv[2])
def nw(n):
    o=b""
    for l in n.split("."):
        o+=bytes([len(l)])+l.encode()
    return o+b"\x00"
w=struct.pack("!HHHHHH",0x2222,0x0100,1,0,0,1)+nw("example.com")+struct.pack("!HH",1,1)
w+=b"\x00"+struct.pack("!HH",41,4096)+struct.pack("!I",0x00008000)+b"\x00\x00"
ctx=ssl.create_default_context(cafile=ca); ctx.set_alpn_protocols(["http/1.1"])
c=http.client.HTTPSConnection("127.0.0.1", port, context=ctx, timeout=15)
c.request("POST","/dns-query",body=w,headers={"Host":"site.example","content-type":"application/dns-message"})
r=c.getresponse(); b=r.read()
print(json.dumps({"status":r.status,"ad":bool(struct.unpack("!H",b[2:4])[0]&0x20) if len(b)>=12 else None}))
PY
)
  [ "$(echo "$DOH" | jq -r '.status' 2>/dev/null)" = "200" ] && break
  sleep 1
done
if [ "$(echo "$DOH" | jq -r '.status' 2>/dev/null)" = "200" ] && [ "$(echo "$DOH" | jq -r '.ad' 2>/dev/null)" = "true" ]; then
  pass "DoH (TLS h1, Host site.example) example.com -> HTTP 200 + ad=true"
else
  fail "DoH did not return ad: $DOH"
fi

echo
echo "U-14 Unbound signed-upstream: PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
[ "$FAIL" = 0 ]
