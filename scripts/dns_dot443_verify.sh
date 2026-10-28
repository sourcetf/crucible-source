#!/usr/bin/env bash
# G-08 真机验证：DoT over 站点 TLS 端口（SNI/ALPN 复用）。
#
# 一条命令覆盖：
#   1. 同一 TLS 端口上 `openssl s_client -alpn dot` 发 DNS 查询拿到应答（dot 证书）；
#   2. 同端口 `curl --http2` / `--http1.1` 正常 200（站点证书、ALPN h2/http1.1）；
#   3. 未声明 ALPN 的普通 TLS 走 HTTP（不是 DNS）；
#   4. ALPN=dot 但 SNI 不在 [dns.dot].sni 白名单 ⇒ 按站点流量处理（不会进 DNS）；
#   5. 独立 DoT 端口（[dns.dot].port）回归；
#   6. reuse_tls_port=false（默认）零变化：同端口 ALPN dot 不会得到 DNS 应答。
#
# 依赖：webserver 二进制（--features tls,tls_boring）、openssl、curl、dig/named。
# 用法：
#   DNSDOT_BIN=$CARGO_TARGET_DIR/release/webserver bash scripts/dns_dot443_verify.sh
# 端口块默认 44300，可用 DNSDOT_BASE 覆盖（避开 24/26/28/29/31/32/33/36/38/40xxx）。
set -uo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN=${DNSDOT_BIN:-${CARGO_TARGET_DIR:-$ROOT/target}/release/webserver}
WORK=${DNSDOT_DIR:-$HOME/scratch-dot443/g08}
BASE=${DNSDOT_BASE:-44300}
SITE_PORT=$BASE
DOT_PORT=$((BASE + 53))
DNS_PORT=$((BASE + 54))          # 实例 A 的 named
RNDC_PORT=$((BASE + 55))
SITE2_PORT=$((BASE + 10)) # reuse=false 对照实例
DNS2_PORT=$((BASE + 64))          # 实例 B：独立 named 端口，避免上一个实例的 named
RNDC2_PORT=$((BASE + 65))         # 尚未退出时端口被占（真机实测会静默服务旧 state）
SITE3_PORT=$((BASE + 20)) # reuse=true 但未配 dot 证书（沿用站点证书）对照实例
DNS3_PORT=$((BASE + 74))
RNDC3_PORT=$((BASE + 75))
DOT3_PORT=$((BASE + 22))

PASS=0
FAIL=0
SKIP=0
pass() { PASS=$((PASS + 1)); echo "PASS: $*"; }
fail() { FAIL=$((FAIL + 1)); echo "FAIL: $*"; }
skip() { SKIP=$((SKIP + 1)); echo "SKIP: $*"; }

cleanup() {
  [ -n "${SRV_PID:-}" ] && kill -TERM "$SRV_PID" 2>/dev/null
  [ -n "${SRV2_PID:-}" ] && kill -TERM "$SRV2_PID" 2>/dev/null
  [ -n "${SRV3_PID:-}" ] && kill -TERM "$SRV3_PID" 2>/dev/null
  for p in "${SRV_PID:-}" "${SRV2_PID:-}" "${SRV3_PID:-}"; do
    [ -n "$p" ] && wait "$p" 2>/dev/null
  done
  # named/子进程由 webserver 负责；兜底只杀掉使用本 work 目录配置的 named。
  for st in "$WORK/state-a/etc/named.conf" "$WORK/state-b/etc/named.conf" "$WORK/state-c/etc/named.conf"; do
    pkill -TERM -f -- "-c $st" 2>/dev/null
  done
}
trap cleanup EXIT

if [ ! -x "$BIN" ]; then
  echo "webserver binary not found: $BIN" >&2
  exit 2
fi
for t in openssl curl python3 dig jq; do
  command -v "$t" >/dev/null 2>&1 || { echo "missing tool: $t" >&2; exit 2; }
done

rm -rf "$WORK"
mkdir -p "$WORK/certs" "$WORK/www" "$WORK/state-a" "$WORK/state-b" "$WORK/state-c"
python3 - "$WORK/www/index.html" <<'PY'
import sys
open(sys.argv[1], "wb").write(b"y" * 127)
PY

# ---------------------------------------------------------------- 证书
CA="$WORK/certs/ca.pem"
openssl req -x509 -newkey rsa:2048 -nodes -days 3 \
  -keyout "$WORK/certs/ca.key" -out "$CA" -subj "/CN=dot443 test CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" >/dev/null 2>&1
mk_cert() { # name cn san
  local n=$1 cn=$2 san=$3
  openssl req -newkey rsa:2048 -nodes -keyout "$WORK/certs/$n.key" \
    -out "$WORK/certs/$n.csr" -subj "/CN=$cn" >/dev/null 2>&1
  printf 'subjectAltName=%s\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n' "$san" > "$WORK/certs/$n.ext"
  openssl x509 -req -in "$WORK/certs/$n.csr" -CA "$CA" -CAkey "$WORK/certs/ca.key" \
    -CAcreateserial -days 3 -extfile "$WORK/certs/$n.ext" -out "$WORK/certs/$n.pem" >/dev/null 2>&1
  cat "$WORK/certs/$n.pem" "$CA" > "$WORK/certs/$n-full.pem"
}
mk_cert site site.example "DNS:site.example,DNS:localhost,IP:127.0.0.1"
mk_cert dot dot.example "DNS:dot.example"

ADMIN_HASH='$argon2id$v=19$m=19456,t=2,p=1$E/RLobwgix2BWMRMT++urA$yEympjJtiDh0ezwSQsnkbsfYAoSzeDAHYw3EsUMBsj4'

write_conf() { # file port reuse [dotcert(yes|no)] [dotport] [sni literal] [dnsport] [rndcport]
  local f=$1 port=$2 reuse=$3 dotcert=${4:-yes} dotport=${5:-$DOT_PORT} sni=${6:-'["dot.example"]'}
  local dns_port=${7:-$DNS_PORT} rndc_port=${8:-$RNDC_PORT}
  local dot_material=""
  if [ "$dotcert" = yes ]; then
    dot_material="cert = \"$WORK/certs/dot-full.pem\"
key = \"$WORK/certs/dot.key\""
  fi
  cat > "$f" <<EOF
[access_log]
enable = false

[admin]
path = "/__admin"
realm = "dot443"

[[admin.users]]
username = "admin"
password_hash = "$ADMIN_HASH"

[[listeners]]
address = "127.0.0.1"
port = $port
root = "$WORK/www"
autoindex = false
http_versions = ["h1", "h2"]
server_name = "site.example"

[listeners.ssl]
cert = "$WORK/certs/site-full.pem"
key = "$WORK/certs/site.key"

[dns]
enabled = true
test_mode = true
listen_addr = "127.0.0.1"
port = $dns_port
rndc_port = $rndc_port
recursion_acl = ["127.0.0.1"]
ecs = false

[dns.modes]
authoritative = true
recursive = false

[dns.dot]
enabled = true
port = $dotport
$dot_material
allow = ["127.0.0.1"]
reuse_tls_port = $reuse
sni = $sni

[dns.doh]
enabled = false
EOF
}

write_conf "$WORK/conf-a.toml" "$SITE_PORT" true
write_conf "$WORK/conf-b.toml" "$SITE2_PORT" false yes "$DOT_PORT" '["dot.example"]' "$DNS2_PORT" "$RNDC2_PORT"
# 无 [dns.dot] cert/key：分流到 DoT 的连接必须沿用**站点证书**（而不是拒绝/冒充）。
write_conf "$WORK/conf-c.toml" "$SITE3_PORT" true no "$DOT3_PORT" '[]' "$DNS3_PORT" "$RNDC3_PORT"

# ---------------------------------------------------------------- 客户端
cat > "$WORK/client.py" <<'PY'
import json, socket, ssl, struct, sys

def name_wire(name):
    out = b""
    for lab in name.rstrip(".").split("."):
        if lab:
            out += bytes([len(lab)]) + lab.encode()
    return out + b"\x00"

def build_query(name, do=False):
    flags = 0x0100 | (0x8000 if do else 0)
    w = struct.pack("!HHHHHH", 0x1234, flags, 1, 0, 0, 1)
    w += name_wire(name) + struct.pack("!HH", 1, 1)
    w += b"\x00" + struct.pack("!HH", 41, 4096) + b"\x00\x00\x00\x00" + b"\x00\x00"
    return w

def skipname(m, o):
    seen = 0
    while seen < 128:
        l = m[o]
        if l & 0xC0 == 0xC0:
            return o + 2
        if l == 0:
            return o + 1
        o += 1 + l
        seen += 1
    raise ValueError("bad name")

def parse(m):
    out = {"rcode": m[3] & 0xF, "an": struct.unpack("!H", m[6:8])[0],
           "ad": bool(struct.unpack("!H", m[2:4])[0] & 0x0020), "addrs": []}
    qd = struct.unpack("!H", m[4:6])[0]
    an = out["an"]
    o = 12
    for _ in range(qd):
        o = skipname(m, o) + 4
    for _ in range(an):
        o = skipname(m, o)
        rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", m[o:o + 10])
        o += 10
        if rtype == 1 and rdlen == 4:
            out["addrs"].append(".".join(str(b) for b in m[o:o + 4]))
        o += rdlen
    return out

def ctx(ca, alpn):
    c = ssl.create_default_context(cafile=ca)
    if alpn:
        c.set_alpn_protocols([alpn])
    return c

def connect(port, ca, sni, alpn):
    s = ctx(ca, alpn).wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=5),
                                 server_hostname=sni)
    cert = s.getpeercert() or {}
    sans = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
    return s, sans

def read_frame(s):
    hdr = s.recv(2)
    if len(hdr) < 2:
        return None
    n = struct.unpack("!H", hdr)[0]
    data = b""
    while len(data) < n:
        chunk = s.recv(n - len(data))
        if not chunk:
            break
        data += chunk
    return data

def main():
    mode = sys.argv[1]
    port = int(sys.argv[2])
    ca = sys.argv[3]
    sni = sys.argv[4]
    alpn = None if sys.argv[5] == "-" else sys.argv[5]
    s, sans = connect(port, ca, sni, alpn)
    out = {"alpn": s.selected_alpn_protocol(), "peer_san": sans}
    try:
        if mode == "dot":
            name = sys.argv[6]
            do = len(sys.argv) > 7 and sys.argv[7] == "do"
            s.sendall(struct.pack("!H", len(build_query(name, do))) + build_query(name, do))
            data = read_frame(s)
            if data is None:
                out["error"] = "eof"
            elif len(data) < 12:
                out["error"] = "short"
            else:
                out.update(parse(data))
        elif mode == "rawdot":  # 发 DNS wire 但按 HTTP 读取（验证不会拿到 DNS 应答）
            name = sys.argv[6]
            w = build_query(name)
            s.sendall(struct.pack("!H", len(w)) + w)
            s.settimeout(3)
            try:
                out["first"] = s.recv(64).hex()
            except Exception as e:
                out["first"] = "timeout/err: %s" % e
        elif mode == "http":
            path = sys.argv[6] if len(sys.argv) > 6 else "/"
            host = sys.argv[7] if len(sys.argv) > 7 else sni
            req = "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % (path, host)
            s.sendall(req.encode())
            s.settimeout(5)
            data = b""
            while True:
                try:
                    chunk = s.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                data += chunk
                if b"\r\n\r\n" in data and len(data) > 64:
                    break
            out["status_line"] = data.split(b"\r\n", 1)[0].decode("latin1")
            out["has_200"] = b" 200 " in data.split(b"\r\n", 1)[0]
    finally:
        s.close()
    print(json.dumps(out))

main()
PY

# ---------------------------------------------------------------- 工具
jget() { python3 -c 'import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1], {"d": d}))' "$1"; }

wait_http() { # port
  for _ in $(seq 1 60); do
    curl -s -o /dev/null -k "https://127.0.0.1:$1/" --resolve "site.example:$1:127.0.0.1" --max-time 1 && return 0
    sleep 0.5
  done
  return 1
}

api() { # method path data
  local m=$1 p=$2 d=${3:-}
  if [ -n "$d" ]; then
    curl -sS -k -u admin:admin -X "$m" -H 'content-type: application/json' -d "$d" "https://127.0.0.1:$SITE_PORT$p"
  else
    curl -sS -k -u admin:admin -X "$m" "https://127.0.0.1:$SITE_PORT$p"
  fi
}

# ---------------------------------------------------------------- 实例 A（reuse=true）
export CRUCIBLE_DNS_STATE_ROOT="$WORK/state-a"
"$BIN" --config "$WORK/conf-a.toml" >"$WORK/server-a.log" 2>&1 &
SRV_PID=$!
if ! wait_http "$SITE_PORT"; then
  echo "instance A did not start; log tail:"; tail -30 "$WORK/server-a.log"; exit 2
fi
pass "instance A started (site TLS :$SITE_PORT, reuse_tls_port=true)"

# 建区 + 记录（经面板 API，named 由实例拉起）
for _ in $(seq 1 40); do
  dig @127.0.0.1 -p "$DNS_PORT" . SOA +time=1 +tries=1 >/dev/null 2>&1 && break
  sleep 0.5
done
api POST /__admin/api/dns/zones '{"name":"dot443.test"}' >/dev/null
api POST /__admin/api/dns/records '{"zone":"dot443.test","name":"www","rtype":"A","ttl":300,"rdata":"192.0.2.44"}' >/dev/null
DNS_OK=0
for _ in $(seq 1 40); do
  if dig @127.0.0.1 -p "$DNS_PORT" www.dot443.test A +short +time=1 +tries=1 2>/dev/null | grep -q '192.0.2.44'; then
    DNS_OK=1; break
  fi
  sleep 0.5
done
if [ "$DNS_OK" = 1 ]; then
  pass "named authoritative zone ready (www.dot443.test A 192.0.2.44)"
else
  fail "named zone not ready"
fi

# 1) openssl s_client -alpn dot：ALPN 协商 + dot 证书
openssl s_client -connect "127.0.0.1:$SITE_PORT" -servername dot.example -alpn dot \
  -CAfile "$CA" -verify_return_error </dev/null >"$WORK/openssl-dot.txt" 2>&1
if grep -qi 'ALPN protocol: dot' "$WORK/openssl-dot.txt" \
   && grep -qi 'Protocol: TLSv1\.3' "$WORK/openssl-dot.txt" \
   && grep -q 'Verify return code: 0 (ok)' "$WORK/openssl-dot.txt"; then
  pass "openssl s_client -alpn dot: TLS1.3 + ALPN protocol: dot"
else
  fail "openssl s_client -alpn dot did not negotiate dot"; sed -n '1,20p' "$WORK/openssl-dot.txt"
fi

# 2) openssl s_client -alpn dot 发真实 DNS 查询（2 字节长度前缀 + wire）
python3 - "$WORK/req-dot.bin" <<'PY'
import struct, sys
def name_wire(n):
    out = b""
    for lab in n.rstrip(".").split("."):
        out += bytes([len(lab)]) + lab.encode()
    return out + b"\x00"
w = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 1)
w += name_wire("www.dot443.test") + struct.pack("!HH", 1, 1)
w += b"\x00" + struct.pack("!HH", 41, 4096) + b"\x00\x00\x00\x00" + b"\x00\x00"
open(sys.argv[1], "wb").write(struct.pack("!H", len(w)) + w)
PY
timeout 6 sh -c "cat '$WORK/req-dot.bin' | openssl s_client -connect 127.0.0.1:$SITE_PORT -servername dot.example -alpn dot -CAfile '$CA' -verify_return_error -quiet -ign_eof" \
  >"$WORK/openssl-dot-raw.bin" 2>"$WORK/openssl-dot-raw.err" || true
OPENSSL_DNS=$(python3 - "$WORK/openssl-dot-raw.bin" <<'PY'
import struct, sys
raw = open(sys.argv[1], "rb").read()
digest = None
# 找到 DNS 应答：2 字节长度前缀 + ID 0x1234
for i in range(max(0, len(raw) - 12)):
    if raw[i:i+2] == b"\x12\x34":
        n = struct.unpack("!H", raw[i-2:i])[0] if i >= 2 else 0
        body = raw[i:i+n]
        if n >= 12 and len(body) == n:
            an = struct.unpack("!H", body[6:8])[0]
            if an >= 1 and b"\xc0\x00\x02\x2c" in body:  # 192.0.2.44
                digest = "rcode=%d an=%d" % (body[3] & 0xF, an)
                break
print(digest or "not-found")
PY
)
if [ "$OPENSSL_DNS" != "not-found" ]; then
  pass "openssl s_client -alpn dot carried DNS query -> answer ($OPENSSL_DNS, 192.0.2.44)"
else
  fail "openssl s_client -alpn dot DNS query got no answer"
  echo "--- raw head ---"; xxd -l 160 "$WORK/openssl-dot-raw.bin" 2>/dev/null | head
fi

# 3) 同端口 curl --http2（站点证书 / ALPN h2）
H2=$(curl -sS --http2 --cacert "$CA" --resolve "site.example:$SITE_PORT:127.0.0.1" \
     -o /dev/null -w '%{http_code} %{http_version}' "https://site.example:$SITE_PORT/" 2>"$WORK/curl-h2.err")
if [ "$H2" = "200 2" ]; then
  pass "curl --http2 site.example:$SITE_PORT -> 200 HTTP/2 (site cert verified)"
else
  fail "curl --http2 -> '$H2'"; cat "$WORK/curl-h2.err"
fi

# 4) 同端口 h1（显式 TLS1.2 / 默认 TLS1.3）
H1=$(curl -sS --http1.1 --cacert "$CA" --resolve "site.example:$SITE_PORT:127.0.0.1" \
     -o /dev/null -w '%{http_code} %{http_version}' "https://site.example:$SITE_PORT/" 2>/dev/null)
if [ "$H1" = "200 1.1" ]; then
  pass "curl --http1.1 site.example:$SITE_PORT -> 200 HTTP/1.1"
else
  fail "curl --http1.1 -> '$H1'"
fi
H1_12=$(curl -sS --http1.1 --tls-max 1.2 --cacert "$CA" --resolve "site.example:$SITE_PORT:127.0.0.1" \
     -o /dev/null -w '%{http_code} %{http_version}' "https://site.example:$SITE_PORT/" 2>/dev/null)
if [ "$H1_12" = "200 1.1" ]; then
  pass "curl --tls-max 1.2 site.example:$SITE_PORT -> 200 HTTP/1.1"
else
  fail "curl TLS1.2 h1 -> '$H1_12'"
fi

# 5) 未声明 ALPN 的普通 TLS 走 HTTP
NOALPN=$(python3 "$WORK/client.py" http "$SITE_PORT" "$CA" site.example - / 2>/dev/null)
if [ "$(echo "$NOALPN" | jq -r '.status_line' 2>/dev/null)" = "HTTP/1.1 200 OK" ]; then
  pass "TLS without ALPN -> HTTP 200 (not DNS): $(echo "$NOALPN" | jq -c '{alpn,status_line}')"
else
  fail "TLS without ALPN did not serve HTTP: $NOALPN"
fi

# 6) DoT over site port（python 客户端，CA 校验 + ALPN + dot 证书）
DOT_SITE=$(python3 "$WORK/client.py" dot "$SITE_PORT" "$CA" dot.example dot www.dot443.test 2>/dev/null)
if [ "$(echo "$DOT_SITE" | jq -r '.alpn' 2>/dev/null)" = "dot" ] \
   && [ "$(echo "$DOT_SITE" | jq -r '.rcode' 2>/dev/null)" = "0" ] \
   && echo "$DOT_SITE" | jq -e '.addrs | index("192.0.2.44")' >/dev/null 2>&1; then
  pass "DoT over :$SITE_PORT (ALPN dot, SNI dot.example, dot cert): rcode=0 addrs=$(echo "$DOT_SITE" | jq -c .addrs)"
else
  fail "DoT over site port failed: $DOT_SITE"
fi
if echo "$DOT_SITE" | jq -e '.peer_san | index("dot.example")' >/dev/null 2>&1; then
  pass "DoT over site port presents the DoT certificate (SAN dot.example)"
else
  fail "DoT over site port did not present dot cert: $DOT_SITE"
fi

# 7) ALPN=dot 但 SNI 不在白名单 ⇒ 站点流量（不拿 DNS 应答）
WRONG_SNI=$(python3 "$WORK/client.py" rawdot "$SITE_PORT" "$CA" site.example dot www.dot443.test 2>/dev/null)
if echo "$WRONG_SNI" | jq -e '.peer_san | index("site.example")' >/dev/null 2>&1; then
  FIRST=$(echo "$WRONG_SNI" | jq -r '.first')
  case "$FIRST" in
    48545450*) pass "ALPN=dot + SNI site.example -> site cert + HTTP response (SNI whitelist enforced)" ;;
    ""|*timeout*) pass "ALPN=dot + SNI site.example -> site cert + connection closed/timeout, no DNS answer (SNI whitelist enforced)" ;;
    *) if echo "$FIRST" | grep -qi 'c000022c'; then
         fail "ALPN=dot + SNI site.example leaked a DNS answer: $WRONG_SNI"
       else
         pass "ALPN=dot + SNI site.example -> non-DNS reply (SNI whitelist enforced): first=$FIRST"
       fi ;;
  esac
else
  fail "ALPN=dot + SNI site.example did not use site cert: $WRONG_SNI"
fi

# 8) 独立 DoT 端口回归（无 ALPN 的旧客户端）
DOT_OLD=$(python3 "$WORK/client.py" dot "$DOT_PORT" "$CA" dot.example - www.dot443.test 2>/dev/null)
if [ "$(echo "$DOT_OLD" | jq -r '.rcode' 2>/dev/null)" = "0" ] \
   && echo "$DOT_OLD" | jq -e '.addrs | index("192.0.2.44")' >/dev/null 2>&1; then
  pass "dedicated DoT :$DOT_PORT still serves DNS (no ALPN, legacy client)"
else
  fail "dedicated DoT port regression: $DOT_OLD"
fi

# 9) 站点 h2 流量不受 DoT 影响（连续 20 次混合 ALPN dot / h2 连接）
MIX_OK=1
for i in $(seq 1 10); do
  c=$(curl -sS --http2 --cacert "$CA" --resolve "site.example:$SITE_PORT:127.0.0.1" \
      -o /dev/null -w '%{http_code} %{http_version}' "https://site.example:$SITE_PORT/" 2>/dev/null)
  [ "$c" = "200 2" ] || { MIX_OK=0; break; }
  d=$(python3 "$WORK/client.py" dot "$SITE_PORT" "$CA" dot.example dot www.dot443.test 2>/dev/null | jq -r '.rcode')
  [ "$d" = "0" ] || { MIX_OK=0; break; }
done
if [ "$MIX_OK" = 1 ]; then
  pass "mixed ALPN dot / h2 traffic on one port: 10/10 each OK"
else
  fail "mixed traffic failed at iteration $i"
fi

kill -TERM "$SRV_PID" 2>/dev/null
wait "$SRV_PID" 2>/dev/null
SRV_PID=
sleep 1

# ---------------------------------------------------------------- 实例 B（reuse=false，零变化对照）
export CRUCIBLE_DNS_STATE_ROOT="$WORK/state-b"
"$BIN" --config "$WORK/conf-b.toml" >"$WORK/server-b.log" 2>&1 &
SRV2_PID=$!
if wait_http "$SITE2_PORT"; then
  B_H2=$(curl -sS --http2 --cacert "$CA" --resolve "site.example:$SITE2_PORT:127.0.0.1" \
       -o /dev/null -w '%{http_code} %{http_version}' "https://site.example:$SITE2_PORT/" 2>/dev/null)
  B_DOT=$(python3 "$WORK/client.py" rawdot "$SITE2_PORT" "$CA" site.example dot www.dot443.test 2>/dev/null)
  B_ALPN=$(echo "$B_DOT" | jq -r '.alpn')
  if [ "$B_H2" = "200 2" ] && [ "$B_ALPN" = "null" ]; then
    pass "reuse_tls_port=false: h2 200 and ALPN dot NOT negotiated (zero change) [first=$(echo "$B_DOT" | jq -r '.first')]"
  else
    fail "reuse_tls_port=false control failed: h2='$B_H2' alpn='$B_ALPN' dot=$B_DOT"
  fi
else
  fail "instance B did not start"
fi
kill -TERM "$SRV2_PID" 2>/dev/null
wait "$SRV2_PID" 2>/dev/null
SRV2_PID=
sleep 1

# ---------------------------------------------------------------- 实例 C（reuse=true，无 dot 专用证书）
# 证书选择：没配 [dns.dot] cert/key 时必须沿用**站点证书**完成 DoT 握手（不能拒绝，
# 也不能拿站点证书去冒充 dot 名字）。sni=[] 只按 ALPN 判定。
export CRUCIBLE_DNS_STATE_ROOT="$WORK/state-c"
"$BIN" --config "$WORK/conf-c.toml" >"$WORK/server-c.log" 2>&1 &
SRV3_PID=$!
if wait_http "$SITE3_PORT"; then
  # 实例 C 是独立 state root：同样先建区/记录，再验证 DoT 分流。
  for _ in $(seq 1 40); do
    dig @127.0.0.1 -p "$DNS3_PORT" . SOA +time=1 +tries=1 >/dev/null 2>&1 && break
    sleep 0.5
  done
  curl -sS -k -u admin:admin -X POST -H 'content-type: application/json' \
    -d '{"name":"dot443.test"}' "https://127.0.0.1:$SITE3_PORT/__admin/api/dns/zones" >/dev/null 2>&1
  curl -sS -k -u admin:admin -X POST -H 'content-type: application/json' \
    -d '{"zone":"dot443.test","name":"www","rtype":"A","ttl":300,"rdata":"192.0.2.44"}' \
    "https://127.0.0.1:$SITE3_PORT/__admin/api/dns/records" >/dev/null 2>&1
  for _ in $(seq 1 40); do
    dig @127.0.0.1 -p "$DNS3_PORT" www.dot443.test A +short +time=1 +tries=1 2>/dev/null | grep -q '192.0.2.44' && break
    sleep 0.5
  done
  C_DOT=$(python3 "$WORK/client.py" dot "$SITE3_PORT" "$CA" site.example dot www.dot443.test 2>/dev/null)
  if [ "$(echo "$C_DOT" | jq -r '.alpn' 2>/dev/null)" = "dot" ] \
     && [ "$(echo "$C_DOT" | jq -r '.rcode' 2>/dev/null)" = "0" ] \
     && echo "$C_DOT" | jq -e '.peer_san | index("site.example")' >/dev/null 2>&1 \
     && echo "$C_DOT" | jq -e '.addrs | index("192.0.2.44")' >/dev/null 2>&1; then
    pass "reuse without [dns.dot] cert: ALPN dot uses the site certificate + DNS answer"
  else
    fail "reuse without dot cert did not use site cert / DNS: $C_DOT"
  fi
  C_H2=$(curl -sS --http2 --cacert "$CA" --resolve "site.example:$SITE3_PORT:127.0.0.1" \
       -o /dev/null -w '%{http_code} %{http_version}' "https://site.example:$SITE3_PORT/" 2>/dev/null)
  if [ "$C_H2" = "200 2" ]; then
    pass "reuse without dot cert: site h2 traffic still 200 HTTP/2"
  else
    fail "reuse without dot cert: site h2 -> '$C_H2'"
  fi
else
  fail "instance C did not start"
fi
kill -TERM "$SRV3_PID" 2>/dev/null
wait "$SRV3_PID" 2>/dev/null
SRV3_PID=

echo
echo "G-08 DoT TLS-port reuse: PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
[ -n "${DNSDOT_KEEP:-}" ] || true
[ "$FAIL" = 0 ]
