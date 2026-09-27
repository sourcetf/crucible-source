#!/bin/sh
set -u
BASE="${1:-http://127.0.0.1:19095/__admin}"
AUTH="${2:-admin:admin}"
PASS=0; FAIL=0
ok(){ PASS=$((PASS+1)); echo "PASS: $1"; }
bad(){ FAIL=$((FAIL+1)); echo "FAIL: $1"; }
api(){ curl -s -m 20 -u "$AUTH" "$@"; }
post(){ api -H "Content-Type: application/json" -d "$2" "$BASE$1"; }
ST=$(api "$BASE/api/dns/status")
# 端口必须从**顶层** `port` 取。旧实现是 `grep -oE '"port":[0-9]+' | head -1` ——
# 但 status JSON 里 `dot` 是嵌套对象、序列化在前，所以第一个 `"port"` 是 **DoT 端口**
# （测试态 11853）。于是这个脚本把明文 DNS 查询全打到 DoT 口上：A/AAAA/SOA/NS/AXFR/RPZ/
# 递归 **全部误报 FAIL**（实测 FAIL=15），而服务其实是好的 —— 「验收脚本永远不通过」
# 就等于 DNS 这条线没人能验。用 JSON 解析取顶层字段，不再靠字段顺序。
set -- $(printf '%s' "$ST" | python3 -c 'import json,sys
try:
    d = json.load(sys.stdin)
except Exception:
    print("5353 false"); raise SystemExit
print(d.get("port") or 5353, "true" if d.get("test_mode") else "false",
      "true" if (d.get("modes") or {}).get("root") else "false")' 2>/dev/null)
PORT="${1:-5353}"
TM="${2:-false}"
ROOTMODE="${3:-false}"
DOTP=853; [ "$TM" = "true" ] && DOTP=11853
DOHBASE="http://127.0.0.1:19095"
echo "== 0. named reconcile =="
echo "$ST" | grep -q "\"named_running\":true" && ok "named_running=true" || bad "named_running"
echo "== 1. 权威 zone/records + dig 全类型 =="
post /api/dns/zones "{\"action\":\"add\",\"name\":\"verify.test\",\"kind\":\"master\"}" >/dev/null
post /api/dns/records "{\"action\":\"add\",\"zone\":\"verify.test\",\"name\":\"@\",\"rtype\":\"A\",\"ttl\":300,\"rdata\":\"192.0.2.1\"}" >/dev/null
post /api/dns/records "{\"action\":\"add\",\"zone\":\"verify.test\",\"name\":\"@\",\"rtype\":\"AAAA\",\"ttl\":300,\"rdata\":\"2001:db8::1\"}" >/dev/null
post /api/dns/records "{\"action\":\"add\",\"zone\":\"verify.test\",\"name\":\"www\",\"rtype\":\"CNAME\",\"ttl\":300,\"rdata\":\"verify.test.\"}" >/dev/null
post /api/dns/records "{\"action\":\"add\",\"zone\":\"verify.test\",\"name\":\"@\",\"rtype\":\"MX\",\"ttl\":300,\"rdata\":\"10 mail.verify.test.\"}" >/dev/null
post /api/dns/records "{\"action\":\"add\",\"zone\":\"verify.test\",\"name\":\"@\",\"rtype\":\"TXT\",\"ttl\":300,\"rdata\":\"\\\"v=spf1 -all\\\"\"}" >/dev/null
post /api/dns/records "{\"action\":\"add\",\"zone\":\"verify.test\",\"name\":\"@\",\"rtype\":\"CAA\",\"ttl\":300,\"rdata\":\"0 issue \\\"letsencrypt.org\\\"\"}" >/dev/null
post /api/dns/records "{\"action\":\"add\",\"zone\":\"verify.test\",\"name\":\"@\",\"rtype\":\"SRV\",\"ttl\":300,\"rdata\":\"10 10 5060 sip\"}" >/dev/null
sleep 3
A=$(dig @127.0.0.1 -p $PORT verify.test A +short +time=3 +tries=1)
echo "$A" | grep -q "192.0.2.1" && ok "A" || bad "A: $A"
dig @127.0.0.1 -p $PORT verify.test AAAA +short +time=3 +tries=1 | grep -q "2001:db8::1" && ok "AAAA" || bad "AAAA"
dig @127.0.0.1 -p $PORT www.verify.test +short +time=3 +tries=1 | grep -q "192.0.2.1" && ok "CNAME" || bad "CNAME"
dig @127.0.0.1 -p $PORT verify.test MX +short +time=3 +tries=1 | grep -q "mail.verify.test" && ok "MX" || bad "MX"
dig @127.0.0.1 -p $PORT verify.test TXT +short +time=3 +tries=1 | grep -q "spf1" && ok "TXT" || bad "TXT"
dig @127.0.0.1 -p $PORT verify.test CAA +short +time=3 +tries=1 | grep -q "letsencrypt" && ok "CAA" || bad "CAA"
dig @127.0.0.1 -p $PORT verify.test SOA +short +time=3 +tries=1 | grep -q "ns1.verify.test" && ok "SOA" || bad "SOA"
dig @127.0.0.1 -p $PORT verify.test NS +short +time=3 +tries=1 | grep -q "ns1.verify.test" && ok "NS" || bad "NS"
dig @127.0.0.1 -p $PORT verify.test SRV +short +time=3 +tries=1 | grep -q "5060" && ok "SRV" || bad "SRV"
echo "== 2. DNSSEC =="
dig @127.0.0.1 -p $PORT verify.test DNSKEY +time=4 +tries=1 | grep -q "DNSKEY" && ok "DNSKEY" || bad "DNSKEY"
dig @127.0.0.1 -p $PORT verify.test A +dnssec +time=4 +tries=1 | grep -q "RRSIG" && ok "RRSIG" || bad "RRSIG"
dig @127.0.0.1 -p $PORT verify.test NSEC3PARAM +short +time=4 +tries=1 | grep -q . && ok "NSEC3PARAM" || bad "NSEC3PARAM"
dig @127.0.0.1 -p $PORT verify.test CDS +time=4 +tries=1 | grep -q "CDS" && ok "CDS" || bad "CDS"
dig @127.0.0.1 -p $PORT verify.test CDNSKEY +time=4 +tries=1 | grep -q "CDNSKEY" && ok "CDNSKEY" || bad "CDNSKEY"
echo "== 3. AXFR =="
dig @127.0.0.1 -p $PORT verify.test AXFR +time=4 +tries=1 | grep -q "SOA" && ok "AXFR in-ACL" || bad "AXFR"
echo "== 4. RPZ =="
dig @127.0.0.1 -p $PORT blocked.crucible.test +time=4 +tries=1 | grep -q "NXDOMAIN" && ok "RPZ nxdomain" || bad "RPZ"
echo "== 5. 递归 + DoH =="
# root zone 模式（`modes.root = true`）下 named 对**根**是权威的，公共域名会得到
# 权威 NXDOMAIN（测试配置就是如此：`zone "." { type primary; }`）。此时「递归」这项
# 在该环境里**无法通过**，如实跳过并说明，而不是报一个假 FAIL（那会让整个脚本永远
# 不通过，验收形同虚设）。生产配置 root 关闭，递归正常（已实测 dig cloudflare.com 有应答）。
if [ "$ROOTMODE" = "true" ]; then
  echo "SKIP: recursion（本实例开了 root zone 模式，对根权威 ⇒ 公共域名返回权威 NXDOMAIN）"
else
  dig @127.0.0.1 -p $PORT cloudflare.com A +short +time=6 +tries=1 | grep -qE "^[0-9]" && ok "recursion" || bad "recursion"
fi
B64="ct0AAQABAAAAAAAABXNtb2tlBHRlc3QAAAEAAQ=="
# 查询报文**在这里生成**：旧实现直接 `--data-binary @/tmp/q2.bin`，但没有任何地方写过
# 那个文件（它原本靠另一个脚本 dns_smoke.sh 留下），于是 DoH POST 与 DoT 两项**恒失败**。
Q2=/tmp/q2.bin
python3 -c 'import base64,sys; open(sys.argv[1],"wb").write(base64.b64decode(sys.argv[2]))' "$Q2" "$B64"
CT=$(curl -s -m 10 -o /dev/null -w "%{content_type}" "$DOHBASE/dns-query?dns=$B64")
echo "$CT" | grep -q "application/dns-message" && ok "DoH GET" || bad "DoH GET: $CT"
CT2=$(curl -s -m 10 -o /dev/null -w "%{content_type}" -H "Content-Type: application/dns-message" --data-binary @$Q2 "$DOHBASE/dns-query")
echo "$CT2" | grep -q "application/dns-message" && ok "DoH POST" || bad "DoH POST: $CT2"
echo "== 6. DoT =="
# 用 python3 + ssl 做 DoT 探测，**不用 openssl**（用户明确要求项目不依赖 openssl，
# 现场也可能已卸载它）。旧实现 `openssl s_client … | strings` 既违反该要求，
# 又会在 openssl 缺失时静默变 FAIL。
if python3 - "$DOTP" "$Q2" <<'PY'
import socket, ssl, struct, sys
port, path = int(sys.argv[1]), sys.argv[2]
q = open(path, "rb").read()
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
try:
    with socket.create_connection(("127.0.0.1", port), timeout=8) as raw:
        with ctx.wrap_socket(raw, server_hostname="crucible.local") as tls:
            tls.sendall(struct.pack(">H", len(q)) + q)   # RFC7858: 2 字节长度前缀
            hdr = tls.recv(2)
            if len(hdr) < 2:
                sys.exit(1)
            n = struct.unpack(">H", hdr)[0]
            data = b""
            while len(data) < n:
                chunk = tls.recv(n - len(data))
                if not chunk:
                    break
                data += chunk
            # 问题段会被回显，因此能查到查询名
            sys.exit(0 if b"smoke" in data else 1)
except Exception:
    sys.exit(1)
PY
then ok "DoT"; else bad "DoT"; fi
echo "== 7. 汇总 =="
api "$BASE/api/dns/status" | grep -q "\"named_running\":true" && ok "final status" || bad "final status"
echo "PASS=$PASS FAIL=$FAIL (port=$PORT dot=$DOTP root=$ROOTMODE test_mode=$TM)"
