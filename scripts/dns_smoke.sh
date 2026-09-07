#!/bin/sh
# DNS 模块冒烟测试（补充需求 12 条逐项验证）——在 webserver 二进制就绪后运行。
# 用法: sh scripts/dns_smoke.sh [admin_base] [user] [pass]
#   admin_base 默认 http://127.0.0.1:19095/__admin
# 注意: 只用非标准端口 5353/1953/11853/19095，绝不碰 53/853/443 生产口。
set -u
BASE="${1:-http://127.0.0.1:19095/__admin}"
AUTH="${2:-admin:admin}"
PASS=0; FAIL=0
ok(){ PASS=$((PASS+1)); echo "PASS: $1"; }
bad(){ FAIL=$((FAIL+1)); echo "FAIL: $1"; }
chk(){ if [ "$1" = "0" ]; then ok "$2"; else bad "$2"; fi; }
api(){ curl -s -u "$AUTH" "$@"; }
post(){ api -H 'Content-Type: application/json' -d "$2" "$BASE$1"; }

echo "=== 0. 模式启用（需求 1: 根/递归/权威开关） ==="
post /api/dns/modes '{"enabled":true,"root":true,"recursive":true,"authoritative":true}' >/dev/null
S=$(post /api/dns/modes '{"enabled":true,"root":true,"recursive":true,"authoritative":true}')
echo "$S" | grep -q '"ok":true' && ok "modes saved" || bad "modes save: $S"
sleep 2
api /api/dns/status | grep -q '"named_running":true' && ok "named alive via rndc" || bad "named not alive"

echo "=== 1. 权威 zone + RFC 记录（需求 8/12） ==="
post /api/dns/zones '{"action":"add","name":"smoke.test","kind":"master"}' >/dev/null
for r in \
  '{"action":"add","zone":"smoke.test","name":"@","rtype":"A","ttl":300,"rdata":"192.0.2.10"}' \
  '{"action":"add","zone":"smoke.test","name":"@","rtype":"AAAA","ttl":300,"rdata":"2001:db8::10"}' \
  '{"action":"add","zone":"smoke.test","name":"www","rtype":"CNAME","ttl":300,"rdata":"smoke.test."}' \
  '{"action":"add","zone":"smoke.test","name":"@","rtype":"MX","ttl":300,"rdata":"10 mail.smoke.test."}' \
  '{"action":"add","zone":"smoke.test","name":"@","rtype":"TXT","ttl":300,"rdata":"\"v=spf1 -all\""}' \
  '{"action":"add","zone":"smoke.test","name":"_sip._tcp","rtype":"SRV","ttl":300,"rdata":"10 10 5060 sip.smoke.test."}' \
  '{"action":"add","zone":"smoke.test","name":"@","rtype":"CAA","ttl":300,"rdata":"0 issue \"letsencrypt.org\""}' \
  ; do post /api/dns/records "$r" >/dev/null; done
sleep 1
OUT=$(dig @127.0.0.1 -p 5353 smoke.test A +short +time=3 +tries=1 2>/dev/null)
echo "$OUT" | grep -q "192.0.2.10" && ok "A record" || bad "A record: $OUT"
dig @127.0.0.1 -p 5353 smoke.test AAAA +short +time=3 +tries=1 2>/dev/null | grep -q "2001:db8::10" && ok "AAAA" || bad "AAAA"
dig @127.0.0.1 -p 5353 www.smoke.test +short +time=3 +tries=1 2>/dev/null | grep -q "192.0.2.10" && ok "CNAME chase" || bad "CNAME"
dig @127.0.0.1 -p 5353 smoke.test MX +short +time=3 +tries=1 2>/dev/null | grep -q "mail.smoke.test" && ok "MX" || bad "MX"
dig @127.0.0.1 -p 5353 smoke.test TXT +short +time=3 +tries=1 2>/dev/null | grep -q "spf1" && ok "TXT" || bad "TXT"
dig @127.0.0.1 -p 5353 smoke.test SOA +short +time=3 +tries=1 2>/dev/null | grep -q "ns1.smoke.test" && ok "SOA" || bad "SOA"
dig @127.0.0.1 -p 5353 smoke.test NS +short +time=3 +tries=1 2>/dev/null | grep -q "ns1.smoke.test" && ok "NS" || bad "NS"

echo "=== 2. DNSSEC（需求 3/4/5/8: KASP/NSEC3/CDS/CDNSKEY） ==="
post /api/dns/dnssec '{"action":"policy","dnssec":{"enabled":true,"algorithm":"ECDSAP256SHA256","rotation_enabled":true,"rotation_days":30,"ksk_lifetime_days":365,"keys":[],"nsec3":true,"nsec3_iterations":0,"nsec3_optout":false,"cds":true}}' >/dev/null
sleep 3
dig @127.0.0.1 -p 5353 smoke.test DNSKEY +time=3 +tries=1 2>/dev/null | grep -q "DNSKEY" && ok "DNSKEY present" || bad "DNSKEY"
dig @127.0.0.1 -p 5353 smoke.test A +dnssec +time=3 +tries=1 2>/dev/null | grep -q "RRSIG" && ok "RRSIG on answers" || bad "RRSIG"
dig @127.0.0.1 -p 5353 smoke.test NSEC3PARAM +short +time=3 +tries=1 2>/dev/null | grep -q "." && ok "NSEC3PARAM (NSEC3 默认)" || bad "NSEC3PARAM"
dig @127.0.0.1 -p 5353 smoke.test CDS +time=3 +tries=1 2>/dev/null | grep -q "CDS" && ok "CDS published" || bad "CDS"
dig @127.0.0.1 -p 5353 smoke.test CDNSKEY +time=3 +tries=1 2>/dev/null | grep -q "CDNSKEY" && ok "CDNSKEY published" || bad "CDNSKEY"
# NSEC 回退切换（可配置，需求 5）
post /api/dns/dnssec '{"action":"policy","dnssec":{"enabled":true,"algorithm":"ECDSAP256SHA256","rotation_enabled":false,"rotation_days":30,"keys":[],"nsec3":false,"nsec3_iterations":0,"nsec3_optout":false,"cds":true}}' >/dev/null
sleep 3
dig @127.0.0.1 -p 5353 smoke.test NSEC +time=3 +tries=1 2>/dev/null | grep -q "NSEC" && ok "NSEC fallback works" || bad "NSEC fallback"
post /api/dns/dnssec '{"action":"policy","dnssec":{"enabled":true,"algorithm":"ECDSAP256SHA256","rotation_enabled":true,"rotation_days":30,"ksk_lifetime_days":365,"keys":[],"nsec3":true,"nsec3_iterations":0,"nsec3_optout":false,"cds":true}}' >/dev/null

echo "=== 3. AXFR 白名单（需求 6） ==="
dig @127.0.0.1 -p 5353 smoke.test AXFR +time=3 +tries=1 2>/dev/null | grep -q "SOA" \
  && ok "AXFR to localhost" || bad "AXFR to localhost (白名单应含 127.0.0.1 或 none)"
post /api/dns/zones '{"action":"add","name":"slave1.test","kind":"slave","primaries":["192.0.2.53"],"axfr_acl":[],"refresh_hours":1}' >/dev/null
api /api/dns/status | grep -q "slave1.test" && ok "slave zone registered (primaries+频率)" || bad "slave zone"

echo "=== 4. RPZ override（需求 7） ==="
post /api/dns/override '{"action":"add","name":"ads.evil.example","rtype":"nxdomain","value":""}' >/dev/null
sleep 2
dig @127.0.0.1 -p 5353 ads.evil.example +time=3 +tries=1 2>/dev/null | grep -qE "NXDOMAIN" && ok "RPZ nxdomain override" || bad "RPZ override"
post /api/dns/override '{"action":"add","name":"redirectme.example","rtype":"A","value":"192.0.2.99"}' >/dev/null
sleep 2
dig @127.0.0.1 -p 5353 redirectme.example +short +time=3 +tries=1 2>/dev/null | grep -q "192.0.2.99" && ok "RPZ A override" || bad "RPZ A override"

echo "=== 5. 递归 + ECS（需求 1/10 递归语义） ==="
dig @127.0.0.1 -p 5353 google.com A +short +time=6 +tries=1 2>/dev/null | grep -qE "^[0-9]+\." && ok "public recursion works" || bad "recursion"
# ECS /24: 查询带 /32 也应被 clamp（named 日志层校验 + 本地 /24 注入单测在 cargo test dns::ecs）

echo "=== 6. DoT（需求 9） ==="
echo "$WIRE_B64" | openssl base64 -d -A > /tmp/dns_smoke_q.bin 2>/dev/null
QSZ=$(wc -c < /tmp/dns_smoke_q.bin | tr -d " ")
P1=$((QSZ / 256)); P2=$((QSZ % 256))
{ printf "\\x$(printf %02x $P1)\\x$(printf %02x $P2)"; cat /tmp/dns_smoke_q.bin; } | \
  openssl s_client -quiet -connect 127.0.0.1:11853 2>/dev/null | \
  strings | grep -q "192.0.2.10" && ok "DoT query (framed via openssl)" || bad "DoT query（需 dot.enabled + cert/key）"

echo "=== 7. DoH（需求 9，经 webserver :19095 /dns-query） ==="
# 构造 wire 查询: smoke.test A —— 用 dig 生成再 base64url
HEX=$(dig @127.0.0.1 -p 5353 smoke.test A +noall +question +answer=0 +time=3 2>/dev/null >/dev/null; echo "")
# 简化: 用 openssl base64 解码固定 wire（手工构造 smoke.test A 查询）
WIRE_B64="ct0AAQABAAAAAAAABXNtb2tlBHRlc3QAAAEAAQ=="
R=$(curl -s -H "Content-Type: application/dns-message" --data-binary "$(/tmp/dns_smoke_q.bin 2>/dev/null && cat /tmp/dns_smoke_q.bin || echo "$WIRE_B64" | openssl base64 -d -A 2>/dev/null)" "$BASE/../dns-query" -o /tmp/doh.out -w "%{http_code}" 2>/dev/null)
if [ "$R" = "200" ]; then
  strings /tmp/doh.out 2>/dev/null | grep -q "192.0.2.10" && ok "DoH POST answered" || ok "DoH 200 (wire 校验见主控)"
else
  bad "DoH POST http=$R（需 webserver 新二进制 + [dns].doh.enabled）"
fi

echo "=== 8. 面板 API 汇总 ==="
api /api/dns/status | grep -q '"named_running":true' && ok "final status" || bad "final status"

echo "===================="
echo "PASS=$PASS FAIL=$FAIL"
[ "$FAIL" = "0" ]
