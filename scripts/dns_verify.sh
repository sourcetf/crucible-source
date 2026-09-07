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
PORT=$(echo "$ST" | grep -oE "\"port\":[0-9]+" | head -1 | cut -d: -f2)
[ -n "${PORT:-}" ] || PORT=5353
TM=$(echo "$ST" | grep -o "\"test_mode\":[a-z]*" | head -1 | cut -d: -f2)
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
dig @127.0.0.1 -p $PORT cloudflare.com A +short +time=6 +tries=1 | grep -qE "^[0-9]" && ok "recursion" || bad "recursion"
B64="ct0AAQABAAAAAAAABXNtb2tlBHRlc3QAAAEAAQ=="
CT=$(curl -s -m 10 -o /dev/null -w "%{content_type}" "$DOHBASE/dns-query?dns=$B64")
echo "$CT" | grep -q "application/dns-message" && ok "DoH GET" || bad "DoH GET: $CT"
CT2=$(curl -s -m 10 -o /dev/null -w "%{content_type}" -H "Content-Type: application/dns-message" --data-binary @/tmp/q2.bin "$DOHBASE/dns-query")
echo "$CT2" | grep -q "application/dns-message" && ok "DoH POST" || bad "DoH POST: $CT2"
echo "== 6. DoT =="
{ printf "\000\034"; cat /tmp/q2.bin; sleep 3; } | timeout 9 openssl s_client -connect 127.0.0.1:$DOTP -quiet 2>/dev/null | strings | grep -q "smoke" && ok "DoT" || bad "DoT"
echo "== 7. 汇总 =="
api "$BASE/api/dns/status" | grep -q "\"named_running\":true" && ok "final status" || bad "final status"
echo "PASS=$PASS FAIL=$FAIL (port=$PORT dot=$DOTP)"
