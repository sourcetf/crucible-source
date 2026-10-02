#!/bin/sh
# 四轮改动后的**只读**回归扫（生产端口，全部是 GET/HEAD/OPTIONS，不改任何状态、不写盘）。
# 目的：4 轮共 62 处改动全部落盘部署后，逐协议/逐特性确认没有横向回归。
set -u
PLAIN=http://127.0.0.1:9095
FAIR=http://127.0.0.1:9081
T12=https://127.0.0.1:9445
T13=https://127.0.0.1:9446
H3=https://127.0.0.1:8443

p() { # label url [curl args...]
  _l=$1; _u=$2; shift 2
  _c=$(curl -s -o /dev/null -w '%{http_code}' --max-time 12 "$@" "$_u" 2>/dev/null)
  printf '  %-30s %s\n' "$_l" "${_c:-ERR}"
}

echo "=== A. h1 明文（:9095，root=www-apps，18 个引擎）==="
for e in rust go c lua python php asp jsp do ruby perl wsgi asgi psgi rack cgi tsx aspnet; do
  p "/$e/" "$PLAIN/$e/"
done

echo "=== B. 静态面 ==="
p "9095 /" "$PLAIN/"
p "9081 / (fair-plain)" "$FAIR/"
p "9445 / (tls1.2)" "$T12" -k
p "9446 / (tls1.3)" "$T13" -k

echo "=== C. h2 / h3 ==="
p "9445 h2" "$T12/" -k --http2
p "8443 h2" "$H3/" -k --http2
p "8443 h3" "$H3/" -k --http3-only

echo "=== D. 管理面 / 指标（未认证必须 401，绝不能 200）==="
p "/__admin (9095)" "$PLAIN/__admin"
p "/__admin/ (8443)" "$H3/__admin/" -k
p "/__admin/api/config (8443)" "$H3/__admin/api/config" -k
p "/__metrics (8443)" "$H3/__metrics" -k

echo "=== E. 穿越 / 方法（不得出现 200）==="
p "/../../etc/passwd" "$PLAIN/../../etc/passwd"
p "/%2e%2e/%2e%2e/etc/passwd" "$PLAIN/%2e%2e/%2e%2e/etc/passwd"
p "/..%2f..%2fetc/passwd" "$PLAIN/..%2f..%2fetc/passwd"
p "/__admin/../config.toml" "$PLAIN/__admin/../config.toml"
echo -n "  HEAD /  9095: "; curl -s -o /dev/null -w '%{http_code}\n' --max-time 10 -I "$PLAIN/"
echo -n "  OPTIONS /  9095: "; curl -s -o /dev/null -w '%{http_code}\n' --max-time 10 -X OPTIONS "$PLAIN/"

echo "=== F. Range / 条件请求 ==="
echo -n "  Range bytes=0-9 (静态): "
curl -s -o /dev/null -w '%{http_code} len=%{size_download}\n' --max-time 10 -H 'Range: bytes=0-9' "$FAIR/"
echo -n "  非法 Range bytes=99999999- : "
curl -s -o /dev/null -w '%{http_code}\n' --max-time 10 -H 'Range: bytes=99999999-' "$FAIR/"

echo "=== G. DNS over TCP（权威 + 递归 + type65）==="
python3 - <<'PY'
import socket, struct, random
def q(name, qtype, server=('127.0.0.1',53)):
    tid = random.randint(0,65535)
    h = struct.pack('>HHHHHH', tid, 0x0100, 1,0,0,0)
    parts = b''.join(bytes([len(x)])+x.encode() for x in name.split('.'))+b'\x00'
    pkt = h + parts + struct.pack('>HH', qtype, 1)
    s = socket.socket(); s.settimeout(8); s.connect(server)
    s.sendall(struct.pack('>H', len(pkt))+pkt)
    ln = struct.unpack('>H', s.recv(2))[0]; d=b''
    while len(d) < ln: d += s.recv(ln-len(d))
    s.close()
    return 'rcode=%d ancount=%d' % (d[3]&0xF, struct.unpack('>H', d[6:8])[0])
for n,t,lab in [('crucible.local',65,'HTTPS(apex,ECH)'),('example.com',1,'递归 A'),('example.com',28,'递归 AAAA'),
                ('answers.default',1,'权威 A'),('nonexistent-xyz.crucible.local',1,'不存在(期望 rcode=3)')]:
    try: print('  %-26s %s' % (lab, q(n,t)))
    except Exception as e: print('  %-26s ERR %s' % (lab, e))
PY

echo "=== H. DoT（853 TLS 握手 + 一个真查询）==="
python3 - <<'PY'
import socket, ssl, struct, random
try:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    s = socket.create_connection(('127.0.0.1',853), timeout=8)
    t = ctx.wrap_socket(s, server_hostname='crucible.local')
    print('  握手 OK  version=%s' % t.version())
    tid = random.randint(0,65535)
    name='example.com'
    h = struct.pack('>HHHHHH', tid, 0x0100, 1,0,0,0)
    parts = b''.join(bytes([len(x)])+x.encode() for x in name.split('.'))+b'\x00'
    pkt = h + parts + struct.pack('>HH', 1, 1)
    t.sendall(struct.pack('>H', len(pkt))+pkt)
    ln = struct.unpack('>H', t.recv(2))[0]; d=b''
    while len(d) < ln: d += t.recv(ln-len(d))
    print('  查询 OK  rcode=%d ancount=%d' % (d[3]&0xF, struct.unpack('>H', d[6:8])[0]))
    t.close()
except Exception as e:
    print('  DoT 失败:', e)
PY

echo "=== I. 服务仍在 ==="
pgrep -x webserver >/dev/null && echo "  webserver: up" || echo "  webserver: DOWN"
pgrep -x named     >/dev/null && echo "  named:     up" || echo "  named:     DOWN"
echo "=== 回归扫结束 ==="