#!/usr/bin/env python3
"""accept-verify-ext.py — 工号 1009 / agent-verify2 扩展黑盒检查（wave-5）。

覆盖主套件不易放进去的项：
- per-listener ip_access 在 TLS 面（:29096）与 h3 面（:29097）是否生效
  （core2-wave4 报告点名「TLS/h3 请求路径仍走全局 ip_access」，本脚本回归）
- SIGHUP 重载：进程存活且继续服务
- worker 线程上界（CRUCIBLE_WORKER_THREADS 过大 → 钳制到 1024）
- 面板空 extensions 保存后路由仍正常（admin /api/apps/save 往返）

前提：主实例（config-verify.toml，端口 29000+）已由 accept-verify-start.sh 起好，
且 accept-verify-upstream.py 在 29099/29100 上跑着。

用法: python3 scripts/accept-verify-ext.py [--json out.json]
"""
import asyncio, sys, json, os, ssl, socket, subprocess, time, signal

HOST = "127.0.0.1"
TLSIP = 29096      # TLS + per-listener ip_access
H3IP = 29097       # h1+h2+h3 + per-listener ip_access
APPS = 29095
SCRATCH = "/home/dev123/scratch-verify4"
ADMIN = ("admin", "admin")

RESULTS = []


def rec(area, name, ok, expected="", observed="", repro="", sev="P1", skip=False, owner=""):
    st = "SKIP" if skip else ("PASS" if ok else "FAIL")
    RESULTS.append(dict(area=area, name=name, status=st, severity=sev, expected=str(expected),
                        observed=str(observed), repro=repro, owner=owner))
    print(f"[{st}] {name}" + ("" if ok else f"  (exp={expected!r} obs={observed!r})"))


def curl(args, timeout=10):
    try:
        p = subprocess.run(["curl", "-sS", "--max-time", str(timeout), "-o", "/dev/null",
                            "-w", "%{http_code}"] + args, capture_output=True, timeout=timeout + 5)
        return p.stdout.decode().strip()
    except Exception as e:
        return f"ERR {e}"


# ── per-listener ip_access：TLS 面 ──
def test_tls_ip_access():
    area = "扩展·per-listener ip_access（TLS 面 :29096）"
    c1 = curl(["-k", f"https://{HOST}:{TLSIP}/"])
    rec(area, "TLS h1 per-listener ip_access allow=[10/8] 拒 127.0.0.1 → 403", c1 == "403",
        "403", c1, f"curl -k https://{HOST}:{TLSIP}/ （listener 配 [listeners.ip_access] allow=['10.0.0.0/8']）",
        sev="P2", owner="h1")
    c2 = curl(["-k", "--http2", f"https://{HOST}:{TLSIP}/"])
    rec(area, "TLS h2 per-listener ip_access → 403", c2 == "403", "403", c2, sev="P2", owner="h2h3")


# ── per-listener ip_access：h3 面 ──
async def _h3_get(port, path, authority, sni):
    from aioquic.asyncio.client import connect
    from aioquic.asyncio.protocol import QuicConnectionProtocol
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.h3.connection import H3Connection
    from aioquic.h3.events import HeadersReceived, DataReceived

    class Client(QuicConnectionProtocol):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            self._h3 = H3Connection(self._quic)
            self._status = None
            self._body = b""
            self._done = asyncio.Event()

        def quic_event_received(self, event):
            for ev in self._h3.handle_event(event):
                if isinstance(ev, HeadersReceived):
                    for k, v in ev.headers:
                        if k == b":status":
                            self._status = int(v)
                    if ev.stream_ended:
                        self._done.set()
                elif isinstance(ev, DataReceived):
                    self._body += ev.data
                    if ev.stream_ended:
                        self._done.set()

        async def get(self, authority, path):
            sid = self._quic.get_next_available_stream_id()
            self._h3.send_headers(sid, [
                (b":method", b"GET"), (b":scheme", b"https"),
                (b":authority", authority.encode()), (b":path", path.encode()),
            ], end_stream=True)
            self.transmit()
            try:
                await asyncio.wait_for(self._done.wait(), timeout=8)
            except asyncio.TimeoutError:
                pass
            return self._status

    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"], verify_mode=ssl.CERT_NONE)
    cfg.max_datagram_frame_size = 65536
    async with connect(HOST, port, configuration=cfg, create_protocol=Client) as cli:
        return await cli.get(authority, path)


def _h3_get_t(port, path, authority, sni=None, timeout=12):
    """带硬超时（服务端被杀时 aioquic connect 会永久等握手，绝不允许挂死套件）。"""
    return asyncio.run(asyncio.wait_for(_h3_get(port, path, authority, sni), timeout=timeout))


def test_h3_ip_access():
    area = "扩展·per-listener ip_access（h3 面 :29097）"
    try:
        st = _h3_get_t(H3IP, "/", f"{HOST}:{H3IP}", "h3ip.crucible.local")
        rec(area, "h3 per-listener ip_access allow=[10/8] 拒 127.0.0.1 → 403", st == 403,
            "403", st, f"aioquic h3 GET https://{HOST}:{H3IP}/", sev="P2", owner="h2h3")
    except Exception as e:
        rec(area, "h3 per-listener ip_access → 403", False, "403", f"exc {e!r}", sev="P2", owner="h2h3")


# ── SIGHUP 重载 ──
def test_sighup():
    area = "扩展·SIGHUP 重载"
    pidf = os.path.join(SCRATCH, "webserver.pid")
    try:
        pid = int(open(pidf).read().strip())
    except Exception as e:
        rec(area, "读取实例 PID", False, "pid", f"exc {e}", sev="P1", owner="core")
        return
    # 触发前确认活着
    pre = curl([f"http://{HOST}:29081/"])
    try:
        os.kill(pid, signal.SIGHUP)
    except Exception as e:
        rec(area, "发送 SIGHUP", False, "ok", f"exc {e}", sev="P1", owner="core")
        return
    time.sleep(1.5)
    alive = True
    try:
        os.kill(pid, 0)
    except Exception:
        alive = False
    post = curl([f"http://{HOST}:29081/"])
    rec(area, "SIGHUP 后进程存活", alive, "alive", "alive" if alive else "dead", sev="P1", owner="core")
    rec(area, "SIGHUP 后仍正常服务", post == "200", "200", f"pre={pre} post={post}",
        "kill -HUP <pid>; curl http://127.0.0.1:29081/", sev="P1", owner="core")


# ── worker 线程上界 ──
def test_worker_cap():
    area = "扩展·worker 线程上界"
    cfg = os.path.join(SCRATCH, "conf", "worker-cap.toml")
    with open(cfg, "w") as f:
        f.write(f'''
[access_log]
enable = false
[[listeners]]
address = "127.0.0.1"
port = 29085
root = "{SCRATCH}/www-ip"
http_versions = ["h1"]
''')
    env = dict(os.environ)
    env["CRUCIBLE_WORKER_THREADS"] = "100000"
    env["CRUCIBLE_DNS_STATE_ROOT"] = os.path.join(SCRATCH, "state-dns")
    log = os.path.join(SCRATCH, "logs", "worker-cap.log")
    try:
        p = subprocess.Popen([os.path.join(SCRATCH, "bin", "webserver"), "--config", cfg],
                             stdout=open(log, "w"), stderr=subprocess.STDOUT, env=env,
                             cwd="/home/dev123/crucible-git")
    except Exception as e:
        rec(area, "启动钳制实例", False, "ok", f"exc {e}", sev="P2", owner="core")
        return
    threads = None
    for _ in range(40):
        time.sleep(0.25)
        try:
            txt = open(f"/proc/{p.pid}/status").read()
            for ln in txt.splitlines():
                if ln.startswith("Threads:"):
                    threads = int(ln.split()[1])
            if threads and curl([f"http://{HOST}:29085/"]):
                break
        except Exception:
            pass
    try:
        p.terminate()
    except Exception:
        pass
    if threads is None:
        rec(area, "CRUCIBLE_WORKER_THREADS=100000 被钳制", False, "<=1030", "no threads",
            sev="P2", owner="core")
    else:
        rec(area, "CRUCIBLE_WORKER_THREADS=100000 被钳制到 ~1024", threads <= 1030,
            "<=1030", f"Threads={threads}", "CRUCIBLE_WORKER_THREADS=100000 起实例读 /proc/<pid>/status",
            sev="P2", owner="core")


# ── 面板空 extensions 保存后路由仍正常 ──
def admin_req(method, sub, data=None, ct="application/json"):
    cmd = ["curl", "-sS", "--max-time", "15", "-X", method,
           f"http://{HOST}:{APPS}/__admin{sub}", "-u", "admin:admin",
           "-H", f"Origin: http://{HOST}:{APPS}",
           "-H", "X-Requested-With: accept-verify"]
    if data is not None:
        cmd += ["-H", f"Content-Type: {ct}", "--data-binary", data]
    p = subprocess.run(cmd, capture_output=True, timeout=20)
    return p.stdout.decode("latin1", "replace")


def test_panel_empty_ext():
    area = "扩展·面板空 extensions 保存后路由"
    out = admin_req("GET", "/api/config/json")
    try:
        cfg = json.loads(out)
    except Exception:
        rec(area, "读取 config/json", False, "JSON", out[:60], sev="P1", owner="admin")
        return
    target = None
    for l in (cfg.get("listeners") or []):
        if int(l.get("port", 0)) == APPS and (l.get("apps") or []):
            target = l
            break
    if not target:
        rec(area, "找到 apps listener", False, "apps listener", "none", sev="P2", owner="admin")
        return
    apps = target["apps"]
    # 挑一个 app，把 extensions 清空（触发 wave2 缺陷：空 extensions 变 [""]）
    saved = json.loads(json.dumps(apps))
    changed = False
    for a in saved:
        if a.get("extensions"):
            a["extensions"] = []
            changed = True
            break
    if not changed:
        rec(area, "构造空 extensions", False, "app with extensions", "none", skip=True, owner="admin")
        return
    body = json.dumps({"port": APPS, "apps": saved})
    resp = admin_req("POST", "/api/apps/save", data=body)
    rec(area, "空 extensions 保存成功", "error" not in resp[:40].lower(), "ok", resp[:80],
        sev="P1", owner="admin")
    time.sleep(1.0)
    # 保存后：config/json 不得出现 [""]
    out2 = admin_req("GET", "/api/config/json")
    polluted = '[""]' in out2.replace(" ", "")
    rec(area, "保存后 config/json 无 extensions=['']", not polluted, "no ['']",
        "polluted" if polluted else "ok", sev="P1", owner="admin")
    # 路由仍正常：被改的 app 路径探测；退化时用 /c/ 兜底
    c = curl([f"http://{HOST}:{APPS}/c/"])
    rec(area, "空 extensions 保存后原路由仍正常（/c/ → 200）", c == "200", "200", c,
        "admin /api/apps/save 清空 extensions；再 curl 原 app 路径", sev="P1", owner="admin")


# ─────────────── 通用：带 body 的 curl / h3 请求 ───────────────
def curl_body(args, timeout=12):
    """返回 (code:str, body:bytes)。"""
    import tempfile
    bp = os.path.join(SCRATCH, "tmp", "ext-body.bin")
    try:
        p = subprocess.run(["curl", "-sS", "--max-time", str(timeout), "-D", "-", "-o", bp] + args,
                           capture_output=True, timeout=timeout + 5)
        out = p.stdout
        code = "-"
        for ln in out.split(b"\r\n"):
            if ln.startswith(b"HTTP/"):
                code = ln.split(b" ")[1].decode()
                break
        body = open(bp, "rb").read() if os.path.exists(bp) else b""
        return code, body
    except Exception as e:
        return f"ERR {e}", b""


def _h3_request(port, path, authority, method="GET", extra_headers=(), timeout=8):
    """aioquic h3 单请求，返回 (status:int|None, body:bytes)。"""
    from aioquic.asyncio.client import connect
    from aioquic.asyncio.protocol import QuicConnectionProtocol
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.h3.connection import H3Connection
    from aioquic.h3.events import HeadersReceived, DataReceived

    class Client(QuicConnectionProtocol):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            self._h3 = H3Connection(self._quic)
            self._status = None
            self._body = b""
            self._done = asyncio.Event()

        def quic_event_received(self, event):
            for ev in self._h3.handle_event(event):
                if isinstance(ev, HeadersReceived):
                    for k, v in ev.headers:
                        if k == b":status":
                            self._status = int(v)
                    if ev.stream_ended:
                        self._done.set()
                elif isinstance(ev, DataReceived):
                    self._body += ev.data
                    if ev.stream_ended:
                        self._done.set()

        async def req(self, authority, path, method, extra):
            sid = self._quic.get_next_available_stream_id()
            hdrs = [(b":method", method.encode()), (b":scheme", b"https"),
                    (b":authority", authority.encode()), (b":path", path.encode())]
            hdrs += [(k.encode(), v.encode()) for k, v in extra]
            self._h3.send_headers(sid, hdrs, end_stream=True)
            self.transmit()
            try:
                await asyncio.wait_for(self._done.wait(), timeout=8)
            except asyncio.TimeoutError:
                pass
            if self._status is not None:
                await asyncio.sleep(0.2)
            return self._status, self._body

    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"], verify_mode=ssl.CERT_NONE)
    cfg.max_datagram_frame_size = 65536

    async def _run():
        async with connect(HOST, port, configuration=cfg, create_protocol=Client) as cli:
            return await cli.req(authority, path, method, extra_headers)

    return asyncio.run(asyncio.wait_for(_run(), timeout=timeout + 2))


# ─────────────── per-listener ip_access：三面「放行」对照 ───────────────
def test_ip_access_control_faces():
    area = "扩展·per-listener ip_access 三面对照（明文/TLS/h3 放行）"
    c = curl([f"http://{HOST}:29093/"])
    rec(area, "明文 ACL 口 29093 → 403", c == "403", "403", c, sev="P2", owner="core")
    c = curl([f"http://{HOST}:29094/"])
    rec(area, "明文无 ACL 口 29094 → 200（放行）", c == "200", "200", c, sev="P2", owner="core")
    c = curl(["-k", f"https://{HOST}:29443/"])
    rec(area, "TLS 无 ACL 口 29443 h1 → 200（放行）", c == "200", "200", c, sev="P2", owner="h1")
    c = curl(["-k", "--http2", f"https://{HOST}:29443/"])
    rec(area, "TLS 无 ACL 口 29443 h2 → 200（放行）", c == "200", "200", c, sev="P2", owner="h2h3")
    try:
        st, _ = _h3_request(29098, "/", f"{HOST}:29098")
        rec(area, "h3 无 ACL 口 29098 → 200（放行）", st == 200, 200, st, sev="P2", owner="h2h3")
    except Exception as e:
        rec(area, "h3 无 ACL 口 29098 → 200（放行）", False, 200, f"exc {e!r}", sev="P2", owner="h2h3")
    try:
        st, _ = _h3_request(29097, "/", f"{HOST}:29097")
        rec(area, "h3 ACL 口 29097 → 403（拒）", st == 403, 403, st, sev="P2", owner="h2h3")
    except Exception as e:
        rec(area, "h3 ACL 口 29097 → 403（拒）", False, 403, f"exc {e!r}", sev="P2", owner="h2h3")


# ─────────────── 页面规则维度 host/method/header × 四协议 ───────────────
DIM_HOST = "dim.crucible.local"


def _face_codes(path, method="GET", host=None, hdr=None, h10=False):
    """同一请求在 h1/h2c/h1(TLS)/h2(TLS)/h3 五个面上的状态码（wave-7：+h1TLS）。"""
    out = {}
    # h1（29090 明文）
    if h10:
        import socket as _s
        try:
            sk = _s.create_connection((HOST, 29090), timeout=5)
            sk.sendall(f"{method} {path} HTTP/1.0\r\n\r\n".encode())
            sk.settimeout(5)
            data = sk.recv(4096)
            sk.close()
            out["h1-http10-nohost"] = int(data.split(b" ")[1]) if data.startswith(b"HTTP/") else None
        except Exception as e:
            out["h1-http10-nohost"] = f"exc {e}"
        return out
    args = [f"http://{HOST}:29090{path}"]
    if method != "GET":
        args = ["-X", method] + args
    if host:
        args = ["-H", f"Host: {host}"] + args
    if hdr:
        args = ["-H", hdr] + args
    out["h1"] = curl(args)
    # h2c（29090）
    out["h2c"] = curl(["--http2-prior-knowledge"] + args)
    # h1/h2 TLS（29098）——29098 的 http_versions 含 h1（wave-7：五面口径之一）
    def _tls_args(http2):
        a = ["-k"] + (["--http2"] if http2 else []) + [f"https://{HOST}:29098{path}"]
        if method != "GET":
            a = ["-X", method] + a
        if host:
            a = ["-H", f"Host: {host}"] + a
        if hdr:
            a = ["-H", hdr] + a
        return a
    out["h1TLS"] = curl(_tls_args(False))
    out["h2TLS"] = curl(_tls_args(True))
    # h3（29098）
    extra = []
    if hdr:
        k, _, v = hdr.partition(":")
        extra.append((k.strip(), v.strip()))
    try:
        st, _ = _h3_request(29098, path, host or f"{HOST}:29098", method=method, extra_headers=extra)
        out["h3"] = str(st) if st is not None else None  # 与其他面统一为字符串比较
    except Exception as e:
        out["h3"] = f"exc {e!r}"
    return out


def test_page_rule_dims():
    area = "扩展·页面规则维度 host/method/header（h1/h2c/h1TLS/h2TLS/h3 五面一致性）"
    cases = [
        ("method 命中 POST /dimmeth", "/dimmeth", "POST", None, None, 403),
        ("method 不命中 GET /dimmeth", "/dimmeth", "GET", None, None, 404),
        ("host 命中 /dimhost(Host=dim)", "/dimhost", "GET", DIM_HOST, None, 403),
        ("host 不命中 /dimhost(Host=other)", "/dimhost", "GET", "other.local", None, 404),
        ("header 命中 /dimhdr(x-dim: yes)", "/dimhdr", "GET", None, "x-dim: yes", 403),
        ("header 不命中 /dimhdr(无头)", "/dimhdr", "GET", None, None, 404),
        ("通配 host 命中子域 /dimwild", "/dimwild", "GET", "sub.crucible.local", None, 403),
        ("通配 host 命中 apex /dimwild", "/dimwild", "GET", "crucible.local", None, 403),
        ("通配 host 不命中 /dimwild(other)", "/dimwild", "GET", "other.local", None, 404),
    ]
    for label, path, method, host, hdr, want in cases:
        codes = _face_codes(path, method=method, host=host, hdr=hdr)
        ok = all(str(codes.get(f)) == str(want) for f in ("h1", "h2c", "h1TLS", "h2TLS", "h3"))
        rec(area, label, ok, f"五面均 {want}", codes,
            "同一 page rule 在 29090(h1/h2c) 与 29098(h1TLS/h2TLS/h3)", sev="P1", owner="page_rules")
    # 组合维度：PUT+host+header 三者全满足才 403（h1/h2c）
    codes = _face_codes("/dimall", method="PUT", host=DIM_HOST, hdr="x-dim: yes")
    ok = codes.get("h1") == "403" and codes.get("h2c") == "403"
    rec(area, "组合维度全满足 PUT /dimall → 403", ok, "h1/h2c 均 403", codes, sev="P1", owner="page_rules")
    c1 = curl(["-X", "PUT", "-H", f"Host: {DIM_HOST}", f"http://{HOST}:29090/dimall"])
    rec(area, "组合维度缺 header 不命中（PUT /dimall 无 X-Dim ≠ 403）", c1 != "403",
        "≠403", c1, sev="P2", owner="page_rules")
    # 维度取不到：HTTP/1.0 无 Host，带 host 约束的规则必须**判不匹配**（不得放宽）
    codes = _face_codes("/dimhost", method="GET", h10=True)
    v = codes.get("h1-http10-nohost")
    rec(area, "维度取不到（HTTP/1.0 无 Host）→ host 规则不匹配（404，非 403）", v == 404,
        "404", codes, "printf 'GET /dimhost HTTP/1.0\\r\\n\\r\\n' | nc 127.0.0.1 29090",
        sev="P1", owner="page_rules")


# ─────────────── priority 回归（h1/h2c） ───────────────
def test_priority_regression():
    area = "扩展·页面规则 priority（h1/h2c）"
    c1 = curl([f"http://{HOST}:29090/dup"])
    c2 = curl(["--http2-prior-knowledge", f"http://{HOST}:29090/dup"])
    rec(area, "priority 大者胜 /dup → 308（h1）", c1 == "308", 308, c1, sev="P1", owner="page_rules")
    rec(area, "priority 大者胜 /dup → 308（h2c）", c2 == "308", 308, c2, sev="P1", owner="page_rules")
    c1 = curl([f"http://{HOST}:29090/order"])
    c2 = curl(["--http2-prior-knowledge", f"http://{HOST}:29090/order"])
    rec(area, "等 priority 保持配置顺序 /order → 301（h1）", c1 == "301", 301, c1,
        sev="P1", owner="page_rules")
    rec(area, "等 priority 保持配置顺序 /order → 301（h2c）", c2 == "301", 301, c2,
        sev="P1", owner="page_rules")


# ─────────────── per-site access_log（§16.12） ───────────────
def _access_log_has(tag, logfile=None):
    time.sleep(1.2)  # 批量写缓冲 250ms + 余量
    logfile = logfile or os.path.join(SCRATCH, "logs", "webserver.log")
    try:
        return tag in open(logfile, encoding="utf-8", errors="replace").read()
    except Exception:
        return False


def test_per_site_access_log():
    area = "扩展·per-site 访问日志（§16.12，全局 enable=true）"
    tag_off = f"/alsite-off-{int(time.time())}.txt"
    c1 = curl([f"http://{HOST}:29087{tag_off}"])
    tag_on = f"/alsite-on-{int(time.time())}.txt"
    c2 = curl([f"http://{HOST}:29090{tag_on}"])
    has_off = _access_log_has(tag_off)
    has_on = _access_log_has(tag_on)
    rec(area, "listener 覆盖 enable=false → 不打日志", not has_off,
        "log 无该行", f"hit={c1} log_has={has_off}",
        "29087 配 [listeners.access_log] enable=false；全局 enable=true；打 29087 后查 webserver.log",
        sev="P1", owner="admin")
    rec(area, "未配 listener 继承全局 enable=true → 打日志", has_on,
        "log 有该行", f"hit={c2} log_has={has_on}", sev="P2", owner="admin")


def test_per_site_access_log_level():
    """§16.12 per-site level（wave-7 复核点）：全局 level=info，29088 覆盖 level=debug。

    历史缺陷是「把访问日志等级选成 debug/trace → env_logger 默认 info 过滤 →
    一行都不落盘」。当前实现（access_log.rs 注释声明为有意）让 level 只做配置/展示、
    落盘路径统一，于是打 29088 的请求必须**照常**出现在 webserver.log；同时打未配
    level 的 29090 也必须落盘。若未来把 level 变成真过滤，这条检查会暴露行为变化。"""
    area = "扩展·per-site 访问日志 level（§16.12，覆盖 level=debug）"
    tag_dbg = f"/allvl-dbg-{int(time.time())}.txt"
    c1 = curl([f"http://{HOST}:29088{tag_dbg}"])
    tag_inf = f"/allvl-inf-{int(time.time())}.txt"
    c2 = curl([f"http://{HOST}:29090{tag_inf}"])
    has_dbg = _access_log_has(tag_dbg)
    has_inf = _access_log_has(tag_inf)
    rec(area, "listener 覆盖 level=debug（全局 info）→ 仍落盘（历史缺陷回归）", has_dbg,
        "log 有该行", f"hit={c1} log_has={has_dbg}",
        "29088 配 [listeners.access_log] level='debug'；全局 info；打 29088 后查 webserver.log",
        sev="P1", owner="admin")
    rec(area, "未配 level 的 listener（继承 info）→ 仍落盘", has_inf,
        "log 有该行", f"hit={c2} log_has={has_inf}", sev="P2", owner="admin")


def test_per_site_access_log_global_off():
    """独立实例：全局 enable=false + 一个 listener 覆盖 enable=true。
    期望（字段级继承语义）：覆盖的 listener 打日志、另一个不打。"""
    area = "扩展·per-site 访问日志（全局 enable=false）"
    cfg = os.path.join(SCRATCH, "conf", "accesslog-global-off.toml")
    with open(cfg, "w") as f:
        f.write(f'''
[access_log]
enable = false
level = "info"

[[listeners]]
address = "127.0.0.1"
port = 29086
root = "{SCRATCH}/www-alog"
http_versions = ["h1"]

[listeners.access_log]
enable = true

[[listeners]]
address = "127.0.0.1"
port = 29089
root = "{SCRATCH}/www-alog2"
http_versions = ["h1"]
''')
    env = dict(os.environ)
    env["CRUCIBLE_DNS_STATE_ROOT"] = os.path.join(SCRATCH, "state-dns")
    log = os.path.join(SCRATCH, "logs", "accesslog-global-off.log")
    try:
        p = subprocess.Popen([os.path.join(SCRATCH, "bin", "webserver"), "--config", cfg],
                             stdout=open(log, "w"), stderr=subprocess.STDOUT, env=env,
                             cwd="/home/dev123/crucible-git")
    except Exception as e:
        rec(area, "启动全局-off 实例", False, "ok", f"exc {e}", sev="P2", owner="admin")
        return
    for _ in range(40):
        time.sleep(0.25)
        if curl([f"http://{HOST}:29086/"]) == "200":
            break
    tag_a = f"/glog-on-{int(time.time())}.txt"
    tag_b = f"/glog-inherit-{int(time.time())}.txt"
    curl([f"http://{HOST}:29086{tag_a}"])
    curl([f"http://{HOST}:29089{tag_b}"])
    has_a = _access_log_has(tag_a, logfile=log)
    has_b = _access_log_has(tag_b, logfile=log)
    try:
        p.terminate()
    except Exception:
        pass
    rec(area, "listener 覆盖 enable=true（全局 false）→ 打日志", has_a,
        "log 有该行", f"log_has={has_a}",
        "独立实例：全局 enable=false；29086 覆盖 enable=true", sev="P1", owner="admin")
    rec(area, "未配 listener 仍继承全局 enable=false → 不打日志", not has_b,
        "log 无该行", f"log_has={has_b}", sev="P2", owner="admin")


# ─────────────── per-child .env（cgi / cgi_script） ───────────────
def test_env_isolation():
    area = "扩展·per-child .env（cgi :29094）"
    import threading

    # 1) .env 正常下发：/envd（带 .env、快）
    t0 = time.time()
    code, body = curl_body([f"http://{HOST}:29094/envd/"])
    dt = time.time() - t0
    txt = body.decode("latin1", "replace")
    rec(area, ".env 下发 /envd → WINDOWMARK=from-app-D", code == "200" and "WINDOWMARK=from-app-D" in txt,
        "200 + from-app-D", f"{code} {txt[:90]!r} ({dt:.2f}s)", sev="P1", owner="apps")
    # 2) 无 .env 的 app 不得看到 A/D 的键
    code, body = curl_body([f"http://{HOST}:29094/envb/"])
    txt = body.decode("latin1", "replace")
    rec(area, "无 .env 应用看不到他人密钥 /envb → <unset>", code == "200" and "WINDOWMARK=<unset>" in txt
        and "SECRET_A=<unset>" in txt and "a-only-secret" not in txt,
        "200 + <unset>", f"{code} {txt[:90]!r}", sev="P0", owner="apps")

    # 3) A（带 .env，慢 2s）在飞：B（无 .env）不被污染、不等锁
    a_res, b_res = {}, {}

    def _call(tag, url):
        t0 = time.time()
        c, b = curl_body([url], timeout=20)
        (a_res if tag == "a" else b_res)["dt"] = time.time() - t0
        (a_res if tag == "a" else b_res)["txt"] = b.decode("latin1", "replace")
        (a_res if tag == "a" else b_res)["code"] = c

    ta = threading.Thread(target=_call, args=("a", f"http://{HOST}:29094/enva/"))
    ta.start()
    time.sleep(0.4)  # A 已在飞（sleep 2）
    _call("b", f"http://{HOST}:29094/envb/")
    ta.join()
    rec(area, "A(带 .env) 在飞时 B(无 .env) 输出无 A 的密钥", "SECRET_A=<unset>" in b_res.get("txt", "")
        and "a-only-secret" not in b_res.get("txt", ""),
        "B 无污染", f"A={a_res.get('txt','')[:60]!r} B={b_res.get('txt','')[:60]!r}",
        sev="P0", owner="apps")
    rec(area, "A 在飞时 B 不被 env 锁串行（B 时延 < 1.5s）", b_res.get("dt", 99) < 1.5,
        "<1.5s", f"B={b_res.get('dt'):.2f}s A={a_res.get('dt'):.2f}s",
        "并发：/enva(sleep 2, 带 .env) + /envb(无 .env)", sev="P1", owner="apps")

    # 4) 不同 .env 并发互不阻塞：D（带 .env，快）在 A 在飞时也应立即回
    d_res = {}
    ta = threading.Thread(target=_call, args=("a", f"http://{HOST}:29094/enva/"))
    ta.start()
    time.sleep(0.4)
    t0 = time.time()
    code, body = curl_body([f"http://{HOST}:29094/envd/"], timeout=20)
    d_res["dt"] = time.time() - t0
    d_res["txt"] = body.decode("latin1", "replace")
    ta.join()
    rec(area, "A(带.env) 在飞时 D(另一 .env) 并发不被阻塞（<1.5s）", d_res["dt"] < 1.5,
        "<1.5s", f"D={d_res['dt']:.2f}s A={a_res.get('dt'):.2f}s",
        "并发 /enva(sleep 2, A 的 .env) + /envd(D 的 .env)", sev="P1", owner="apps")
    rec(area, "并发下 D 的密钥仍是自己的 from-app-D", "WINDOWMARK=from-app-D" in d_res["txt"],
        "from-app-D", d_res["txt"][:80], sev="P0", owner="apps")

    # 5) 慢空请求 C（sleep 3，无 .env）在飞时，带 .env 的 A 不被拖到 4.7s
    tc = threading.Thread(target=curl_body, args=([f"http://{HOST}:29094/envc/"],))
    tc.start()
    time.sleep(0.4)
    t0 = time.time()
    code, body = curl_body([f"http://{HOST}:29094/enva/"], timeout=20)
    a2_dt = time.time() - t0
    tc.join()
    rec(area, "慢空请求在飞时带 .env 请求不被串行拖慢（<3.5s，旧行为 4.7s）", a2_dt < 3.5,
        "<3.5s", f"enva={a2_dt:.2f}s", sev="P1", owner="apps")

    # 6) cgi_script 路径同样按子进程传 .env（apply_clean_env）
    code, body = curl_body([f"http://{HOST}:29094/envs/"], timeout=15)
    txt = body.decode("latin1", "replace")
    rec(area, "cgi_script .env 下发 /envs → from-app-S 且无他人密钥",
        code == "200" and "WINDOWMARK=from-app-S" in txt and "SECRET_A=<unset>" in txt,
        "200 + from-app-S", f"{code} {txt[:90]!r}", sev="P1", owner="apps")

    # 7) 交替矩阵 A→B→A→B（wave-7）：每次请求都是一次独立 spawn，检查
    #    「每个请求只看自己的 .env」且**请求之间零残留**（上一请求的临时 env 不得
    #    出现在下一请求的子进程里）。
    seq = ["/enva/", "/envb/", "/enva/", "/envb/"]
    seq_out = []
    for u in seq:
        c, body = curl_body([f"http://{HOST}:29094{u}"], timeout=20)
        seq_out.append((u, c, body.decode("latin1", "replace")))
    ok_a = all(("WINDOWMARK=from-app-A" in t) and ("SECRET_A=a-only-secret" in t)
               and ("SECRET_D=<unset>" in t)
               for u, c, t in seq_out if u.startswith("/enva"))
    ok_b = all(("WINDOWMARK=<unset>" in t) and ("SECRET_A=<unset>" in t)
               and ("only-secret" not in t)
               for u, c, t in seq_out if u.startswith("/envb"))
    rec(area, "交替矩阵 A/B/A/B：每请求只看自己的 .env、请求间零残留",
        ok_a and ok_b, "A 见 A 的键；B 全 <unset>",
        "; ".join(f"{u}:{t[:44]!r}" for u, c, t in seq_out), sev="P0", owner="apps")
    # 8) 跨应用不泄漏：C（无 .env）看不到 A/D/S 的密钥
    code, body = curl_body([f"http://{HOST}:29094/envc/"], timeout=20)
    txt = body.decode("latin1", "replace")
    rec(area, "跨应用不泄漏：/envc 看不到 A/D/S 的密钥", code == "200"
        and "only-secret" not in txt and "WINDOWMARK=<unset>" in txt,
        "200 + 无任何他人 secret", f"{code} {txt[:80]!r}", sev="P0", owner="apps")


# ─────────────── cgi_script：SCRIPT_NAME / PATH_INFO（wave-7） ───────────────
def test_cgi_script_path_info():
    """CGI/1.1 §4.1.13/§4.1.5：/cgis/index.cgi → PATH_INFO=""，
    /cgis/index.cgi/extra/path → SCRIPT_NAME=/cgis/index.cgi、PATH_INFO=/extra/path。"""
    area = "扩展·cgi_script SCRIPT_NAME/PATH_INFO（:29094）"
    code, body = curl_body([f"http://{HOST}:29094/cgis/index.cgi"], timeout=15)
    txt = body.decode("latin1", "replace")
    rec(area, "/cgis/index.cgi → SCRIPT_NAME=/cgis/index.cgi、PATH_INFO 为空",
        code == "200" and "SCRIPT_NAME=/cgis/index.cgi" in txt and "PATH_INFO=" in txt
        and "PATH_INFO=/extra" not in txt,
        "200 + SCRIPT_NAME=/cgis/index.cgi + PATH_INFO 空", f"{code} {txt[:120]!r}",
        "curl http://127.0.0.1:29094/cgis/index.cgi", sev="P1", owner="apps")
    code, body = curl_body([f"http://{HOST}:29094/cgis/index.cgi/extra/path"], timeout=15)
    txt = body.decode("latin1", "replace")
    rec(area, "/cgis/index.cgi/extra/path → PATH_INFO=/extra/path（旧实现在此 404）",
        code == "200" and "SCRIPT_NAME=/cgis/index.cgi" in txt and "PATH_INFO=/extra/path" in txt,
        "200 + SCRIPT_NAME=/cgis/index.cgi + PATH_INFO=/extra/path", f"{code} {txt[:120]!r}",
        "curl http://127.0.0.1:29094/cgis/index.cgi/extra/path", sev="P1", owner="apps")
    # 跨协议同口径：h2c 面应给出与 h1 相同的一对值
    code2, body2 = curl_body(["--http2-prior-knowledge",
                              f"http://{HOST}:29094/cgis/index.cgi/extra/path"], timeout=15)
    txt2 = body2.decode("latin1", "replace")
    rec(area, "h2c 面 PATH_INFO 与 h1 同口径",
        code2 == "200" and "SCRIPT_NAME=/cgis/index.cgi" in txt2 and "PATH_INFO=/extra/path" in txt2,
        "h2c 200 + 同值", f"{code2} {txt2[:120]!r}", sev="P2", owner="apps")


# ─────────────── 上传 RCE 闸门（app docroot） ───────────────
def test_upload_rce_gate():
    area = "扩展·上传 RCE 闸门（app docroot :29094）"
    files = {
        "init.sh": os.path.join(SCRATCH, "www-up", "cga", "init.sh"),
        ".env": os.path.join(SCRATCH, "www-up", "cga", ".env"),
        "deps/bin/index": os.path.join(SCRATCH, "www-up", "cga", "deps", "bin", "index"),
    }
    before = {}
    for k, p in files.items():
        try:
            st = os.stat(p)
            before[k] = (open(p, "rb").read(), st.st_mtime_ns)
        except Exception as e:
            before[k] = (b"<missing>", 0)
    payload = b"PWNED-BY-ACCEPT-VERIFY\n"
    targets = [
        ("/cga/init.sh", "init.sh"),
        ("/cga/.env", ".env"),
        ("/cga/deps/bin/index", "deps/bin/index"),
        ("/link/init.sh", "init.sh"),
        ("/cga/%69nit.sh", "init.sh"),
        ("/cga/INIT.SH", None),
        ("/cga/foo.txt", None),
    ]
    for tgt, fkey in targets:
        p = subprocess.run(["curl", "-sS", "--max-time", "8", "-o", "/dev/null", "-w", "%{http_code}",
                            "-X", "PUT", "--data-binary", "@-", f"http://{HOST}:29094{tgt}"],
                           input=payload, capture_output=True, timeout=12)
        code = p.stdout.decode().strip()
        rec(area, f"PUT {tgt} → 403 拒绝", code == "403", 403, code,
            f"curl -X PUT --data-binary @pwn http://127.0.0.1:29094{tgt}", sev="P0", owner="static")
        if fkey:
            b, mt = before[fkey]
            try:
                now = open(files[fkey], "rb").read()
                nm = os.stat(files[fkey]).st_mtime_ns
            except Exception:
                now, nm = b"<missing>", 0
            rec(area, f"PUT {tgt} 后 {fkey} 内容/mtime 未变", now == b and nm == mt,
                "unchanged", f"content={'same' if now == b else 'CHANGED'} mtime={'same' if nm == mt else 'CHANGED'}",
                sev="P0", owner="static")
    # 正常上传（不在任何 app docroot 内）必须仍可用
    tag = f"/gate-ok-{int(time.time())}.txt"
    p = subprocess.run(["curl", "-sS", "--max-time", "8", "-o", "/dev/null", "-w", "%{http_code}",
                        "-X", "PUT", "--data-binary", "@-", f"http://{HOST}:29094{tag}"],
                       input=b"normal upload\n", capture_output=True, timeout=12)
    code = p.stdout.decode().strip()
    rec(area, "app docroot 外正常上传 → 2xx", code in ("200", "201", "204"), "2xx", code,
        f"PUT {tag}", sev="P1", owner="static")
    code, body = curl_body([f"http://{HOST}:29094{tag}"])
    rec(area, "正常上传内容可 GET 回", code == "200" and b"normal upload" in body, "200", code,
        sev="P2", owner="static")

    # wave-7：闸门「全形态」——判据在 percent-decode + 归一化之后（upload_api.rs:321-392），
    # 含 query / 双斜杠 / 点段 / 编码分隔符都必须被拒；`..` 穿越形态由 safe_join 在前一道拒。
    # `%2F`/`%5C` 有**更早**的显式拒绝（服务端回 400「路径含编码分隔符(%2f/%5c)，拒绝」），
    # 与 403 同为「拒绝且不落盘」；两种都算通过（关键是无写入，下面逐文件核对内容/mtime）。
    exotic = [
        ("/cga/init.sh?q=1", "query", ("403",)),
        ("/cga//init.sh", "双斜杠", ("403",)),
        ("/cga/./init.sh", "点段", ("403",)),
        ("/cga/deps%2Fbin%2Findex", "编码分隔符 %2F", ("400", "403")),
        ("/cg%61/init.sh", "编码目录名 %61=a", ("403",)),
        ("/cga/deps/../init.sh", ".. 穿越", ("400", "403", "404")),
        ("/link/../cga/init.sh", ".. 穿越(经符号链接)", ("400", "403", "404")),
    ]
    for tgt, label, want in exotic:
        code, _ = curl_body(["-X", "PUT", "--data-binary", "PWNED2", f"http://{HOST}:29094{tgt}"],
                            timeout=12)
        rec(area, f"PUT {tgt}（{label}）→ 拒绝 {want}", code in want,
            "/".join(want), code,
            f"curl -X PUT --data-binary PWNED2 http://127.0.0.1:29094{tgt}", sev="P0", owner="static")
    for fkey in files:
        b, mt = before[fkey]
        try:
            now = open(files[fkey], "rb").read()
            nm = os.stat(files[fkey]).st_mtime_ns
        except Exception:
            now, nm = b"<missing>", 0
        rec(area, f"闸门全形态后 {fkey} 内容/mtime 仍未变", now == b and nm == mt,
            "unchanged", f"content={'same' if now == b else 'CHANGED'}",
            sev="P0", owner="static")


def test_upload_session_recovery():
    """wave-7 复核点（h1c-wave6 §3.2 的可用性缺陷）：上传口 per-IP 会话配额 16，
    若「中断/畸形的失败上传」也占配额且不回收，15 次中断后同一 IP 会被 503 锁到 TTL(1h)。
    断言：20 次中断（发头 + 少量字节后强行断开）之后，同 IP 的正常上传仍 2xx。"""
    area = "扩展·上传中断 20 次后同 IP 上传（wave-7 复核）"
    for i in range(20):
        try:
            s = socket.create_connection((HOST, 29094), timeout=5)
            s.sendall((f"PUT /abort-{int(time.time())}-{i}.bin HTTP/1.1\r\n"
                       f"Host: 127.0.0.1:29094\r\nContent-Length: 1024\r\n\r\n").encode()
                      + b"0123456789")
            s.settimeout(1.5)
            try:
                s.recv(4096)          # 可能拿到 400（body 不完整），也可能直接 EOF
            except Exception:
                pass
            s.close()                  # 强行中断（RST/FIN）
        except Exception:
            pass
    time.sleep(1.0)
    tag = f"/after-aborts-{int(time.time())}.txt"
    code, body = curl_body(["-X", "PUT", "--data-binary", "normal-after-aborts",
                            f"http://{HOST}:29094{tag}"], timeout=10)
    rec(area, "中断 20 次后同 IP 正常上传仍 2xx（非 503 锁死）",
        code in ("200", "201", "204"), "2xx（非 503）", code,
        "20×（PUT CL:1024 + 发 10 字节后断开）→ 再普通 PUT",
        sev="P1", owner="static")
    c2, b2 = curl_body([f"http://{HOST}:29094{tag}"])
    if code in ("200", "201", "204"):
        rec(area, "中断后上传内容正确（GET 回读）", c2 == "200" and b2 == b"normal-after-aborts",
            "200 + 内容一致", f"{c2} {b2[:30]!r}", sev="P2", owner="static")


# ─────────────── ACME 面板/续期统一入口（wave-6 半成品复核） ───────────────
def test_acme_unified_entry():
    area = "扩展·面板 ACME 立即签发走统一入口（:29095）"
    out = admin_req("POST", "/api/dns/acme/issue")
    # admin_req 用 latin1 解码；服务端错误文案是 UTF-8，这里还原后判据才可靠。
    try:
        text = out.encode("latin1", "ignore").decode("utf-8", "replace")
    except Exception:
        text = out
    low = text.lower()
    # 旧面板自拼命令：空域名报 `unsafe domain ""`；统一入口（issue_now→issue_if_missing）
    # 报可定位的「domain 未配置」。黑盒判据只认新错误文案。
    rec(area, "acme/issue 空域名 → 统一入口错误（domain 未配置，非 unsafe domain）",
        ("未配置" in text) and ("unsafe" not in low),
        "domain 未配置", text[:100], "curl -u admin:admin -X POST -H 'Origin: ...' :29095/__admin/api/dns/acme/issue",
        sev="P2", owner="dns")


def test_acme_fake_client():
    """wave-7：面板「立即签发」走统一入口（issue_now→issue→探测 acme.sh/acme-client/certbot）
    —— 用**假 certbot**（PATH 里第一个）黑盒证明面板触发的是真实探测链，而不是旧的自拼命令。

    独立实例：admin listener :29096x（不冲突）+ [dns.acme] domain 配好但 enabled=false
    （不 spawn 续期循环、不 bind :80）；启动时 PATH 前置 `$SCRATCH/bin/acme-fake`。
    假 certbot 被 run_client 调用时写 marker 并退出 1 → 面板回错误（含 certbot 失败信息）。
    判据：marker 出现（面板真的驱动了外部签发工具链）。"""
    area = "扩展·面板签发统一入口（假 acme 脚本）"
    port = 29084
    cfg = os.path.join(SCRATCH, "conf", "acme-fake.toml")
    with open(cfg, "w") as f:
        f.write(f'''
[access_log]
enable = false

[admin]
realm = "accept-verify-acme"
path = "/__admin"

[[admin.users]]
username = "admin"
password_hash = "$argon2id$v=19$m=19456,t=2,p=1$E/RLobwgix2BWMRMT++urA$yEympjJtiDh0ezwSQsnkbsfYAoSzeDAHYw3EsUMBsj4"

[dns]
enabled = true
test_mode = true
port = 29554
rndc_port = 29154
ecs = true

[dns.acme]
enabled = false
domain = "fake-acme.crucible.test"
email = "admin@crucible.test"
webroot = "{SCRATCH}/acme-fake-www"

[[listeners]]
address = "127.0.0.1"
port = {port}
root = "{SCRATCH}/www-alog2"
http_versions = ["h1"]
''')
    env = dict(os.environ)
    env["CRUCIBLE_DNS_STATE_ROOT"] = os.path.join(SCRATCH, "state-dns-acme")
    env["PATH"] = os.path.join(SCRATCH, "bin", "acme-fake") + ":" + env.get("PATH", "")
    log = os.path.join(SCRATCH, "logs", "acme-fake.log")
    marker = os.path.join(SCRATCH, "tmp", "acme-fake.marker")
    try:
        os.remove(marker)
    except Exception:
        pass
    try:
        p = subprocess.Popen([os.path.join(SCRATCH, "bin", "webserver"), "--config", cfg],
                             stdout=open(log, "w"), stderr=subprocess.STDOUT, env=env,
                             cwd="/home/dev123/crucible-git")
    except Exception as e:
        rec(area, "启动假 ACME 实例", False, "ok", f"exc {e}", sev="P2", owner="dns")
        return
    for _ in range(40):
        time.sleep(0.25)
        if curl([f"http://{HOST}:{port}/"]) == "200":
            break
    # 面板 POST /api/dns/acme/issue（与 ext 其余 admin 调用同款：带 Origin + X-Requested-With）
    import subprocess as _sp
    pr = _sp.run(["curl", "-sS", "--max-time", "20", "-X", "POST",
                  f"http://{HOST}:{port}/__admin/api/dns/acme/issue",
                  "-u", "admin:admin", "-H", f"Origin: http://{HOST}:{port}"],
                 capture_output=True, timeout=25)
    resp = pr.stdout.decode("latin1", "replace")
    time.sleep(0.5)
    invoked = os.path.exists(marker)
    try:
        p.terminate()
        p.wait(timeout=5)
    except Exception:
        pass
    rec(area, "面板 acme/issue 驱动外部工具链（假 certbot 被调用）", invoked,
        "marker 出现", f"marker={'yes' if invoked else 'no'} resp={resp[:90]!r}",
        "独立实例 [dns.acme] domain 已配 + PATH 前置假 certbot；POST /api/dns/acme/issue",
        sev="P2", owner="dns")
    rec(area, "假 certbot 失败 → 面板返回可定位错误（非静默 ok）",
        (not invoked) or ("error" in resp.lower() or "失败" in resp or "certbot" in resp.lower()),
        "错误响应", resp[:100], sev="P2", owner="dns")


def test_engine_abi_guard():
    """wave-7 复核点：ABI 自报符号的旧/新 .so 行为（wave-2 P0 回归防线）。

    假 .so（accept-verify-fakeabi.c 现编，见 accept-verify.sh）：
      * libapp_fake_abi_old.so —— 旧代产物：**缺** `appengine_abi_version`；
      * libapp_fake_abi_bad.so —— 自报 `appengine_abi_version()==99`（host 期望 2）。
    两者 `appengine_execute` 一旦被调用就写 marker。断言：两条路径都 502 拒载、
    marker 不存在（= 没被调用）、实例存活且随后仍正常服务。"""
    area = "扩展·引擎 ABI 握手（旧代/异版 .so 拒载，:29094）"
    pidf = os.path.join(SCRATCH, "webserver.pid")
    try:
        pid = int(open(pidf).read().strip())
    except Exception as e:
        rec(area, "读取实例 PID", False, "pid", f"exc {e}", sev="P1", owner="apps")
        return
    for path, label, marker in [
        ("/fakeabiold/", "旧代 .so（缺 appengine_abi_version）", "old"),
        ("/fakeabibad/", "异版 .so（自报 ABI=99）", "bad"),
    ]:
        mf = os.path.join(SCRATCH, f"abi-{marker}.marker")
        try:
            os.remove(mf)
        except Exception:
            pass
        p = subprocess.run(["curl", "-sS", "--max-time", "15", "-o", "/dev/null",
                            "-w", "%{http_code}", f"http://{HOST}:29094{path}"],
                           capture_output=True, timeout=20)
        code = p.stdout.decode().strip()
        executed = os.path.exists(mf)
        alive = True
        try:
            os.kill(pid, 0)
        except Exception:
            alive = False
        rec(area, f"{label} → 502 拒载", code == "502", 502, code,
            f"curl http://127.0.0.1:29094{path}", sev="P0", owner="apps")
        rec(area, f"{label} 未被调用（marker 不存在）", not executed, "no marker",
            "MARKER 出现=错误地调用了 .so" if executed else "no marker", sev="P0", owner="apps")
        rec(area, f"{label} 后进程存活", alive, "alive", "alive" if alive else "DEAD",
            sev="P0", owner="apps")
    # 半死后仍服务：正常静态请求应 200
    c = curl([f"http://{HOST}:29095/"])
    rec(area, "ABI 拒载后实例仍正常服务（:29095 → 200）", c == "200", 200, c,
        sev="P0", owner="apps")
    # 正面对照：合法 ABI（真 libapp_cgi.so 自报 2）必须能加载并执行
    code, body = curl_body([f"http://{HOST}:29094/cga/index.cgi"], timeout=15)
    rec(area, "新代 .so（真 libapp_cgi.so，ABI=2）正常加载执行（/cga/index.cgi → 200 cga-index）",
        code == "200" and b"cga-index" in body, "200 cga-index",
        f"{code} {body[:40]!r}", sev="P1", owner="apps")


def main():
    out = os.path.join(SCRATCH, "accept-ext-results.json")
    if "--json" in sys.argv:
        out = sys.argv[sys.argv.index("--json") + 1]
    test_tls_ip_access()
    test_h3_ip_access()
    test_ip_access_control_faces()
    test_page_rule_dims()
    test_priority_regression()
    test_per_site_access_log()
    test_per_site_access_log_level()
    test_per_site_access_log_global_off()
    test_env_isolation()
    test_cgi_script_path_info()
    test_upload_rce_gate()
    test_upload_session_recovery()
    test_engine_abi_guard()
    test_acme_unified_entry()
    test_acme_fake_client()
    test_sighup()
    test_worker_cap()
    test_panel_empty_ext()
    npass = sum(1 for r in RESULTS if r["status"] == "PASS")
    nfail = sum(1 for r in RESULTS if r["status"] == "FAIL")
    nskip = sum(1 for r in RESULTS if r["status"] == "SKIP")
    print(f"\n==== EXT SUMMARY: PASS={npass} FAIL={nfail} SKIP={nskip} ====")
    with open(out, "w") as f:
        json.dump(RESULTS, f, indent=2, ensure_ascii=False)
    print(f"results -> {out}")
    sys.exit(1 if nfail else 0)


if __name__ == "__main__":
    main()
