#!/usr/bin/env python3
"""accept-verify-ext.py — 工号 1009 / agent-verify2 扩展黑盒检查（wave-5）。

覆盖主套件不易放进去的项：
- per-listener ip_access 在 TLS 面（:26096）与 h3 面（:26097）是否生效
  （core2-wave4 报告点名「TLS/h3 请求路径仍走全局 ip_access」，本脚本回归）
- SIGHUP 重载：进程存活且继续服务
- worker 线程上界（CRUCIBLE_WORKER_THREADS 过大 → 钳制到 1024）
- 面板空 extensions 保存后路由仍正常（admin /api/apps/save 往返）

前提：主实例（config-verify.toml，端口 26000+）已由 accept-verify-start.sh 起好，
且 accept-verify-upstream.py 在 26099/26100 上跑着。

用法: python3 scripts/accept-verify-ext.py [--json out.json]
"""
import asyncio, sys, json, os, ssl, socket, subprocess, time, signal

HOST = "127.0.0.1"
TLSIP = 26096      # TLS + per-listener ip_access
H3IP = 26097       # h1+h2+h3 + per-listener ip_access
APPS = 26095
SCRATCH = "/home/dev123/scratch-verify2"
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
    area = "扩展·per-listener ip_access（TLS 面 :26096）"
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


def test_h3_ip_access():
    area = "扩展·per-listener ip_access（h3 面 :26097）"
    try:
        st = asyncio.run(_h3_get(H3IP, "/", f"{HOST}:{H3IP}", "h3ip.crucible.local"))
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
    pre = curl([f"http://{HOST}:26081/"])
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
    post = curl([f"http://{HOST}:26081/"])
    rec(area, "SIGHUP 后进程存活", alive, "alive", "alive" if alive else "dead", sev="P1", owner="core")
    rec(area, "SIGHUP 后仍正常服务", post == "200", "200", f"pre={pre} post={post}",
        "kill -HUP <pid>; curl http://127.0.0.1:26081/", sev="P1", owner="core")


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
port = 26085
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
            if threads and curl([f"http://{HOST}:26085/"]):
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


def main():
    out = os.path.join(SCRATCH, "accept-ext-results.json")
    if "--json" in sys.argv:
        out = sys.argv[sys.argv.index("--json") + 1]
    test_tls_ip_access()
    test_h3_ip_access()
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
