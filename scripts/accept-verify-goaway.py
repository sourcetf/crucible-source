#!/usr/bin/env python3
"""accept-verify-goaway.py — HTTP/3 GOAWAY（配置变更优雅停机）黑盒复核（wave-6）。

背景：h3b-wave5 报告称「配置/证书变更 → 先发 H3 GOAWAY（RFC 9114 §5.2），
宽限 5s 让在飞请求收尾，再关端点」。本脚本独立复核两条：
  1. 空闲连接收到 GOAWAY（且 GOAWAY 之前连接未被 CONNECTION_CLOSE 掐断）；
  2. **在飞请求**（/slow 经代理到 2s 慢上游）在触发后仍拿到完整 200 响应。

触发方式：改本套件**自己 scratch 里**的 config-verify.toml（把 36098 listener 的 root
从 www-h3dir 换成 www-h3dir2 —— 指纹变化）+ SIGHUP；测完恢复原文件。
（证书文件用仓库共享 cert.pem，绝不 touch。）

aioquic 的 H3Connection 会静默忽略 control stream 上的 GOAWAY，因此这里在 QUIC 事件层
自行解析 server control stream（server-initiated uni，stream_id % 4 == 3）。

用法: python3 scripts/accept-verify-goaway.py [--json out.json]
"""
import asyncio, json, os, re, signal, ssl, subprocess, sys, time

HOST = "127.0.0.1"
PORT = 36098
SCRATCH = "/home/dev123/scratch-verify6"
AUTHORITY = f"{HOST}:{PORT}"
OLD_ROOT = f"{SCRATCH}/www-h3dir"
NEW_ROOT = f"{SCRATCH}/www-h3dir2"
PIDF = os.path.join(SCRATCH, "webserver.pid")


def running_cfg():
    """从 /proc/<pid>/cmdline 取**当前进程实际用的**配置文件。

    套件收尾（PASS2/PASS2.1）会把实例换成 `config-verify-nov6.toml`；若这里写死
    `config-verify.toml`，独立重跑会编辑一个没人读的文件 + SIGHUP，观测到「没有
    GOAWAY」——那是测量装置问题，不是产品行为（verify6-wave12 实测踩到）。
    """
    try:
        pid = int(open(PIDF).read().strip())
        parts = open(f"/proc/{pid}/cmdline", "rb").read().split(b"\0")
        for i, p in enumerate(parts):
            if p == b"--config" and i + 1 < len(parts):
                return parts[i + 1].decode()
    except OSError:
        pass
    return os.path.join(SCRATCH, "conf", "config-verify.toml")


CFG = running_cfg()

RESULTS = []


def rec(area, name, ok, expected="", observed="", repro="", sev="P1", skip=False, owner="h2h3"):
    st = "SKIP" if skip else ("PASS" if ok else "FAIL")
    RESULTS.append(dict(area=area, name=name, status=st, severity=sev, expected=str(expected),
                        observed=str(observed), repro=repro, owner=owner))
    print(f"[{st}] {name}" + ("" if ok else f"  (exp={expected!r} obs={observed!r})"))


def read_varint(buf, off):
    b0 = buf[off]
    if b0 < 0x40:
        return b0, off + 1
    if b0 < 0x80:
        return ((b0 & 0x3F) << 8) | buf[off + 1], off + 2
    if b0 < 0xC0:
        return ((b0 & 0x3F) << 16) | int.from_bytes(buf[off + 1:off + 3], "big"), off + 3
    return ((b0 & 0x3F) << 24) | int.from_bytes(buf[off + 1:off + 5], "big"), off + 5


def make_client():
    from aioquic.asyncio.protocol import QuicConnectionProtocol
    from aioquic.h3.connection import H3Connection
    from aioquic.h3.events import HeadersReceived, DataReceived
    from aioquic.quic.events import StreamDataReceived, StreamReset, ConnectionTerminated

    class Client(QuicConnectionProtocol):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            self._http = H3Connection(self._quic)
            self.resp = {}
            self.ctrl = {}
            self.ctrl_type = {}
            self.goaways = []
            self.goaway_at = None
            self.resets = {}
            self.terminated = None

        def _slot(self, sid):
            return self.resp.setdefault(sid, {"headers": None, "body": b"", "ended": False})

        def _scan_control(self, sid):
            raw = self.ctrl.get(sid)
            if raw is None:
                return
            st = self.ctrl_type.get(sid)
            if st is None:
                if not raw:
                    return
                st, _ = read_varint(raw, 0)
                self.ctrl_type[sid] = st
                if st != 0x00:
                    return
                off = 1
            else:
                off = 1
            while off < len(raw):
                try:
                    ftype, off2 = read_varint(raw, off)
                    flen, off3 = read_varint(raw, off2)
                except IndexError:
                    return
                if off3 + flen > len(raw):
                    return
                if ftype == 0x07:  # GOAWAY
                    mid, _ = read_varint(raw, off3)
                    if mid not in self.goaways:
                        self.goaways.append(mid)
                        self.goaway_at = time.time()
                off = off3 + flen

        def quic_event_received(self, event):
            if isinstance(event, StreamDataReceived):
                sid = event.stream_id
                if sid % 4 == 3:
                    self.ctrl[sid] = self.ctrl.get(sid, b"") + event.data
                    self._scan_control(sid)
                if event.end_stream:
                    self._slot(sid)["ended"] = True
            elif isinstance(event, StreamReset):
                self.resets[event.stream_id] = event.error_code
            elif isinstance(event, ConnectionTerminated):
                self.terminated = event
            for ev in self._http.handle_event(event):
                sid = getattr(ev, "stream_id", None)
                if sid is None:
                    continue
                if isinstance(ev, HeadersReceived):
                    self._slot(sid)["headers"] = ev.headers
                elif isinstance(ev, DataReceived):
                    self._slot(sid)["body"] += ev.data
                if getattr(ev, "stream_ended", False):
                    self._slot(sid)["ended"] = True

        def send_get(self, path):
            sid = self._quic.get_next_available_stream_id()
            self._http.send_headers(stream_id=sid, headers=[
                (b":method", b"GET"), (b":scheme", b"https"),
                (b":authority", AUTHORITY.encode()), (b":path", path.encode()),
            ], end_stream=True)
            self.transmit()
            return sid

        async def wait_resp(self, sid, seconds=10.0):
            t0 = time.time()
            while time.time() - t0 < seconds:
                await asyncio.sleep(0.05)
                self.transmit()
                if self.resp.get(sid, {}).get("ended"):
                    break
            return self.resp.get(sid, {})

    return Client


def status_of(slot):
    h = slot.get("headers")
    if not h:
        return None
    for k, v in h:
        if k == b":status":
            return int(v)
    return None


def trigger_reload(old=OLD_ROOT, new=NEW_ROOT):
    """把 36098 listener 的 root 换掉（指纹变化）+ SIGHUP。返回 (ok, msg)。"""
    try:
        s = open(CFG).read()
    except Exception as e:
        return False, f"read cfg: {e}"
    if old not in s:
        return False, f"pattern {old} not found"
    open(CFG + ".goaway.bak", "w").write(s)
    open(CFG, "w").write(s.replace(old, new, 1))
    os.utime(CFG, None)
    try:
        pid = int(open(PIDF).read().strip())
        os.kill(pid, signal.SIGHUP)
    except Exception as e:
        return False, f"SIGHUP: {e}"
    return True, "cfg edited + SIGHUP"


def restore_reload(old=OLD_ROOT, new=NEW_ROOT):
    try:
        if os.path.exists(CFG + ".goaway.bak"):
            s = open(CFG + ".goaway.bak").read()
            open(CFG, "w").write(s)
            os.utime(CFG, None)
            os.remove(CFG + ".goaway.bak")
        pid = int(open(PIDF).read().strip())
        os.kill(pid, signal.SIGHUP)
    except Exception:
        pass


async def scenario(inflight: bool, wait_s=20.0):
    async def _inner():
        from aioquic.asyncio.client import connect
        from aioquic.quic.configuration import QuicConfiguration

        Client = make_client()
        cfg = QuicConfiguration(alpn_protocols=["h3"], is_client=True)
        cfg.verify_mode = ssl.CERT_NONE
        async with connect(HOST, PORT, configuration=cfg, create_protocol=Client) as c:
            await c.ping()
            sid = c.send_get("/slow" if inflight else "/")
            if not inflight:
                r = await c.wait_resp(sid, seconds=6.0)
                base = status_of(r)
                print(f"[goaway] baseline GET / -> {base}")
            else:
                print("[goaway] sent GET /slow (2s upstream, in-flight)")
                await asyncio.sleep(0.5)
            ok, msg = trigger_reload()
            print(f"[goaway] trigger: ok={ok} {msg}")
            t0 = time.time()
            t_goaway = None
            while time.time() - t0 < wait_s:
                await asyncio.sleep(0.05)
                c.transmit()
                if c.goaways and t_goaway is None:
                    t_goaway = time.time() - t0
                if t_goaway is not None and (not inflight or c.resp.get(sid, {}).get("ended")):
                    break
                if c.terminated is not None and t_goaway is None:
                    break
            term = c.terminated
            status = status_of(c.resp.get(sid, {}))
            return {
                "goaway": list(c.goaways),
                "t_goaway": t_goaway,
                "terminated": None if term is None else term.error_code,
                "status": status,
            }
    return await asyncio.wait_for(_inner(), timeout=wait_s + 25)



def test_idle():
    area = "扩展·h3 GOAWAY（空闲连接 :36098）"
    try:
        r = asyncio.run(scenario(inflight=False))
    except Exception as e:
        rec(area, "空闲连接收到 H3 GOAWAY", False, "GOAWAY", f"exc {e!r}", owner="h2h3")
        return
    got = bool(r["goaway"])
    rec(area, "空闲连接收到 H3 GOAWAY（配置变更）", got, "GOAWAY frame",
        f"goaways={r['goaway']} t={r['t_goaway']} terminated={r['terminated']}",
        "改 scratch config 的 36098 root + SIGHUP；aioquic 自解析 control stream",
        sev="P1", owner="h2h3")
    rec(area, "GOAWAY 之前连接未被 CONNECTION_CLOSE 掐断", got and r["terminated"] is None,
        "no CONNECTION_CLOSE before GOAWAY",
        f"goaway={got} terminated={r['terminated']}", sev="P1", owner="h2h3")


def test_inflight():
    area = "扩展·h3 GOAWAY（在飞请求 :36098/slow）"
    try:
        r = asyncio.run(scenario(inflight=True, wait_s=25.0))
    except Exception as e:
        rec(area, "在飞请求收到 GOAWAY", False, "GOAWAY", f"exc {e!r}", owner="h2h3")
        return
    rec(area, "在飞请求期间收到 H3 GOAWAY", bool(r["goaway"]), "GOAWAY frame",
        f"goaways={r['goaway']} t={r['t_goaway']} terminated={r['terminated']}",
        sev="P1", owner="h2h3")
    rec(area, "在飞 /slow 请求仍拿到完整 200（响应不被截断）", r["status"] == 200, 200,
        f"status={r['status']} terminated={r['terminated']}", sev="P0", owner="h2h3")


async def scenario_grace_window(delay=2.2, wait_s=20.0):
    """宽限窗口内**新建连接**（wave-12 收口项，原 verify3b P3-1 / h2h3e-wave8 §3）。

    `h3_graceful_endpoint_close` 只在「广播时存在活跃连接」时才宽限 5s，所以：
      1) 先建长活连接 A（保证 receivers ≥ 1）；
      2) 触发重载（root 互换 + SIGHUP）；
      3) 等 delay 秒（广播已发生、ep.close() 未到）后再建连接 B；
      4) B 应被**入场自检**立即补发 GOAWAY（h3.rs 的 "arrived inside the shutdown grace
         window" 分支），其首条请求（stream id 0 ≤ GOAWAY max_id）仍按 crate
         grace-interval 语义被服务（RFC 9114 §5.2 可解释），宽限结束后以 0x0 收尾。
    """
    async def _inner():
        from aioquic.asyncio.client import connect
        from aioquic.quic.configuration import QuicConfiguration

        cfg = QuicConfiguration(alpn_protocols=["h3"], is_client=True)
        cfg.verify_mode = ssl.CERT_NONE
        ClientA = make_client()
        out = {}
        async with connect(HOST, PORT, configuration=cfg, create_protocol=ClientA) as a:
            await a.ping()
            sid = a.send_get("/")
            await a.wait_resp(sid, seconds=6.0)
            ok, msg = trigger_reload()
            out["trigger"] = f"ok={ok} {msg}"
            t0 = time.time()
            await asyncio.sleep(delay)
            ClientB = make_client()
            async with connect(HOST, PORT, configuration=cfg, create_protocol=ClientB) as b:
                out["b_connect_after"] = round(time.time() - t0, 3)
                sidb = b.send_get("/")
                rb = await b.wait_resp(sidb, seconds=6.0)
                out["b_status"] = status_of(rb)
                out["b_goaway_at_connect"] = (round(b.goaway_at - t0, 3)
                                              if b.goaway_at else None)
                for _ in range(80):
                    await asyncio.sleep(0.1)
                    b.transmit()
                    if b.terminated is not None:
                        break
                out["b_goaways"] = list(b.goaways)
                out["b_terminated"] = None if b.terminated is None else b.terminated.error_code
            # 收 A（老连接）
            for _ in range(60):
                await asyncio.sleep(0.1)
                a.transmit()
                if a.terminated is not None:
                    break
            out["a_goaways"] = list(a.goaways)
        return out
    return await asyncio.wait_for(_inner(), timeout=wait_s + 25)


def test_grace_window():
    area = "扩展·h3 GOAWAY（宽限窗口内新连接 :36098）"
    try:
        r = asyncio.run(scenario_grace_window())
    except Exception as e:
        rec(area, "宽限窗口内新建连接收到 GOAWAY", False, "GOAWAY frame", f"exc {e!r}",
            owner="h2h3")
        return
    rec(area, "宽限窗口内新建连接收到 GOAWAY（入场自检）", bool(r.get("b_goaways")),
        "GOAWAY frame", f"b_goaways={r.get('b_goaways')} t={r.get('b_goaway_at_connect')} "
                        f"connect_after={r.get('b_connect_after')}", owner="h2h3")
    rec(area, "宽限窗口内首条请求（stream id 0）仍被服务", r.get("b_status") == 200, 200,
        f"status={r.get('b_status')} terminated={r.get('b_terminated')} "
        f"({r.get('trigger')})", owner="h2h3")
    rec(area, "宽限结束后新连接以 0x0 正常收尾（非超时/非 RST）", r.get("b_terminated") == 0,
        0, f"terminated={r.get('b_terminated')}", owner="h2h3")


def probe_ok(timeout_each=6.0):
    """探测 36098 的 h3 端点是否已（重新）就绪：GET / → 200。"""
    async def _p():
        from aioquic.asyncio.client import connect
        from aioquic.quic.configuration import QuicConfiguration

        Client = make_client()
        cfg = QuicConfiguration(alpn_protocols=["h3"], is_client=True)
        cfg.verify_mode = ssl.CERT_NONE
        async with connect(HOST, PORT, configuration=cfg, create_protocol=Client) as c:
            await c.ping()
            sid = c.send_get("/")
            r = await c.wait_resp(sid, seconds=4.0)
            return status_of(r)
    try:
        return asyncio.run(asyncio.wait_for(_p(), timeout=timeout_each)) == 200
    except Exception:
        return False


def wait_h3_ready(total=40.0):
    """等端点从「宽限 5s 后重启」中恢复。

    旧端点会继续接受连接直到 `ep.close()`（宽限 5s）—— 在它上面 probe 也会成功，但它的
    watcher 已经退出（不会广播 GOAWAY），于是新一轮 trigger 打不中。所以：先睡满
    宽限(5s)+reconciler(2s)，再要求**连续两次**探活成功（间隔 2s），确认拿到的是新端点。
    """
    time.sleep(7.0)
    t0 = time.time()
    ok1 = ok2 = False
    while time.time() - t0 < total:
        if probe_ok():
            if ok1:
                ok2 = True
                break
            ok1 = True
        else:
            ok1 = False
        time.sleep(2.0)
    if ok2:
        return True
    return False


def upstream_ok():
    """h1(https) 打同一个 listener 的 /slow：200 说明套件上游活着（否则 502）。
    注意 36098 是 **TLS** listener，必须 https（明文打它是 TLS 握手错误 → 000）。"""
    try:
        import ssl, urllib.request
        ctx = ssl._create_unverified_context()
        r = urllib.request.urlopen(f"https://{HOST}:{PORT}/slow", timeout=8, context=ctx)
        return r.status == 200
    except Exception:
        return False


def main():
    out = os.path.join(SCRATCH, "accept-goaway-results.json")
    if "--json" in sys.argv:
        out = sys.argv[sys.argv.index("--json") + 1]
    try:
        test_idle()
    finally:
        restore_reload()
    # 旧端点宽限 5s + reconciler 2s + 重启：等到探活成功再跑在飞场景，
    # 否则会连到「正在关闭的旧端点」，必然收不到 GOAWAY（套件自身时序问题）。
    ready = wait_h3_ready()
    print(f"[goaway] endpoint re-ready after restore: {ready}")
    if not upstream_ok():
        rec("扩展·h3 GOAWAY（在飞请求 :36098/slow）", "在飞请求期间收到 H3 GOAWAY", False,
            "GOAWAY frame", "上游 36099 /slow 不可达（外部误杀？）", owner="h2h3", skip=True)
        rec("扩展·h3 GOAWAY（在飞请求 :36098/slow）", "在飞 /slow 请求仍拿到完整 200（响应不被截断）",
            False, 200, "上游 36099 /slow 不可达", owner="h2h3", skip=True)
    else:
        try:
            test_inflight()
        finally:
            restore_reload()
    # ── 宽限窗口内新连接（wave-12 收口项）：需要端点已恢复 + 一条长活连接撑开宽限 ──
    ready2 = wait_h3_ready()
    print(f"[goaway] endpoint re-ready before grace-window test: {ready2}")
    try:
        test_grace_window()
    finally:
        restore_reload()
    npass = sum(1 for r in RESULTS if r["status"] == "PASS")
    nfail = sum(1 for r in RESULTS if r["status"] == "FAIL")
    nskip = sum(1 for r in RESULTS if r["status"] == "SKIP")
    print(f"\n==== GOAWAY SUMMARY: PASS={npass} FAIL={nfail} SKIP={nskip} ====")
    with open(out, "w") as f:
        json.dump(RESULTS, f, indent=2, ensure_ascii=False)
    print(f"results -> {out}")
    sys.exit(1 if nfail else 0)


if __name__ == "__main__":
    main()
