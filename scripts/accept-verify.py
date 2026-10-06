#!/usr/bin/env python3
"""accept-verify.py — 工号 1009 黑盒验收套件（HTTP/1.x + HTTP/2 + 静态 + 上传 +
autoindex + header 改写 + 限流 + ACL + 重定向 + 代理 + 应用引擎 + DNS 面板 + Admin API）。

前提：先 `sh scripts/accept-verify-start.sh` 起实例（端口块 23000+），
并 `python3 scripts/accept-verify-upstream.py &` 起本机上游。
本脚本只做黑盒请求，不修任何东西。

用法: python3 scripts/accept-verify.py [--json out.json]
退出码：0 = 无 P0/P1 失败；1 = 有失败。
"""
import sys, os, json, socket, ssl, subprocess, time, re, base64, argparse

REPO = "/home/dev123/crucible-git"
HOST = "127.0.0.1"
PLAIN = 23081     # h1+h2c 静态（qmux 明文）
APPS = 23095      # 应用引擎
TLS12 = 23445
TLS13 = 23446
PROD = 23443      # h1+h2+h3 + TLS + autoindex upload
DOH = 23444
ADV = 23090       # proxy + page_rules
RATE = 23091
AUTH = 23092
IPACC = 23093
UP = 23094        # upload + autoindex + 目录 301
UPSTREAM = 23099

ADMIN = ("admin", "admin")
TMP = "/home/dev123/scratch-verify/tmp"
os.makedirs(TMP, exist_ok=True)

RESULTS = []          # dict: area,name,status(PASS/FAIL/SKIP),severity,expected,observed,repro
_cur_area = "?"


def area(a):
    global _cur_area
    _cur_area = a
    print(f"\n=== {a} ===")


def rec(name, ok, expected="", observed="", repro="", sev="P1", skip=False, owner=""):
    st = "SKIP" if skip else ("PASS" if ok else "FAIL")
    RESULTS.append(dict(area=_cur_area, name=name, status=st, severity=sev,
                        expected=str(expected), observed=str(observed),
                        repro=repro, owner=owner))
    tag = {"PASS": "PASS", "FAIL": "FAIL", "SKIP": "SKIP"}[st]
    print(f"[{tag}] {name}" + ("" if ok else f"  (exp={expected!r} obs={observed!r})"))


def curl(args=None, timeout=10, method=None, data=None, headers=None, port=None, path="/",
         scheme="http", auth=None, http2=False, http10=False, insecure=True):
    """returns (code:int|None, headers:dict, body:bytes, raw:str)"""
    url = args[-1] if args else f"{scheme}://{HOST}:{port}{path}"
    if method == "HEAD":
        # HEAD 单独处理：-I 让 curl 把响应头当“body”输出，不能用 -o 取 body
        cmd = ["curl", "-sS", "--max-time", str(timeout)]
        if scheme == "https" and insecure:
            cmd += ["-k"]
        if auth:
            cmd += ["-u", f"{auth[0]}:{auth[1]}"]
        for h in (headers or []):
            cmd += ["-H", h]
        cmd += ["-I", url]
        try:
            p = subprocess.run(cmd, capture_output=True, timeout=timeout + 5)
            out = p.stdout.decode("latin1")
            lines = out.split("\r\n")
            code = None
            m = re.match(r"HTTP/\S+\s+(\d+)", lines[0]) if lines else None
            if m:
                code = int(m.group(1))
            hdrs = {}
            for ln in lines[1:]:
                if ":" in ln:
                    k, v = ln.split(":", 1)
                    hdrs[k.strip().lower()] = v.strip()
            return code, hdrs, b"", out
        except Exception as e:
            return None, {}, b"", f"ERR {e}"
    cmd = ["curl", "-sS", "--max-time", str(timeout)]
    if scheme == "https" and insecure:
        cmd += ["-k"]
    if http2:
        cmd += ["--http2-prior-knowledge"] if scheme == "http" else ["--http2"]
    if http10:
        cmd += ["--http1.0"]
    if method:
        if method == "HEAD":
            cmd += ["-I"]        # -I 才真正走 HEAD 语义；-X HEAD 会让 curl 等 body
        else:
            cmd += ["-X", method]
    if data is not None:
        cmd += ["--data-binary", data]
    if auth:
        cmd += ["-u", f"{auth[0]}:{auth[1]}"]
    for h in (headers or []):
        cmd += ["-H", h]
    cmd += ["-D", "-", "-o", os.path.join(TMP, "body.bin"), url]
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout + 5)
        out = p.stdout.decode("latin1")
        hdr_blob, _, _ = out.partition("\r\n\r\n")
        lines = hdr_blob.split("\r\n")
        code = None
        m = re.match(r"HTTP/\S+\s+(\d+)", lines[0]) if lines else None
        if m:
            code = int(m.group(1))
        hdrs = {}
        for ln in lines[1:]:
            if ":" in ln:
                k, v = ln.split(":", 1)
                hdrs[k.strip().lower()] = v.strip()
        body = b""
        bp = os.path.join(TMP, "body.bin")
        if os.path.exists(bp):
            body = open(bp, "rb").read()
        return code, hdrs, body, out
    except Exception as e:
        return None, {}, b"", f"ERR {e}"


def raw_h1(port, payload, read_timeout=5, maxread=65536):
    """发送裸 HTTP/1.x 请求，返回原始响应字节。"""
    try:
        s = socket.create_connection((HOST, port), timeout=5)
        s.sendall(payload)
        s.settimeout(read_timeout)
        data = b""
        try:
            while len(data) < maxread:
                d = s.recv(4096)
                if not d:
                    break
                data += d
        except socket.timeout:
            pass
        s.close()
        return data
    except Exception as e:
        return b"ERR " + str(e).encode()


# ───────────────────────── 静态 / HTTP 语义 ─────────────────────────
def test_static():
    area("静态文件 / HTTP 语义 (h1 :23081)")
    c, h, b, _ = curl(port=PLAIN, path="/")
    rec("GET / → 200", c == 200, 200, c, f"curl -s http://127.0.0.1:{PLAIN}/")
    rec("Content-Length 存在且等于 body", h.get("content-length") == str(len(b)),
        "len(body)", f"{h.get('content-length')} vs {len(b)}")
    c, h, b, _ = curl(port=PLAIN, path="/", method="HEAD")
    rec("HEAD / → 200 且无 body", c == 200 and len(b) == 0, "200/no-body", f"{c}/{len(b)}")

    # HTTP/1.0
    r = raw_h1(PLAIN, b"GET / HTTP/1.0\r\n\r\n")
    rec("HTTP/1.0 GET / 无 Host → 200", r.startswith(b"HTTP/1.0 200") or r.startswith(b"HTTP/1.1 200"),
        "200", r.split(b"\r\n")[0][:40], "printf 'GET / HTTP/1.0\\r\\n\\r\\n' | nc 127.0.0.1 23081")

    # HTTP/1.1 缺 Host → 400
    r = raw_h1(PLAIN, b"GET / HTTP/1.1\r\n\r\n")
    rec("HTTP/1.1 缺 Host → 400", b" 400" in r.split(b"\r\n")[0], "400", r.split(b"\r\n")[0][:40],
        "printf 'GET / HTTP/1.1\\r\\n\\r\\n' | nc 127.0.0.1 23081", sev="P1", owner="h1")

    # 目录无尾斜杠 → 301 且 Location 以 / 结尾
    c, h, b, _ = curl(port=UP, path="/sub")
    loc = h.get("location", "")
    rec("目录无尾斜杠 → 301 + Location 尾斜杠", c == 301 and loc.endswith("/"),
        "301 Location=/sub/", f"{c} loc={loc}",
        f"curl -s -o /dev/null -w '%{{http_code}} %{{redirect_url}}' http://127.0.0.1:{UP}/sub",
        sev="P1", owner="static")

    # autoindex 链接编码（用一个**没有 index 文件**的目录才会出列表）
    c, h, b, _ = curl(port=UP, path="/listing/")
    html = b.decode("latin1")
    bad = re.search(r'href="[^"]*%2[Ff]', html)
    rec("autoindex 子目录链接不含 %2F", bad is None, "no %2F", bad.group(0) if bad else "ok",
        f"curl http://127.0.0.1:{UP}/listing/", sev="P2", owner="static")
    rec("autoindex 列出子目录 sub/", c == 200 and "sub" in html, "200 listing has sub",
        f"{c} {'has sub' if 'sub' in html else html[:60]}", sev="P2", owner="static")

    # ETag + If-None-Match → 304
    c, h, b, _ = curl(port=PLAIN, path="/index.html")
    etag = h.get("etag")
    rec("静态响应带 ETag", bool(etag), "ETag present", etag)
    if etag:
        c2, h2, _, _ = curl(port=PLAIN, path="/index.html", headers=[f"If-None-Match: {etag}"])
        rec("If-None-Match 命中 → 304", c2 == 304, 304, c2, sev="P1", owner="static")

    # Range → 206
    c, h, b, _ = curl(port=PLAIN, path="/index.html", headers=["Range: bytes=0-4"])
    rec("Range: bytes=0-4 → 206 + Content-Range", c == 206 and "content-range" in h,
        "206 Content-Range: bytes 0-4/N", f"{c} cr={h.get('content-range')}", sev="P1", owner="static")
    rec("206 body 长度=5", len(b) == 5, 5, len(b))
    # 非法 Range → 416
    c, h, b, _ = curl(port=PLAIN, path="/index.html", headers=["Range: bytes=99999-100000"])
    rec("越界 Range → 416", c == 416, 416, c, sev="P2", owner="static")

    # HEAD + Range
    c, h, b, _ = curl(port=PLAIN, path="/index.html", method="HEAD", headers=["Range: bytes=0-4"])
    rec("HEAD+Range → 206 无 body", c == 206 and len(b) == 0, "206/empty", f"{c}/{len(b)}", owner="static")

    # 路径穿越
    for pth in ["/../../etc/passwd", "/..%2f..%2fetc%2fpasswd", "/%2e%2e/%2e%2e/etc/passwd"]:
        c, h, b, _ = curl(port=PLAIN, path=pth)
        leak = b"root:" in b
        rec(f"路径穿越 {pth} 不泄漏", (not leak) and c in (400, 403, 404),
            "403/404 无泄漏", f"{c} leak={leak}", sev="P0", owner="static")

    # 未知方法 → 405
    c, h, b, _ = curl(port=PLAIN, path="/index.html", method="DELETE")
    rec("静态 DELETE → 405", c == 405, 405, c, sev="P2", owner="static")

    # POST 到静态 → 405 且带 content-type（wave2 交接项 4）
    c, h, b, _ = curl(port=PLAIN, path="/index.html", method="POST", data="x")
    rec("静态 POST → 405 带 content-type", c == 405 and "content-type" in h,
        "405 + content-type", f"{c} ct={h.get('content-type')}", sev="P2", owner="static")

    # Host 校验：非法 Host → 400
    for hv in ["..", "_"]:
        r = raw_h1(PLAIN, f"GET / HTTP/1.1\r\nHost: {hv}\r\nConnection: close\r\n\r\n".encode())
        rec(f"非法 Host {hv!r} → 400", b" 400" in r.split(b"\r\n")[0], "400",
            r.split(b"\r\n")[0][:40], sev="P2", owner="h1")


# ───────────────────────── HTTP/2 ─────────────────────────
def test_h2():
    area("HTTP/2 (h2c :23081 / TLS h2 :23443)")
    c, h, b, raw = curl(port=PLAIN, path="/", http2=True)
    rec("h2c GET / → 200", c == 200, 200, c, f"curl --http2-prior-knowledge http://127.0.0.1:{PLAIN}/",
        sev="P0", owner="h2h3")
    c, h, b, raw = curl(port=PROD, path="/", scheme="https", http2=True)
    rec("TLS h2 GET / → 200", c == 200, 200, c, sev="P1", owner="h2h3")

    # 目录 301 一致性 h1 vs h2
    c1, h1d, _, _ = curl(port=UP, path="/sub", http2=False)
    c2, h2d, _, _ = curl(port=UP, path="/sub", http2=True)
    rec("目录 301 h1/h2 一致", c1 == c2 == 301 and
        (h1d.get("location") or "").endswith("/") == (h2d.get("location") or "").endswith("/"),
        "h1==h2 301", f"h1={c1}/{h1d.get('location')} h2={c2}/{h2d.get('location')}",
        sev="P2", owner="h2h3")

    # 405 content-type 一致性
    c1, h1d, _, _ = curl(port=UP, path="/index.html", method="POST", data="x")
    c2, h2d, _, _ = curl(port=UP, path="/index.html", http2=True, method="POST", data="x")
    rec("405 content-type h1/h2 一致", (("content-type" in h1d) == ("content-type" in h2d)),
        "both have/absent ct", f"h1ct={h1d.get('content-type')} h2ct={h2d.get('content-type')}",
        sev="P2", owner="static")

    # h2 缺 :authority / 非法 Host 校验（wave2 交接项 2）
    # 用 curl 无法直接构造非法 :authority，改用 --header 'Host: ..'
    c, h, b, _ = curl(port=PROD, path="/", scheme="https", http2=True, headers=["Host: .."])
    rec("h2 非法 Host(..) → 400", c == 400, 400, c, sev="P1", owner="h2h3")
    c, h, b, _ = curl(port=PROD, path="/", scheme="https", http2=True, headers=["Host: _"])
    rec("h2 非法 Host(_) → 400", c == 400, 400, c, sev="P1", owner="h2h3")


# ───────────────────────── TLS ─────────────────────────
def test_tls():
    area("TLS (:23445 TLS1.2 / :23446 TLS1.3 / :23443)")
    c, h, b, raw = curl(port=TLS13, path="/", scheme="https")
    rec("TLS1.3 listener 200", c == 200, 200, c)
    # 版本协商：23446 prefer 1.3
    p = subprocess.run(["openssl", "s_client", "-connect", f"{HOST}:{TLS13}", "-tls1_3",
                        "-servername", "fair-tls13-test.crucible.local", "-brief"],
                       input=b"", capture_output=True, timeout=10)
    rec("TLS1.3 握手成功", p.returncode == 0 or b"Protocol version: TLSv1.3" in p.stdout + p.stderr,
        "TLSv1.3", (p.stdout + p.stderr).decode("utf-8","replace")[:80])
    # 23445 只允许 1.2
    p = subprocess.run(["openssl", "s_client", "-connect", f"{HOST}:{TLS12}", "-tls1_3",
                        "-servername", "fair-tls12-test.crucible.local"],
                       input=b"", capture_output=True, timeout=10)
    out = (p.stdout + p.stderr).decode("utf-8","replace")
    rec("TLS1.2 listener 拒绝 TLS1.3", "alert" in out.lower() or "handshake failure" in out.lower()
        or "no protocols available" in out.lower() or p.returncode != 0,
        "拒绝1.3", out.strip().splitlines()[-1][:80] if out.strip() else "", sev="P2", owner="tls")
    # ALPN h2 提供
    p = subprocess.run(["openssl", "s_client", "-connect", f"{HOST}:{TLS13}", "-alpn", "h2",
                        "-servername", "fair-tls13-test.crucible.local"],
                       input=b"", capture_output=True, timeout=10)
    out = (p.stdout + p.stderr).decode("utf-8","replace")
    rec("TLS ALPN 协商 h2", "ALPN protocol: h2" in out,
        "ALPN=h2", [l for l in out.splitlines() if "ALPN" in l][:1], sev="P1", owner="tls")
    # QMux v1 ALPN（config 23445 qmux=true）：客户端只给 h1-02qx 时应协商成功
    p = subprocess.run(["openssl", "s_client", "-connect", f"{HOST}:{TLS12}", "-alpn", "h1-02qx",
                        "-servername", "fair-tls12-test.crucible.local"],
                       input=b"", capture_output=True, timeout=10)
    out2 = (p.stdout + p.stderr).decode("utf-8", "replace")
    rec("QMux ALPN h1-02qx 被接受", "ALPN protocol: h1-02qx" in out2, "ALPN=h1-02qx",
        [l for l in out2.splitlines() if "ALPN" in l][:1], sev="P2", owner="h2h3")


# ───────────────────────── 上传 / 断点续传 ─────────────────────────
def test_upload():
    area("上传 / 断点续传 (:23094 PUT/PATCH)")
    name = f"/accept-{int(time.time())}.txt"
    payload = "hello-crucible-upload"
    c, h, b, _ = curl(port=UP, path=name, method="PUT", data=payload,
                      headers=["Content-Type: text/plain"])
    rec("PUT 新文件 → 2xx", c in (200, 201, 204), "2xx", c,
        f"curl -T - http://127.0.0.1:{UP}{name}", sev="P1", owner="static")
    c, h, b, _ = curl(port=UP, path=name)
    rec("PUT 后可 GET 回内容", c == 200 and b.decode("latin1") == payload, payload,
        f"{c} {b[:40]!r}", sev="P1", owner="static")
    # 断点续传：先 PUT 前 5 字节，再 PATCH 续写
    name2 = f"/accept-resume-{int(time.time())}.bin"
    c, h, b, _ = curl(port=UP, path=name2, method="PUT", data="ABCDE",
                      headers=["Content-Range: bytes 0-4/10"])
    rec("分片 PUT 0-4/10 → 2xx", c is not None and 200 <= c < 300, "2xx", c, sev="P1", owner="static")
    c, h, b, _ = curl(port=UP, path=name2, method="PATCH", data="FGHIJ",
                      headers=["Content-Range: bytes 5-9/10"])
    rec("PATCH 续传 5-9/10 → 2xx", c is not None and 200 <= c < 300, "2xx", c, sev="P1", owner="static")
    c, h, b, _ = curl(port=UP, path=name2)
    rec("续传后完整内容 ABCDEFGHIJ", b.decode("latin1") == "ABCDEFGHIJ", "ABCDEFGHIJ",
        b[:20], sev="P1", owner="static")
    # PUT 到已存在目录 → 409
    c, h, b, _ = curl(port=UP, path="/sub/", method="PUT", data="x")
    rec("PUT 到目录 → 409", c == 409, 409, c, sev="P2", owner="static")

    # 上传 webshell：PUT 一个 .php 到**被 php 引擎接管的路径** /php/。
    # 路由上 apps 优先于 upload，所以该 PUT 进 php 引擎（本机 502），关键是**没有文件落盘**。
    curl(port=UP, path="/php/evil.php", method="PUT", data="<?php echo 1; ?>")
    c, h, b, _ = curl(port=UP, path="/php/evil.php")
    leaked = b"<?php" in b
    rec("上传可执行 .php 不落盘（无 webshell）", not leaked, "无 php 源码可读",
        f"GET->{c} leaked={leaked}",
        f"curl -T evil.php http://127.0.0.1:{UP}/php/evil.php; curl http://127.0.0.1:{UP}/php/evil.php",
        sev="P0", owner="static")

    # body 读超时 408（slowloris on upload）：声明 100 字节只发 3 字节后挂住。
    # UPLOAD_IDLE_TIMEOUT = 60s（upload_api.rs），等 70s 看是否 408。
    try:
        s = socket.create_connection((HOST, UP), timeout=5)
        s.sendall((f"PUT /slow-{int(time.time())}.txt HTTP/1.1\r\n"
                   f"Host: 127.0.0.1:{UP}\r\nContent-Length: 100\r\n\r\n").encode() + b"abc")
        s.settimeout(72)
        t0 = time.time()
        try:
            d = s.recv(4096)
        except socket.timeout:
            d = b""
        el = time.time() - t0
        s.close()
        rec("上传 body 停滞 → 408（帧间超时 60s）", b" 408" in d.split(b"\r\n")[0],
            "408 within ~60s", f"{d.split(b'\r\n')[0][:30]!r} after {el:.0f}s",
            sev="P1", owner="static")
    except Exception as e:
        rec("上传 body 停滞 → 408", False, "408", f"exc {e}", sev="P1", owner="static")


# ───────────────────────── header 改写 / 页面规则 / 代理 ─────────────────────────
def test_adv():
    area("页面规则 / 代理 / header 改写 (:23090)")
    # rewrite /old/* → /new （rewrite_path 把 /old/<x> 映射为 /new/<x>）
    c, h, b, _ = curl(port=ADV, path="/old/index.html")
    rec("page_rule rewrite /old/* → /new", c == 200 and b"new content" in b,
        "200 new content", f"{c} {b[:30]!r}",
        f"curl http://127.0.0.1:{ADV}/old/index.html", sev="P1", owner="proxy")
    # redirect
    c, h, b, _ = curl(port=ADV, path="/redir/x")
    rec("page_rule redirect → 301 + Location", c == 301 and h.get("location") == "https://example.com/moved",
        "301 https://example.com/moved", f"{c} {h.get('location')}", sev="P1", owner="proxy")
    # header inject
    c, h, b, _ = curl(port=ADV, path="/hdr/x")
    rec("page_rule header 注入 X-Page", h.get("x-page") == "on", "X-Page: on", h.get("x-page"),
        sev="P2", owner="proxy")
    # block
    c, h, b, _ = curl(port=ADV, path="/blocked")
    rec("page_rule block → 403", c == 403, 403, c, sev="P2", owner="proxy")

    # 代理：基本转发
    c, h, b, _ = curl(port=ADV, path="/proxy/hello")
    rec("proxy 转发 → 200 + upstream 标记", c == 200 and h.get("x-upstream") == "yes",
        "200 X-Upstream:yes", f"{c} {h.get('x-upstream')}", sev="P1", owner="proxy")
    rec("proxy 响应头改写 X-Added-Resp", h.get("x-added-resp") == "resp-yes",
        "X-Added-Resp: resp-yes", h.get("x-added-resp"), sev="P1", owner="proxy")
    rec("proxy 请求头改写透传 X-Added-Req", b"x-added-req: req-yes" in b.lower(),
        "upstream 收到 x-added-req", b[:80], sev="P1", owner="proxy")

    # WebSocket 升级（wave2 P0：h1.rs 缺 .with_upgrades()）
    try:
        s = socket.create_connection((HOST, ADV), timeout=5)
        s.sendall((f"GET /ws HTTP/1.1\r\nHost: 127.0.0.1:{ADV}\r\n"
                   "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                   "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                   "Sec-WebSocket-Version: 13\r\n\r\n").encode())
        s.settimeout(5)
        first = s.recv(4096)
        upgraded = b" 101" in first.split(b"\r\n")[0]
        tunnel = False
        if upgraded:
            # 发送隧道字节，期望回显
            s.sendall(b"PING123")
            try:
                echo = s.recv(4096)
                tunnel = b"PING123" in echo
            except socket.timeout:
                tunnel = False
        s.close()
        rec("WebSocket 升级 → 101", upgraded, "101", first.split(b"\r\n")[0][:40],
            sev="P0", owner="h1")
        rec("WebSocket 隧道字节回显", tunnel, "echo PING123",
            "tunnel ok" if tunnel else "no echo/EOF", sev="P0", owner="h1")
    except Exception as e:
        rec("WebSocket 升级 → 101", False, "101", f"exc {e}", sev="P0", owner="h1")


# ───────────────────────── 限流 / ACL ─────────────────────────
def test_acl():
    area("限流 / ACL / basic auth (:23091/:23092/:23093)")
    # rate limit
    codes = []
    for _ in range(15):
        c, h, b, _ = curl(port=RATE, path="/", timeout=3)
        codes.append(c)
    rec("限流触发 429", 429 in codes, "429 after burst", f"codes={codes}",
        sev="P1", owner="core")
    # basic auth
    c, h, b, _ = curl(port=AUTH, path="/")
    rec("basic_auth 无凭据 → 401 + WWW-Authenticate", c == 401 and "www-authenticate" in h,
        "401 + WWW-Authenticate", f"{c} {h.get('www-authenticate')}", sev="P1", owner="core")
    c, h, b, _ = curl(port=AUTH, path="/", auth=ADMIN)
    rec("basic_auth 正确凭据 → 200", c == 200, 200, c, sev="P1", owner="core")
    c, h, b, _ = curl(port=AUTH, path="/", auth=("admin", "wrong"))
    rec("basic_auth 错误口令 → 401", c == 401, 401, c, sev="P1", owner="core")
    # ip_access（per-listener，规格 §16.1 要求；本实现疑似仅全局）
    c, h, b, _ = curl(port=IPACC, path="/")
    rec("per-listener ip_access allow=[10/8] 拒 127.0.0.1", c == 403,
        "403 forbidden", c, sev="P1", owner="core",
        repro=f"config [[listeners]] port=23093 [listeners.ip_access] allow=[10.0.0.0/8]; curl http://127.0.0.1:{IPACC}/")


# ───────────────────────── 重定向 / HSTS ─────────────────────────
def test_redirect_hsts():
    area("重定向 / HSTS (:23445 port_reuse)")
    # 明文打到「port_reuse 且无 TLS 兄弟」的 listener 才应 301 到 https（config-test 无此形态，
    # 23445 有 TLS 兄弟 → 明文请求非 301 属正常，跳过）。open-redirect 用 Host 探测。
    # HSTS 头
    c, h, b, _ = curl(port=TLS13, path="/", scheme="https")
    hsts = h.get("strict-transport-security")
    rec("TLS 响应带 HSTS", bool(hsts), "Strict-Transport-Security", hsts, sev="P2", owner="h1")
    if hsts:
        rec("HSTS 不含未要求的 includeSubDomains;preload", "includesubdomains" not in hsts.lower()
            or "preload" not in hsts.lower(), "无 includeSubDomains;preload", hsts,
            sev="P2", owner="h1")
    # open-redirect：//evil
    c, h, b, _ = curl(port=TLS12, path="/", scheme="http", headers=["Host: //evil.com"])
    loc = h.get("location", "")
    rec("301 不因 Host 变协议相对 open-redirect", not loc.startswith("//"),
        "Location 不以 // 开头", f"code={c} loc={loc}", sev="P0", owner="h1")


# ───────────────────────── 应用引擎 ─────────────────────────
ENGINES = [
    ("/php", "php", "PHP"),
    ("/c", "c", "C"),
    ("/go", "go", "Go"),
    ("/rust", "rust", "Rust"),
    ("/lua", "lua", "Lua"),
    ("/python", "python", "Python"),
    ("/ruby", "ruby", "Ruby"),
    ("/perl", "perl", "Perl"),
    ("/wsgi", "wsgi", "WSGI"),
    ("/asgi", "asgi", "ASGI"),
    ("/psgi", "psgi", "PSGI"),
    ("/rack", "rack", "Rack"),
    ("/cgi", "cgi", "CGI"),
    ("/uwsgi", "uwsgi", "uWSGI"),
    ("/tsx", "tsx", "TSX"),
    ("/asp", "asp", "ASP"),
    ("/aspnet", "aspnet", "ASP.NET"),
    ("/jsp", "jsp", "JSP"),
]


# 本机缺失的运行时 → 引擎不可用属环境限制（诚实 502），标 SKIP 并在报告注明
ENV_SKIP = {
    "php": "php-fpm/php-cgi 不在 PATH",
    "go": "无 libapp_go.so（缺 Go 工具链）",
    "rust": "无 libapp_rust.so",
    "python": "scriptffi 未带 CRUCIBLE_HAVE_PYTHON",
    "ruby": "无 libapp_ruby.so（缺 libruby）",
    "perl": "scriptffi 未带 CRUCIBLE_HAVE_PERL",
    "wsgi": "缺 libpython3.so",
    "asgi": "缺 libpython3.so",
    "psgi": "libapp_psgi.so 未嵌入 Perl",
    "rack": "libapp_rack.so 未嵌入 Ruby",
    "uwsgi": "缺 libpython3.so",
    "tsx": "无 TSX 转译器（缺 node/tsx）",
    "jsp": "jsp sidecar 未就绪（缺 java）",
}


def test_apps():
    area("应用引擎 (:23095)")
    for path, slug, label in ENGINES:
        c, h, b, _ = curl(port=APPS, path=path + "/", timeout=20)
        body = b.decode("latin1", "replace")
        if c == 200 and len(b) > 0:
            rec(f"引擎 {label} {path}/ → 200", True, 200, c, owner="apps")
        elif slug in ENV_SKIP:
            rec(f"引擎 {label} {path}/ → 环境不可用（SKIP）", True,
                f"env: {ENV_SKIP[slug]}", f"{c} {body[:50]}", skip=True, owner="apps")
        else:
            rec(f"引擎 {label} {path}/ → 200", False, 200, f"{c} {body[:70]!r}",
                sev="P1", owner="apps", repro=f"curl -s http://127.0.0.1:{APPS}{path}/")
    # /php/ h2 一致性（wave2 交接：/php/ 在 h2 恒 502）——两边状态码必须一致
    c1, _, b1, _ = curl(port=APPS, path="/php/", timeout=20)
    c2, _, b2, _ = curl(port=APPS, path="/php/", http2=True, timeout=20)
    rec("/php/ h1/h2 状态一致", c1 == c2, f"h1={c1} h2={c2}", f"h1={c1} h2={c2}",
        sev="P1", owner="apps")


# ───────────────────────── Admin API ─────────────────────────
def admin_req(method, sub, port=APPS, data=None, ct="application/json", auth=ADMIN, extra=None):
    cmd = ["curl", "-sS", "--max-time", "15", "-X", method,
           f"http://{HOST}:{port}/__admin{sub}", "-u", f"{auth[0]}:{auth[1]}",
           "-H", f"Origin: http://{HOST}:{port}",
           "-H", "X-Requested-With: accept-verify"]
    if data is not None:
        cmd += ["-H", f"Content-Type: {ct}", "--data-binary", data]
    for h in (extra or []):
        cmd += ["-H", h]
    p = subprocess.run(cmd, capture_output=True, timeout=20)
    return p.stdout.decode("latin1", "replace"), p.returncode


def test_admin():
    area("Admin API (:23095 /__admin)")
    # 无凭据
    p = subprocess.run(["curl", "-sS", "--max-time", "8", "-o", "/dev/null", "-w", "%{http_code}",
                        f"http://{HOST}:{APPS}/__admin/api/overview"], capture_output=True)
    rec("admin 无凭据 → 401", p.stdout.decode().strip() == "401", "401", p.stdout.decode().strip(),
        sev="P1", owner="admin")
    # 错误口令
    p = subprocess.run(["curl", "-sS", "--max-time", "8", "-o", "/dev/null", "-w", "%{http_code}",
                        "-u", "admin:wrong", f"http://{HOST}:{APPS}/__admin/api/overview"],
                       capture_output=True)
    rec("admin 错误口令 → 401", p.stdout.decode().strip() == "401", "401", p.stdout.decode().strip(),
        sev="P1", owner="admin")
    # 正确口令
    out, rc = admin_req("GET", "/api/overview")
    ok = '"listeners"' in out or '"version"' in out
    rec("admin 正确凭据 → JSON overview", ok, "JSON with listeners", out[:80], sev="P1", owner="admin")
    # CSRF：POST 无 Origin + 简单 content-type → 403
    #（application/json 属非简单请求，admin.rs 有意放行；必须用表单型简单请求探测）
    p = subprocess.run(["curl", "-sS", "--max-time", "8", "-o", "/dev/null", "-w", "%{http_code}",
                        "-u", "admin:admin", "-X", "POST",
                        "-H", "Content-Type: application/x-www-form-urlencoded",
                        "--data-binary", "a=b",
                        f"http://{HOST}:{APPS}/__admin/api/access_log/save"], capture_output=True)
    rec("admin POST 无 Origin(简单请求) → 403 (CSRF)", p.stdout.decode().strip() == "403", "403",
        p.stdout.decode().strip(), sev="P1", owner="admin")
    # 全链路：读 config/json → 保存 → 重载 → 复查
    out, _ = admin_req("GET", "/api/config/json")
    rec("admin GET /api/config/json 返回 JSON", out.strip().startswith("{"), "{...}", out[:60],
        sev="P1", owner="admin")
    out, _ = admin_req("GET", "/api/catalog")
    rec("admin GET /api/catalog 返回 JSON", out.strip().startswith("{") or out.strip().startswith("["),
        "JSON", out[:60], sev="P2", owner="admin")
    out, _ = admin_req("GET", "/api/logs")
    rec("admin GET /api/logs 可读", len(out) >= 0 and "error" not in out[:40].lower(), "logs",
        out[:60], sev="P2", owner="admin")
    # 空 extensions 保存回归（wave2 admin 项：空 extensions 变 [""]）
    out, _ = admin_req("GET", "/api/config/json")
    try:
        cfg = json.loads(out)
    except Exception:
        cfg = None
    if cfg:
        listeners = cfg.get("listeners") or []
        found_empty = False
        for l in listeners:
            for a in (l.get("apps") or []):
                if a.get("extensions") == [""]:
                    found_empty = True
        rec("面板 config/json 无 extensions=[''] 污染", not found_empty, "no ['']",
            "found" if found_empty else "ok", sev="P1", owner="admin")
    else:
        rec("面板 config/json 可解析", False, "JSON", out[:60], sev="P1", owner="admin")
    # geoip lookup
    out, _ = admin_req("GET", "/api/geoip/lookup?ip=1.2.4.8")
    rec("admin geoip lookup 非 501", "501" not in out[:20] and len(out) > 0,
        "JSON (非 501)", out[:80], sev="P1", owner="geoip")
    # UI 无 Cloudflare 字样
    p = subprocess.run(["curl", "-sS", "--max-time", "8", "-u", "admin:admin",
                        f"http://{HOST}:{APPS}/__admin/"], capture_output=True)
    html = p.stdout.decode("latin1", "replace")
    rec("Admin UI 无 Cloudflare 字样", "cloudflare" not in html.lower(), "no cloudflare",
        "found" if "cloudflare" in html.lower() else "ok", sev="P1", owner="admin")


# ───────────────────────── DNS 面板 / DoH ─────────────────────────
def test_dns():
    area("DNS 面板 API / DoH (:23095 /__admin/api/dns)")
    out, _ = admin_req("GET", "/api/dns/status")
    named_missing = '"named_running":false' in out.replace(" ", "")
    rec("dns status 可读", out.strip().startswith("{"), "JSON", out[:80], sev="P1", owner="dns")
    if named_missing:
        rec("named 未运行（本机缺 named）→ 面板其余检查 SKIP", True, "named present",
            "named MISSING", skip=True, owner="dns")
    # zones 列表
    out, _ = admin_req("GET", "/api/dns/zones")
    rec("dns zones 列表可读", out.strip().startswith("{") or out.strip().startswith("["),
        "JSON", out[:80], sev="P2", owner="dns")
    # 添加 zone（需 named 可 spawn；本机缺 named → SKIP）
    out, _ = admin_req("POST", "/api/dns/zones", data='{"action":"add","name":"accept.test","kind":"master"}')
    if named_missing or "named" in out.lower():
        rec("dns 添加 zone（需 named，环境跳过）", True, "ok", out[:70], skip=True, owner="dns")
    else:
        rec("dns 添加 zone", '"ok"' in out, "ok", out[:80], sev="P2", owner="dns")
    # DoH：明文 listener 上应拒绝（RFC 8484 MUST https）
    c, h, b, _ = curl(port=APPS, path="/dns-query?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB",
                      headers=["Accept: application/dns-message"])
    rec("DoH 明文 listener 被拒（RFC 8484 §5）", c in (400, 403, 404, 421, 426),
        "4xx（须 https）", c, sev="P1", owner="h1")
    # DoH host 白名单 fail-closed：白名单只含 crucible.local，用别的 Host 应拒
    c, h, b, _ = curl(port=DOH, path="/dns-query?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB",
                      scheme="https", headers=["Accept: application/dns-message",
                                               "Host: not-allowed.example"])
    rec("DoH 白名单外 Host 被拒", c in (400, 403, 404), "4xx", c, sev="P1", owner="dns")


def test_listeners():
    area("Listener 绑定 / 双栈 / H3 端点")
    log = "/home/dev123/scratch-verify/logs/webserver.log"
    try:
        txt = open(log, encoding="utf-8", errors="replace").read()
    except Exception:
        txt = ""
    bad_v6 = "有地址未能绑定" in txt
    rec("双栈 listener [::] 绑定不失败", not bad_v6, "无 '有地址未能绑定'",
        "EADDRINUSE [::] (IPV6_V6ONLY 未设)" if bad_v6 else "ok",
        "config [[listeners]] address_v6=\"::\" + address=\"0.0.0.0\"; 启动日志出现 '有地址未能绑定: bind [::]:PORT: Address already in use'",
        sev="P1", owner="core")
    # h3 UDP 端点（config 23443 http_versions 含 h3）
    try:
        p = subprocess.run(["ss", "-lun"], capture_output=True, timeout=5)
        udp = p.stdout.decode()
    except Exception:
        udp = ""
    h3_up = ":23443" in udp
    rec("h3/QUIC UDP 端点已绑定 (23443)", h3_up, "ss -lun 有 :23443",
        "bound" if h3_up else "no UDP socket",
        "config 23443 http_versions=[h1,h2,h3]; ss -lun | grep 23443",
        sev="P1", owner="h2h3")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", default="/home/dev123/scratch-verify/accept-results.json")
    args = ap.parse_args()

    # 先确认实例活着
    c, _, _, _ = curl(port=PLAIN, path="/")
    if c is None:
        print("FATAL: instance not up on 23081; run scripts/accept-verify-start.sh first")
        sys.exit(2)

    test_static()
    test_h2()
    test_tls()
    test_listeners()
    test_upload()
    test_adv()
    test_acl()
    test_redirect_hsts()
    test_apps()
    test_admin()
    test_dns()

    npass = sum(1 for r in RESULTS if r["status"] == "PASS")
    nfail = sum(1 for r in RESULTS if r["status"] == "FAIL")
    nskip = sum(1 for r in RESULTS if r["status"] == "SKIP")
    print(f"\n==== SUMMARY: PASS={npass} FAIL={nfail} SKIP={nskip} ====")
    fails = [r for r in RESULTS if r["status"] == "FAIL"]
    for r in sorted(fails, key=lambda x: x["severity"]):
        print(f"  [{r['severity']}] {r['area']} :: {r['name']} exp={r['expected']!r} obs={r['observed']!r}")

    with open(args.json, "w") as f:
        json.dump(RESULTS, f, indent=2, ensure_ascii=False)
    print(f"results -> {args.json}")
    sys.exit(1 if nfail else 0)


if __name__ == "__main__":
    main()
