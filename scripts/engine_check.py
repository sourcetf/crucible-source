#!/usr/bin/env python3
"""App-engine smoke: 每条路由打一发，报告状态码 / X-Crucible-Engine / 正文首行。

用法（VM 上跑测试监听 19095）：
    python3 scripts/engine_check.py [base_url]

请求头跨语言并发验证（HTTP_* / scope["headers"] 是否串台）是独立脚本：
    sh scripts/engine_headers_check.sh
"""
import http.client
import sys

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:19095"
HOST = BASE.split("//", 1)[1].split("/")[0]
hn, _, port = HOST.partition(":")
PORT = int(port or 80)

# (path, engine-name-to-expect-in-header-or-body)
SMOKE = [
    ("/php/", "php"),
    ("/c/", "c"),
    ("/rust/", "rust"),
    ("/go/", "go"),
    ("/lua/", "lua"),
    ("/python/", "python"),
    ("/ruby/", "ruby"),
    ("/perl/", "perl"),
    ("/wsgi/", "wsgi"),
    ("/asgi/", "asgi"),
    ("/psgi/", "psgi"),
    # rack：预期 502 —— MRI/Rack 嵌入默认关闭（见 build_script_ffi.sh；头块验证另见
    # engine_headers_check.sh）。标 "502-ok" 表示这一项不算失败。
    ("/rack/", "502-ok"),
    ("/cgi/", "cgi"),
    ("/uwsgi/", "uwsgi"),
    ("/tsx/", "tsx"),
    ("/asp/", "asp"),
    ("/aspnet/", "aspnet"),
    ("/jsp/", "jsp"),
    ("/do/", "jsp"),
]

N = 120


def get(path, rid=None, timeout=60):
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=timeout)
    hdrs = {"Host": HOST}
    if rid:
        hdrs["X-Request-ID"] = rid
    try:
        c.request("GET", path, headers=hdrs)
        r = c.getresponse()
        body = r.read().decode("utf-8", "replace")
        return r.status, dict((k.lower(), v) for k, v in r.getheaders()), body
    finally:
        c.close()


def smoke():
    bad = 0
    for path, want in SMOKE:
        try:
            st, hd, body = get(path)
        except Exception as e:  # noqa: BLE001
            print(f"FAIL {path:10s} exception {e}")
            bad += 1
            continue
        eng = hd.get("x-crucible-engine", "")
        first = body.strip().splitlines()[0] if body.strip() else ""
        ok = st == 200 or (want == "502-ok" and st == 502)
        tag = "ok  " if ok else "BAD "
        if not ok:
            bad += 1
        print(f"{tag} {path:10s} status={st} engine={eng or '-':14s} body1={first[:60]!r}")
    return bad


def main():
    print(f"== app engine smoke ({BASE}) ==")
    bad = smoke()
    print(f"== summary: smoke_bad={bad} ==")
    print("tip: 请求头跨语言并发验证见 scripts/engine_headers_check.sh")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
