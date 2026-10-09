#!/usr/bin/env python3
"""accept-verify-upstream.py — 验收用本机上游（反向代理 / WebSocket 测试）。

监听 127.0.0.1:PORT（默认 29099，可用 argv[1] 覆盖）。同时起一个 TLS 监听在 PORT+1
（默认 29100），ALPN 广告 `h2,http/1.1` —— 用于验证代理回源「WS 到 h2 上游」时的
force_h1（即便上游广告 h2，也必须按 h1 讲话）。

- GET/POST /proxy*  → 200，body 为收到的请求行 + 请求头（供检查请求头改写），
                      响应头带 X-Upstream: yes。
- GET /ws (Upgrade) → 101 Switching Protocols，之后把收到的字节原样回显（WS 隧道检查）。
- 其它             → 200 + 固定 body。
"""
import socket, sys, threading, ssl, os, time

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 29099
TLSPORT = PORT + 1
BIND = "127.0.0.1"
REPO = "/home/dev123/crucible-git"
LOGDIR = "/home/dev123/scratch-verify4/logs"


def log_req(proto, head):
    try:
        os.makedirs(LOGDIR, exist_ok=True)
        with open(os.path.join(LOGDIR, "upstream-req.log"), "a") as lf:
            lf.write(f"--- {proto}\n" + head.decode("latin1") + "\n")
    except Exception:
        pass


def handle(conn, addr, proto="plain"):
    try:
        conn.settimeout(10)
        buf = b""
        while b"\r\n\r\n" not in buf:
            d = conn.recv(4096)
            if not d:
                return
            buf += d
        head, _, rest = buf.partition(b"\r\n\r\n")
        lines = head.decode("latin1").split("\r\n")
        reqline = lines[0]
        method, path = (reqline.split(" ") + ["", ""])[:2]
        headers = {}
        for ln in lines[1:]:
            if ":" in ln:
                k, v = ln.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        is_ws = headers.get("upgrade", "").lower() == "websocket"
        log_req(proto, head)
        if path.startswith("/slow"):
            # 慢上游：供 h3 GOAWAY 在飞请求测试（响应在 ~2s 后给出）。
            time.sleep(float(os.environ.get("UPSTREAM_SLOW_SECS", "2.0")))
            body = b"slow upstream ok\n"
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Upstream: yes\r\n"
                         + f"Content-Length: {len(body)}\r\n".encode()
                         + b"Connection: close\r\n\r\n" + body)
            return
        if is_ws:
            key = headers.get("sec-websocket-key", "")
            import base64, hashlib
            acc = base64.b64encode(hashlib.sha1(
                (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
            conn.sendall(("HTTP/1.1 101 Switching Protocols\r\n"
                          "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                          f"Sec-WebSocket-Accept: {acc}\r\n\r\n").encode())
            if rest:
                conn.sendall(rest)
            while True:
                d = conn.recv(4096)
                if not d:
                    break
                conn.sendall(d)
            return
        body_lines = [f"UPSTREAM_REQ {method} {path}"]
        for k in sorted(headers):
            body_lines.append(f"HDR {k}: {headers[k]}")
        body = ("\n".join(body_lines) + "\n").encode()
        resp = (b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/plain\r\n"
                b"X-Upstream: yes\r\n"
                + f"Content-Length: {len(body)}\r\n".encode()
                + b"Connection: close\r\n\r\n" + body)
        conn.sendall(resp)
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def serve_plain():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((BIND, PORT))
    s.listen(64)
    print(f"upstream plain listening on {BIND}:{PORT}", flush=True)
    while True:
        try:
            c, a = s.accept()
        except OSError:
            break
        threading.Thread(target=handle, args=(c, a, "plain"), daemon=True).start()


def serve_tls():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(os.path.join(REPO, "cert.pem"), os.path.join(REPO, "key.pem"))
    try:
        ctx.set_alpn_protocols(["h2", "http/1.1"])
    except Exception as e:
        print(f"ALPN set failed: {e}", flush=True)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((BIND, TLSPORT))
    s.listen(64)
    print(f"upstream TLS listening on {BIND}:{TLSPORT} (alpn h2,http/1.1)", flush=True)
    while True:
        try:
            c, a = s.accept()
        except OSError:
            break
        try:
            tc = ctx.wrap_socket(c, server_side=True)
        except Exception:
            try:
                c.close()
            except Exception:
                pass
            continue
        threading.Thread(target=handle, args=(tc, a, "tls"), daemon=True).start()


def main():
    threading.Thread(target=serve_tls, daemon=True).start()
    serve_plain()


if __name__ == "__main__":
    main()
