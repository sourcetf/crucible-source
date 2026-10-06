#!/usr/bin/env python3
"""accept-verify-upstream.py — 验收用本机上游（反向代理 / WebSocket 测试）。

监听 127.0.0.1:23099（可用 argv[1] 覆盖）。
- GET/POST /proxy*  → 200，body 为收到的请求行 + 请求头（供检查请求头改写），
                      响应头带 X-Upstream: yes。
- GET /ws (Upgrade) → 101 Switching Protocols，之后把收到的字节原样回显（WS 隧道检查）。
- 其它             → 200 + 固定 body。
"""
import socket, sys, threading

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 23099
BIND = "127.0.0.1"


def handle(conn, addr):
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
        try:
            with open("/home/dev123/scratch-verify/logs/upstream-req.log", "a") as lf:
                lf.write(f"--- {method} {path} ws={is_ws}\n" + head.decode("latin1") + "\n")
        except Exception:
            pass
        if is_ws:
            key = headers.get("sec-websocket-key", "")
            import base64, hashlib
            acc = base64.b64encode(hashlib.sha1(
                (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
            conn.sendall(("HTTP/1.1 101 Switching Protocols\r\n"
                          "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                          f"Sec-WebSocket-Accept: {acc}\r\n\r\n").encode())
            # 之后回显（WS 隧道字节流验证）
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


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((BIND, PORT))
    s.listen(64)
    print(f"upstream listening on {BIND}:{PORT}", flush=True)
    while True:
        try:
            c, a = s.accept()
        except OSError:
            break
        threading.Thread(target=handle, args=(c, a), daemon=True).start()


if __name__ == "__main__":
    main()
