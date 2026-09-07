#!/usr/bin/env python3
"""§B.3 GeoIP 出站 HTTP（默认走 Tor/SOCKS；查询路径零网络）。

- http_get(url, prefer_tor=True, tor_socks=…, tor_circuit=…, tor_only=False)
  tor_circuit：SOCKS5 用户名做 stream isolation（Tor 默认 IsolateSOCKSAuth →
  不同用户名不同电路）。
- rdap_get_json(url, …)：RDAP JSON（prefer_tor=True），429/403 由调用方处理。
- http_download(url, …)：大文件默认 prefer_tor=False。
- fetch(url, use_tor=…)：旧接口保留（兼容旧调用方）。
"""
from __future__ import annotations

import os
import socket
import ssl
import urllib.error
import urllib.request
from typing import Iterable
from urllib.parse import urlparse

from geoip_tor_pool import tor_newnym_port, tor_socks_endpoints_fallback


def _socks5_connect(host: str, port: int, proxy: tuple[str, int],
                    username: str | None = None) -> socket.socket:
    """SOCKS5 CONNECT：传主机名不做本地 DNS（.onion 必须）。
    username 非空时走用户名/密码认证——Tor IsolateSOCKSAuth 使不同用户名
    使用不同电路（stream isolation）。"""
    s = socket.create_connection(proxy, timeout=60)
    if username:
        s.sendall(b"\x05\x01\x02")
    else:
        s.sendall(b"\x05\x01\x00")
    resp = s.recv(2)
    if len(resp) < 2 or resp[0] != 5:
        raise OSError(f"socks5 greet failed: {resp!r}")
    if resp[1] == 2:  # 需要用户名/密码（我们主动提供了）
        u = username.encode("utf-8") if username else b""
        s.sendall(b"\x01" + bytes([len(u)]) + u + b"\x00")
        resp = s.recv(2)
        if len(resp) < 2 or resp[1] != 0:
            raise OSError(f"socks5 auth failed: {resp!r}")
    elif resp[1] != 0:
        raise OSError(f"socks5 no-auth rejected: {resp!r}")
    host_b = host.encode("utf-8")
    req = b"\x05\x01\x00\x03" + bytes([len(host_b)]) + host_b + port.to_bytes(2, "big")
    s.sendall(req)
    head = s.recv(4)
    if len(head) < 4 or head[1] != 0:
        raise OSError(f"socks5 connect failed: {head!r}")
    atyp = head[3]
    if atyp == 0x01:
        s.recv(6)
    elif atyp == 0x03:
        ln = s.recv(1)[0]
        s.recv(ln + 2)
    elif atyp == 0x04:
        s.recv(18)
    return s


def tor_socks_endpoints() -> Iterable[tuple[str, int]]:
    pool = os.environ.get("GEOIP_TOR_SOCKS", "")
    if pool:
        for item in pool.split(","):
            item = item.strip()
            if not item:
                continue
            host, _, port_s = item.partition(":")
            yield host, int(port_s or "9050")
    else:
        yield "127.0.0.1", 9050


def tor_socks_endpoints_fallback() -> Iterable[tuple[str, int]]:
    return tor_socks_endpoints()


def _fetch_via_socks(url: str, proxy: tuple[str, int],
                     username: str | None = None, timeout: int = 120) -> bytes:
    u = urlparse(url)
    s = _socks5_connect(u.hostname, u.port or (443 if u.scheme == "https" else 80),
                        proxy, username=username)
    if u.scheme == "https":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # RDAP 源证书链经 Tor 出口校验受限
        ss = ctx.wrap_socket(s, server_hostname=u.hostname)
        req = (f"GET {u.path or '/'} HTTP/1.1\r\nHost: {u.hostname}\r\n"
               f"User-Agent: crucible-geoip/1.0\r\nConnection: close\r\n\r\n")
        ss.sendall(req.encode())
        buf = b""
        while True:
            chunk = ss.recv(65536)
            if not chunk:
                break
            buf += chunk
        ss.close()
        body = buf.partition(b"\r\n\r\n")[2]
    else:
        ss = s
        req = (f"GET {u.path or '/'} HTTP/1.1\r\nHost: {u.hostname}\r\n"
               f"User-Agent: crucible-geoip/1.0\r\nConnection: close\r\n\r\n")
        ss.sendall(req.encode())
        buf = b""
        while True:
            chunk = ss.recv(65536)
            if not chunk:
                break
            buf += chunk
        ss.close()
        body = buf.partition(b"\r\n\r\n")[2]
    head_end = buf.find(b"\r\n\r\n")
    status = buf.split(b"\r\n")[0].decode("utf-8", errors="replace")
    if " 200 " not in status + " ":
        code = status.split(" ")[1] if " " in status else "?"
        raise RuntimeError(f"http {code}")
    del head_end
    return body


def http_get(url: str, *, prefer_tor: bool = True,
             tor_socks: str | None = None,
             tor_circuit: str | None = None,
             tor_only: bool = False,
             timeout: int = 120) -> bytes:
    """§B.3 出站 HTTP：默认 Tor；tor_socks 指定池内实例；
    tor_circuit = stream isolation 用户名；429/403 → NEWNYM（该实例）。"""
    if prefer_tor:
        proxies: list[tuple[str, int]] = []
        if tor_socks:
            host, _, port_s = tor_socks.partition(":")
            proxies.append((host, int(port_s or "9050")))
        else:
            proxies = list(tor_socks_endpoints())
        last: Exception | None = None
        for proxy in proxies:
            try:
                return _fetch_via_socks(url, proxy, username=tor_circuit,
                                        timeout=timeout)
            except RuntimeError as exc:
                last = exc
                msg = str(exc)
                if "429" in msg or "403" in msg:
                    # 限流：对该实例 NEWNYM（每口 ControlPort）
                    tor_newnym_port(f"{proxy[0]}:{proxy[1]}")
                continue
            except OSError as exc:
                last = exc
                continue
        if tor_only:
            raise last or OSError("tor fetch failed")
        print(f"warn: tor path failed ({last}); fall back to direct",
              file=sys.stderr)
    with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "crucible-geoip/1.0"}),
                                timeout=timeout) as resp:
        return resp.read()


# 兼容别名（netorg 旧调用）
fetch_via_tor_tor = http_get


def rdap_get_json(url: str, **kw) -> dict:
    import json
    return json.loads(http_get(url, prefer_tor=True, **kw).decode("utf-8", errors="replace"))


def http_download(url: str, dest: str, **kw) -> str:
    kw.setdefault("prefer_tor", False)
    data = http_get(url, **kw)
    Path(dest).write_bytes(data)
    return dest


from pathlib import Path  # noqa: E402  (http_download 使用)


def fetch(url: str, *, timeout: int = 120, use_tor: bool = False) -> bytes:
    """旧接口兼容：fetch(url, use_tor=True) → http_get(tor_only=True)。"""
    return http_get(url, prefer_tor=use_tor, tor_only=use_tor, timeout=timeout)
