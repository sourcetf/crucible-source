#!/usr/bin/env python3
"""Jetty-style JSP sidecar — HTTP/1.1 over Unix domain socket.

Protocol (UDS HTTP-ish):
  Request:  standard HTTP/1.1 request line + headers + optional body
  Response: HTTP/1.1 status + Content-Type/Length + body

Serves real .jsp/.jspx files from JSP_DOCROOT with a minimal translator:
  <%= expr %>          → print expression (string literal / request attrs)
  <% out.println(..) %> → captured text
  <%! ... %> / <%@ ... %> ignored (declarations / directives)
  request.getParameter  → query string / form lookup

ActionBridge (paths ending in .do / .action):
  Forwards CGI-like params (query + application/x-www-form-urlencoded body)
  to a simple handler; companion .jsp with <%= %> still renders when present.

Optional Jetty/Jasper path: see java/ (Maven fat JAR). Not required for UDS
smoke tests — Python sidecar is the default on OpenBSD.
"""
from __future__ import annotations

import argparse
import os
import re
import socket
import sys
import urllib.parse
from pathlib import Path


def _query_params(raw_path: str) -> dict[str, str]:
    if "?" not in raw_path:
        return {}
    qs = raw_path.split("?", 1)[1]
    return {k: (v[0] if v else "") for k, v in urllib.parse.parse_qs(qs, keep_blank_values=True).items()}


def _form_params(body: bytes, content_type: str) -> dict[str, str]:
    ct = (content_type or "").split(";", 1)[0].strip().lower()
    if ct and ct != "application/x-www-form-urlencoded":
        return {}
    if not body:
        return {}
    try:
        text = body.decode("utf-8", errors="replace")
    except Exception:
        return {}
    return {k: (v[0] if v else "") for k, v in urllib.parse.parse_qs(text, keep_blank_values=True).items()}


def _safe_under(doc: Path, rel: str) -> Path | None:
    try:
        # Reject path escape
        if ".." in Path(rel).parts:
            return None
        target = (doc / rel).resolve()
        doc_r = doc.resolve()
        if os.path.commonpath([str(doc_r), str(target)]) != str(doc_r):
            return None
        return target
    except (OSError, ValueError):
        return None


# ---------------------------------------------------------------------------
# `.env` 注入（与 Java 侧 EnvInjectionFilter 同一套语义）
# ---------------------------------------------------------------------------
#
# 宿主侧两条通道（src/server/apps/sidecar_engine.rs::env_forward_headers）：
#   ① 受管 sidecar（deps/bin/index，本文件在 OpenBSD/默认 demo 下走这条）：宿主把
#      **本 app 的 .env** 放进 spawn env ⇒ 进程环境里可见（os.environ；Java 侧 System.getenv）。
#   ② 显式 apps[].socket（运维自己起的进程）：宿主够不着它的进程 env，改为按请求转发
#      `x-crucible-env-<key 小写>` 头（percent-encoded 值）⇒ 变成 **request attribute**。
#      宿主转发前会剥掉客户端自带的同名头 ⇒ 该通道无法被外部注入。
# 为什么是 attribute 而不是全局 setenv：属性**每请求**独立、请求结束即消失；全局变量会被
# 后一个请求覆盖且残留 ⇒ 跨请求/跨应用串味（apps5b 的结论）。
ENV_HEADER_PREFIX = "x-crucible-env-"
ENV_ATTR_PREFIX = "crucible.env."
ENV_ATTR_MAP = "crucible.env"
ENV_MAX_KEYS = 64
ENV_MAX_KEY_LEN = 128
ENV_MAX_VALUE_LEN = 8192
ENV_MAX_TOTAL_BYTES = 16 * 1024


def extract_env_attributes(hdrs: dict[str, str]) -> dict[str, str]:
    """`x-crucible-env-*` 头 → request attribute 表（键 = 去掉前缀的**小写**形态）。

    与 Java `EnvInjectionFilter` 逐条等价：值 percent-decode（UTF-8；非法转义按字面保留；
    **不**把 `+` 当空格 —— RFC 3986，不是表单编码）；空值不注入（= 该键不存在）；上限
    64 键 / 单值 8KiB / 合计 16KiB（与宿主侧同量级，纵深防御）。
    `hdrs` 的键必须是已小写化的头名（见 `_parse_headers`）。
    """
    out: dict[str, str] = {}
    total = 0
    for name, value in hdrs.items():
        if len(out) >= ENV_MAX_KEYS:
            break
        lower = name.lower()
        if not lower.startswith(ENV_HEADER_PREFIX):
            continue
        key = lower[len(ENV_HEADER_PREFIX):]
        if (
            not key
            or len(key) > ENV_MAX_KEY_LEN
            or key in out
            or not all(c.isascii() and (c.isalnum() or c == "_") for c in key)
        ):
            continue
        val = urllib.parse.unquote(value, encoding="utf-8", errors="replace")
        if not val or len(val) > ENV_MAX_VALUE_LEN:
            continue
        if total + len(key) + len(val) > ENV_MAX_TOTAL_BYTES:
            break
        total += len(key) + len(val)
        out[key] = val
    return out


def render_jsp(
    text: str,
    path: str,
    params: dict[str, str],
    env_attrs: dict[str, str] | None = None,
) -> bytes:
    env_attrs = env_attrs or {}
    out: list[str] = []
    i = 0
    while i < len(text):
        if text.startswith("<%", i):
            # directives / declarations
            if text.startswith("<%@", i) or text.startswith("<%!", i):
                end = text.find("%>", i + 3)
                if end == -1:
                    break
                i = end + 2
                continue
            end = text.find("%>", i + 2)
            if end == -1:
                break
            block = text[i + 2 : end].strip()
            i = end + 2
            if block.startswith("="):
                expr = block[1:].strip()
                # request.getParameter("x")
                m = re.search(
                    r'request\.getParameter\s*\(\s*["\']([^"\']+)["\']\s*\)',
                    expr,
                    re.I,
                )
                if m:
                    out.append(params.get(m.group(1), ""))
                    continue
                # request.getAttribute("crucible.env.<key>") —— 显式 socket 的 .env 通道
                # （宿主转发头 → EnvInjectionFilter/extract_env_attributes 注入的属性）。
                m = re.search(
                    r'request\.getAttribute\s*\(\s*["\']([^"\']+)["\']\s*\)',
                    expr,
                    re.I,
                )
                if m:
                    name = m.group(1)
                    if name == ENV_ATTR_MAP:
                        out.append("")
                    elif name.startswith(ENV_ATTR_PREFIX):
                        out.append(env_attrs.get(name[len(ENV_ATTR_PREFIX):], ""))
                    else:
                        out.append("")
                    continue
                # System.getenv("KEY") —— 受管 sidecar 的 spawn env 通道（进程环境）。
                m = re.search(
                    r'System\.getenv\s*\(\s*["\']([^"\']+)["\']\s*\)',
                    expr,
                    re.I,
                )
                if m:
                    out.append(os.environ.get(m.group(1), ""))
                    continue
                # string literal
                if (expr.startswith('"') and expr.endswith('"')) or (
                    expr.startswith("'") and expr.endswith("'")
                ):
                    out.append(expr[1:-1])
                    continue
                out.append(expr.strip('"').strip("'"))
                continue
            m = re.search(
                r'out\.(?:println|print)\s*\(\s*"((?:\\.|[^"\\])*)"\s*\)',
                block,
            )
            if m:
                out.append(bytes(m.group(1), "utf-8").decode("unicode_escape"))
                if "println" in block:
                    out.append("\n")
                continue
            # out.println(request.getParameter(...))
            m2 = re.search(
                r'out\.(?:println|print)\s*\(\s*request\.getParameter\s*\(\s*["\']([^"\']+)["\']\s*\)\s*\)',
                block,
                re.I,
            )
            if m2:
                out.append(params.get(m2.group(1), ""))
                if "println" in block:
                    out.append("\n")
                continue
            continue
        out.append(text[i])
        i += 1
    body = "".join(out)
    if not body.strip():
        body = f"hello from jsp sidecar path={path}\n"
    return body.encode("utf-8")


class ActionBridge:
    """Forward Struts-like .do/.action requests as CGI params to a simple handler.

    Looks for a companion .jsp (same basename) and renders <%= %> with merged
    query+form params. If no JSP exists, returns a CGI-style plain response so
    smoke tests still pass. Full Jetty embedding remains optional (see java/).
    """

    SUFFIXES = (".do", ".action")

    @classmethod
    def matches(cls, path: str) -> bool:
        lower = path.lower().split("?", 1)[0]
        return any(lower.endswith(s) for s in cls.SUFFIXES)

    @staticmethod
    def _basename(path: str) -> str:
        name = path.rsplit("/", 1)[-1]
        for suf in ActionBridge.SUFFIXES:
            if name.lower().endswith(suf):
                return name[: -len(suf)]
        return name

    def handle(
        self,
        *,
        path: str,
        method: str,
        params: dict[str, str],
        doc: Path,
        rel: str,
        env_attrs: dict[str, str] | None = None,
    ) -> tuple[bytes, bytes, bytes]:
        """Return (status, content_type, body)."""
        base = self._basename(rel or path)
        candidates = [
            f"{base}.jsp",
            f"{base}.jspx",
            f"{base}_action.jsp",
            "action.jsp",
        ]
        # Preserve directory prefix of the .do path.
        parent = str(Path(rel).parent).replace("\\", "/")
        if parent in (".", ""):
            parent = ""
        for cand in candidates:
            rel_jsp = f"{parent}/{cand}".lstrip("/") if parent else cand
            jsp = _safe_under(doc, rel_jsp)
            if jsp and jsp.is_file():
                text = jsp.read_text(encoding="utf-8", errors="replace")
                body = render_jsp(text, path, params, env_attrs)
                return (
                    b"200 OK",
                    b"text/html; charset=utf-8",
                    body,
                )
        # Simple CGI-like handler when no companion JSP exists.
        lines = [
            f"ActionBridge ok method={method} path={path}",
            f"action={base}",
        ]
        for k in sorted(params):
            lines.append(f"{k}={params[k]}")
        if not params:
            lines.append("(no cgi params)")
        body = ("\n".join(lines) + "\n").encode("utf-8")
        return (b"200 OK", b"text/plain; charset=utf-8", body)


def read_http_request(conn: socket.socket, limit: int = 262144) -> bytes:
    data = b""
    while b"\r\n\r\n" not in data and len(data) < limit:
        chunk = conn.recv(4096)
        if not chunk:
            break
        data += chunk
    if b"\r\n\r\n" not in data:
        return data
    head, _, rest = data.partition(b"\r\n\r\n")
    cl = 0
    for line in head.split(b"\r\n")[1:]:
        if line.lower().startswith(b"content-length:"):
            try:
                cl = int(line.split(b":", 1)[1].strip())
            except ValueError:
                cl = 0
    while len(rest) < cl and len(data) < limit:
        chunk = conn.recv(min(4096, cl - len(rest)))
        if not chunk:
            break
        rest += chunk
        data = head + b"\r\n\r\n" + rest
    return data


def _parse_headers(head_lines: list[str]) -> dict[str, str]:
    hdrs: dict[str, str] = {}
    for line in head_lines[1:]:
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        hdrs[k.strip().lower()] = v.strip()
    return hdrs


def handle_request(raw: bytes) -> bytes:
    try:
        head, _, body_raw = raw.partition(b"\r\n\r\n")
        lines = head.decode("utf-8", errors="replace").split("\r\n")
        method_path = lines[0] if lines else "GET / HTTP/1.1"
        parts = method_path.split()
        method = parts[0] if parts else "GET"
        raw_path = parts[1] if len(parts) > 1 else "/"
        hdrs = _parse_headers(lines)
        # `.env` 请求头通道 → request attribute（显式 socket 场景；受管 sidecar 的 .env
        # 走 spawn env，环境变量里已可见）。见 extract_env_attributes 的说明。
        env_attrs = extract_env_attributes(hdrs)
        params = _query_params(raw_path)
        form = _form_params(body_raw, hdrs.get("content-type", ""))
        # Form body overrides query on key clash (CGI-ish).
        params = {**params, **form}
        path = raw_path.split("?", 1)[0]
        doc = Path(os.environ.get("JSP_DOCROOT", ".")).resolve()
        rel = path.lstrip("/")
        for prefix in ("jsp/", "do/", "action/"):
            if rel.startswith(prefix):
                rel = rel[len(prefix) :]

        if ActionBridge.matches(path) or ActionBridge.matches(rel):
            status, ctype, body_out = ActionBridge().handle(
                path=path,
                method=method,
                params=params,
                doc=doc,
                rel=rel,
                env_attrs=env_attrs,
            )
            engine = b"jsp-actionbridge"
        else:
            if not rel or rel.endswith("/"):
                rel = (rel + "index.jsp").lstrip("/")
            jsp = _safe_under(doc, rel)
            if jsp is None or not jsp.is_file():
                jsp = _safe_under(doc, "index.jsp")
            if jsp and jsp.is_file() and jsp.suffix.lower() in (".jsp", ".jspx"):
                text = jsp.read_text(encoding="utf-8", errors="replace")
                body_out = render_jsp(text, path, params, env_attrs)
                ctype = b"text/html; charset=utf-8"
                status = b"200 OK"
                engine = b"jsp-sidecar"
            elif jsp and jsp.is_file():
                body_out = jsp.read_bytes()
                ctype = b"application/octet-stream"
                status = b"200 OK"
                engine = b"jsp-sidecar"
            else:
                msg = f"jsp not found under docroot path={path}\n".encode()
                return (
                    b"HTTP/1.1 404 Not Found\r\n"
                    b"Content-Type: text/plain; charset=utf-8\r\n"
                    + f"Content-Length: {len(msg)}\r\n".encode()
                    + b"Connection: close\r\n\r\n"
                    + msg
                )
        hdr = (
            b"HTTP/1.1 "
            + status
            + b"\r\nContent-Type: "
            + ctype
            + b"\r\n"
            + f"Content-Length: {len(body_out)}\r\n".encode()
            + b"Connection: close\r\n"
            + b"X-Crucible-Engine: "
            + engine
            + b"\r\n"
            + b"\r\n"
        )
        return hdr + body_out
    except Exception as e:
        msg = f"jsp sidecar error: {e}\n".encode()
        return (
            b"HTTP/1.1 500 Internal Server Error\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            + f"Content-Length: {len(msg)}\r\n".encode()
            + b"Connection: close\r\n\r\n"
            + msg
        )


def serve(sock_path: str) -> None:
    Path(sock_path).parent.mkdir(parents=True, exist_ok=True)
    if os.path.exists(sock_path):
        os.unlink(sock_path)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(sock_path)
    os.chmod(sock_path, 0o600)
    srv.listen(32)
    sys.stderr.write(
        f"jsp sidecar listening on {sock_path} docroot={os.environ.get('JSP_DOCROOT')}\n"
    )
    sys.stderr.flush()
    while True:
        conn, _ = srv.accept()
        # **单连接异常绝不允许打死 sidecar**：本进程是长驻的，宿主对显式 socket 的
        # sidecar 没有重启权（那是运维的进程）—— 客户端提前断开（EPIPE/ECONNRESET，
        # 例如宿主代理侧超时后关闭）会从 `sendall` 抛出，旧实现会让整个 listener
        # 退出（socket 文件还在但 connect 被拒 ⇒ 该应用之后**永久 502**，只有人工重启）。
        # accept 本身（不会因连接异常抛出）留在 try 外：真出错（EMFILE 等）应快速失败。
        try:
            _serve_one(conn)
        except Exception as e:  # noqa: BLE001 —— 长驻进程的兜底
            try:
                sys.stderr.write(f"jsp sidecar: connection error (kept serving): {e!r}\n")
                sys.stderr.flush()
            except OSError:
                pass
        finally:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                conn.close()
            except OSError:
                pass


def _serve_one(conn: socket.socket) -> None:
    """处理一条连接（异常由 [`serve`] 兜住，不影响后续连接）。"""
    data = read_http_request(conn)
    if data:
        conn.sendall(handle_request(data))


def main() -> int:
    ap = argparse.ArgumentParser(description="Crucible JSP UDS HTTP sidecar")
    ap.add_argument("--socket", "-s", required=True, help="Unix socket path")
    ap.add_argument("--docroot", "-d", default=".", help="JSP document root")
    args = ap.parse_args()
    os.environ["JSP_DOCROOT"] = os.path.abspath(args.docroot)
    serve(os.path.abspath(args.socket))
    return 0


if __name__ == "__main__":
    sys.exit(main())
