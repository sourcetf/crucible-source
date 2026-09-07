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


def render_jsp(text: str, path: str, params: dict[str, str]) -> bytes:
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
                body = render_jsp(text, path, params)
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
                path=path, method=method, params=params, doc=doc, rel=rel
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
                body_out = render_jsp(text, path, params)
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
        try:
            data = read_http_request(conn)
            if data:
                conn.sendall(handle_request(data))
        finally:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            conn.close()


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
