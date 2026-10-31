#!/usr/bin/env python3
"""interop_h3_quiche.py — U-11: drive our HTTP/3 listener with a *third-party*
client (Cloudflare quiche's ``quiche-client``) and check protocol conformance.

Why this is real interoperability evidence
------------------------------------------
The server is Rust/quinn + the Rust ``h3`` crate over BoringSSL.  ``quiche`` is
Cloudflare's independent QUIC + HTTP/3 + QPACK stack (also BoringSSL-based).  A
successful run means our wire encoding (SETTINGS, frames, QPACK, GOAWAY, stream
flow control) is understood by a completely separate implementation — not just
by aioquic, which was the only client used before U-11.

``quiche-client`` has no MASQUE / CONNECT-UDP support (its ``--dgram-proto`` is
Cloudflare's own one-way DATAGRAM test proto), so CONNECT-UDP is exercised by
``interop_h3_udp.py`` (aioquic) and only the plain HTTP/3 surface is driven
here.

Usage (normally called by ``scripts/h3_interop_check.sh``):
    python3 scripts/interop_h3_quiche.py --client /path/to/quiche-client \
        --port 27143 --www <docroot> --up <upload-root> --cert <pem> [--json out.json]
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time


def sha256_file(path):
    if not os.path.exists(path):
        return None
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class Suite:
    def __init__(self, client, port):
        self.client = client
        self.base = f"https://127.0.0.1:{port}"
        self.records = []

    def rec(self, name, ok, detail):
        self.records.append({"name": name, "status": "PASS" if ok else "FAIL",
                             "detail": str(detail)})
        print(f"[{'PASS' if ok else 'FAIL'}] {name}: {detail}", flush=True)

    # ── low level ────────────────────────────────────────────────────────────
    def run(self, args, timeout=90, env_extra=None):
        env = dict(os.environ)
        env.setdefault("RUST_LOG", "info")
        if env_extra:
            env.update(env_extra)
        p = subprocess.run([self.client, "--no-verify", "--http-version", "HTTP/3"] + args,
                           capture_output=True, timeout=timeout, env=env)
        return p

    def fetch(self, path, method="GET", headers=(), body=None, wire_version=None,
              timeout=90, dump_body=True):
        """GET/POST/etc one URL; returns (status, headers dict, body_sha, body_len,
        proc).

        quiche-client's ``--dump-responses`` derives the output filename from the
        URL's last path segment and *panics* when that is empty (URL ending in
        ``/``).  In that case the body is taken from ``--dump-json`` instead
        (which embeds the payload bytes as a JSON array)."""
        d = tempfile.mkdtemp(prefix="qh3resp-")
        try:
            last = path.rstrip("/").rsplit("/", 1)[-1]
            use_dump = dump_body and last != ""
            args = ["--dump-json"]
            if use_dump:
                args += ["--dump-responses", d]
            if method != "GET":
                args += ["--method", method]
            if wire_version:
                args += ["--wire-version", str(wire_version)]
            if body is not None:
                args += ["--body", body]
            for hv in headers:
                args += ["-H", hv]
            args.append(self.base + path)
            p = self.run(args, timeout=timeout)
            status, hdrs = None, {}
            json_body = None
            try:
                js = json.loads(p.stdout.decode("utf-8", "replace"))
                ent = (js.get("entries") or [{}])[0]
                for h in ent.get("response", {}).get("headers", []):
                    if h.get("name") == ":status":
                        status = int(h.get("value"))
                    else:
                        hdrs[h["name"]] = h.get("value")
                jb = ent.get("response", {}).get("body")
                if isinstance(jb, list):
                    json_body = bytes(jb)
            except Exception:
                pass
            if use_dump:
                files = [os.path.join(d, f) for f in os.listdir(d)]
                body_len = sum(os.path.getsize(f) for f in files)
                body_sha = sha256_file(files[0]) if len(files) == 1 else None
            elif json_body is not None:
                body_len = len(json_body)
                body_sha = hashlib.sha256(json_body).hexdigest()
            else:
                body_len, body_sha = 0, None
            return status, hdrs, body_sha, body_len, p
        finally:
            shutil.rmtree(d, ignore_errors=True)

    # ── checks ───────────────────────────────────────────────────────────────
    def run_all(self, www, up, cert):
        idx_sha = sha256_file(os.path.join(www, "index.html"))
        blob1_sha = sha256_file(os.path.join(www, "blob-1m.bin"))
        blob8_sha = sha256_file(os.path.join(www, "blob-8m.bin"))

        # K1: GET / -> 200, body identical
        st, h, bsha, blen, p = self.fetch("/")
        self.rec("K1 GET / -> 200 + body identical", st == 200 and bsha == idx_sha,
                 f"status={st} bytes={blen} sha_ok={bsha == idx_sha}")

        # K2: 1 MiB framing + integrity
        st, h, bsha, blen, p = self.fetch("/blob-1m.bin")
        self.rec("K2 GET 1MiB -> 200, sha256 identical",
                 st == 200 and blen == 1048576 and bsha == blob1_sha,
                 f"status={st} bytes={blen} sha_ok={bsha == blob1_sha}")

        # K3: 8 MiB framing + flow control
        st, h, bsha, blen, p = self.fetch("/blob-8m.bin", timeout=120)
        self.rec("K3 GET 8MiB -> 200, sha256 identical",
                 st == 200 and blen == 8388608 and bsha == blob8_sha,
                 f"status={st} bytes={blen} sha_ok={bsha == blob8_sha}")

        # K4/K5: request body framing — PUT and POST 2 MiB uploads, disk sha must match
        payload = os.path.abspath(up)
        psha = sha256_file(payload)
        disk = os.path.join(www, "up", "quiche-put-2m.bin")
        if os.path.exists(disk):
            os.unlink(disk)
        st, h, bsha, blen, p = self.fetch("/up/quiche-put-2m.bin", method="PUT", body=payload)
        self.rec("K4 PUT 2MiB body -> 201, on-disk sha256 identical",
                 st == 201 and sha256_file(disk) == psha,
                 f"status={st} disk_sha_ok={sha256_file(disk) == psha}")
        disk = os.path.join(www, "up", "quiche-post-2m.bin")
        if os.path.exists(disk):
            os.unlink(disk)
        st, h, bsha, blen, p = self.fetch("/up/quiche-post-2m.bin", method="POST", body=payload)
        self.rec("K5 POST 2MiB body -> 201, on-disk sha256 identical",
                 st == 201 and sha256_file(disk) == psha,
                 f"status={st} disk_sha_ok={sha256_file(disk) == psha}")

        # K6: 404
        st, h, bsha, blen, p = self.fetch("/definitely-not-here-xyz")
        self.rec("K6 GET missing -> 404", st == 404, f"status={st}")

        # K7: directory without trailing slash -> 301 + location
        st, h, bsha, blen, p = self.fetch("/up")
        self.rec("K7 GET /up (dir) -> 301 + location", st == 301 and h.get("location") == "/up/",
                 f"status={st} location={h.get('location')}")

        # K8: Range -> 206 + content-range
        st, h, bsha, blen, p = self.fetch("/blob-1m.bin", headers=["range: bytes=0-9"])
        self.rec("K8 Range bytes=0-9 -> 206 + content-range",
                 st == 206 and (h.get("content-range") or "").startswith("bytes 0-9/"),
                 f"status={st} content-range={h.get('content-range')}")

        # K9: HEAD -> 200, no body
        st, h, bsha, blen, p = self.fetch("/blob-1m.bin", method="HEAD")
        self.rec("K9 HEAD -> 200, zero body", st == 200 and blen == 0,
                 f"status={st} body_bytes={blen}")

        # K10: CONNECT without :protocol -> 501
        st, h, bsha, blen, p = self.fetch("/", method="CONNECT")
        self.rec("K10 CONNECT (no :protocol) -> 501", st == 501, f"status={st}")

        # K11: connection-specific field (te: gzip) -> H3_MESSAGE_ERROR(0x10e) RST
        st, h, bsha, blen, p = self.fetch("/", headers=["te: gzip"])
        err = p.stderr.decode("utf-8", "replace")
        reset = "reset by peer with 270" in err or "0x10e" in err.lower()
        self.rec("K11 te: gzip -> stream reset H3_MESSAGE_ERROR(270)", reset,
                 f"rc={p.returncode} reset_seen={reset}")

        # K12: 50 pipelined requests on one connection
        p = self.run(["-n", "50", self.base + "/blob-1m.bin"], timeout=120)
        got = "50/50 response(s) received" in p.stderr.decode("utf-8", "replace")
        self.rec("K12 50 pipelined GET (multiplexing) -> 50/50", got,
                 "50/50 received" if got else "incomplete")

        # K13: force QUIC v1 (default client wire-version is a greasing value)
        st, h, bsha, blen, p = self.fetch("/", wire_version=1)
        self.rec("K13 QUIC v1 (--wire-version 1) -> 200", st == 200, f"status={st}")

        # K14: H3 GOAWAY on config/cert change while requests are in flight
        self.check_goaway(cert)

    def check_goaway(self, cert):
        """Start a long burst, mutate the certificate file (triggers the server's
        config fingerprint watcher -> H3 GOAWAY), and require the independent
        client to parse GOAWAY from the control stream."""
        p = subprocess.Popen([self.client, "--no-verify", "--http-version", "HTTP/3",
                              "-n", "3000", self.base + "/blob-1m.bin"],
                             stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                             env={**os.environ, "RUST_LOG": "info"})
        time.sleep(2.0)
        now = time.time()
        try:
            os.utime(cert, (now, now))
        except OSError as e:
            p.kill()
            self.rec("K14 GOAWAY parsed by third-party client", False, f"utime failed: {e}")
            return
        # Give the client a moment to process GOAWAY, then stop it.
        time.sleep(3.0)
        p.terminate()
        try:
            err = p.communicate(timeout=15)[1].decode("utf-8", "replace")
        except subprocess.TimeoutExpired:
            p.kill()
            err = ""
        got = "got GOAWAY" in err
        detail = "client logged 'got GOAWAY'"
        if not got:
            detail = "no GOAWAY seen by client (err tail: " + err[-200:].replace("\n", " ") + ")"
        self.rec("K14 GOAWAY parsed by third-party client", got, detail)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--client", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--www", required=True)
    ap.add_argument("--up", required=True)
    ap.add_argument("--cert", required=True)
    ap.add_argument("--json", default="")
    args = ap.parse_args()

    s = Suite(args.client, args.port)
    try:
        s.run_all(args.www, args.up, args.cert)
    except Exception as e:  # noqa: BLE001
        s.records.append({"name": "fatal", "status": "FAIL", "detail": repr(e)})
        print(f"[FAIL] fatal: {e!r}", flush=True)
    fails = [r for r in s.records if r["status"] == "FAIL"]
    summary = {"suite": "U-11 quiche interop", "client": args.client,
               "port": args.port, "results": s.records,
               "failures": [r["name"] for r in fails]}
    if args.json:
        with open(args.json, "w") as f:
            json.dump(summary, f, indent=2)
    print(f"summary: {len(s.records) - len(fails)} passed, {len(fails)} failed",
          flush=True)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
