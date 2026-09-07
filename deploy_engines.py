#!/usr/bin/env python3
"""Deploy Crucible app-engines libraries, samples, and build scripts to remote host."""

from __future__ import annotations

import os
import stat
import sys

import paramiko

HOST = "83.229.125.81"
USER = "root"
PASSWORD = "Yc4+uVpaU658m"
REMOTE_ROOT = "/crucible"

# ---------------------------------------------------------------------------
# File contents
# ---------------------------------------------------------------------------

FILES: dict[str, str] = {}

FILES["libs/app-engines/include/appengine.h"] = r'''/*
 * Crucible app-engine ABI.
 * Loaded via dlopen(RTLD_NOW|RTLD_GLOBAL); symbols resolved with dlsym.
 */
#ifndef APPENGINE_H
#define APPENGINE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct AppEngineResult {
    int status;
    char *headers;       /* "Name: value\r\n" pairs, NUL-terminated block */
    size_t headers_len;
    char *body;
    size_t body_len;
    char *error;         /* optional error string; may be NULL */
} AppEngineResult;

/*
 * Initialize the engine.
 * engine: engine slug (e.g. "c", "go", "rust", "lua")
 * lib_hint: optional path hint / script path; may be NULL
 * returns 0 on success, non-zero on failure
 */
int appengine_init(const char *engine, const char *lib_hint);

/*
 * Execute one request. Caller must free *out with appengine_result_free.
 * returns 0 on success (out filled), non-zero on failure
 */
int appengine_execute(
    const char *script,
    const char *docroot,
    const char *method,
    const char *path,
    const char *query,
    const char *content_type,
    const char *body,
    size_t body_len,
    const char *remote,
    const char *server_name,
    int server_port,
    const char *extra,
    AppEngineResult *out);

void appengine_result_free(AppEngineResult *out);

void appengine_shutdown(void);

#ifdef __cplusplus
}
#endif

#endif /* APPENGINE_H */
'''

FILES["libs/app-engines/common/appengine_common.h"] = r'''#ifndef APPENGINE_COMMON_H
#define APPENGINE_COMMON_H

#include <stddef.h>
#include "appengine.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Allocate and zero a result; returns 0 on success. */
int appengine_result_alloc(AppEngineResult *out);

/* Set body (copies); returns 0 on success. */
int appengine_result_set_body(AppEngineResult *out, const void *data, size_t len);

/* Set a single Content-Type style header block; returns 0 on success. */
int appengine_result_set_headers(AppEngineResult *out, const char *headers);

/* Set error string (copies); returns 0 on success. */
int appengine_result_set_error(AppEngineResult *out, const char *msg);

/* strdup-like helper that returns NULL on failure. */
char *appengine_strdup(const char *s);

/* Fill a simple 200 text/plain hello response. */
int appengine_fill_hello(AppEngineResult *out, const char *engine_name, const char *path);

#ifdef __cplusplus
}
#endif

#endif /* APPENGINE_COMMON_H */
'''

FILES["libs/app-engines/common/appengine_common.c"] = r'''#include "appengine_common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *appengine_strdup(const char *s)
{
    size_t n;
    char *p;

    if (s == NULL)
        return NULL;
    n = strlen(s) + 1;
    p = (char *)malloc(n);
    if (p == NULL)
        return NULL;
    memcpy(p, s, n);
    return p;
}

int appengine_result_alloc(AppEngineResult *out)
{
    if (out == NULL)
        return -1;
    memset(out, 0, sizeof(*out));
    return 0;
}

int appengine_result_set_body(AppEngineResult *out, const void *data, size_t len)
{
    char *p;

    if (out == NULL)
        return -1;
    free(out->body);
    out->body = NULL;
    out->body_len = 0;
    if (data == NULL || len == 0)
        return 0;
    p = (char *)malloc(len + 1);
    if (p == NULL)
        return -1;
    memcpy(p, data, len);
    p[len] = '\0';
    out->body = p;
    out->body_len = len;
    return 0;
}

int appengine_result_set_headers(AppEngineResult *out, const char *headers)
{
    if (out == NULL)
        return -1;
    free(out->headers);
    out->headers = NULL;
    out->headers_len = 0;
    if (headers == NULL)
        return 0;
    out->headers = appengine_strdup(headers);
    if (out->headers == NULL)
        return -1;
    out->headers_len = strlen(out->headers);
    return 0;
}

int appengine_result_set_error(AppEngineResult *out, const char *msg)
{
    if (out == NULL)
        return -1;
    free(out->error);
    out->error = appengine_strdup(msg);
    return out->error == NULL && msg != NULL ? -1 : 0;
}

int appengine_fill_hello(AppEngineResult *out, const char *engine_name, const char *path)
{
    char buf[512];
    int n;

    if (appengine_result_alloc(out) != 0)
        return -1;
    out->status = 200;
    if (appengine_result_set_headers(out, "Content-Type: text/plain; charset=utf-8\r\n") != 0)
        return -1;
    n = snprintf(buf, sizeof(buf), "hello from %s engine path=%s\n",
                 engine_name ? engine_name : "unknown",
                 path ? path : "/");
    if (n < 0)
        return -1;
    return appengine_result_set_body(out, buf, (size_t)n);
}

void appengine_result_free(AppEngineResult *out)
{
    if (out == NULL)
        return;
    free(out->headers);
    free(out->body);
    free(out->error);
    memset(out, 0, sizeof(*out));
}
'''

FILES["libs/app-engines/samples/c-plugin/plugin.c"] = r'''/*
 * Simple C app-engine plugin (hello world).
 * Built into libapp_c.so
 */
#include "appengine.h"
#include "appengine_common.h"

#include <stdio.h>
#include <string.h>

static int g_inited;

int appengine_init(const char *engine, const char *lib_hint)
{
    (void)lib_hint;
    g_inited = 1;
    fprintf(stderr, "c-plugin: init engine=%s\n", engine ? engine : "(null)");
    return 0;
}

int appengine_execute(
    const char *script,
    const char *docroot,
    const char *method,
    const char *path,
    const char *query,
    const char *content_type,
    const char *body,
    size_t body_len,
    const char *remote,
    const char *server_name,
    int server_port,
    const char *extra,
    AppEngineResult *out)
{
    (void)script;
    (void)docroot;
    (void)method;
    (void)query;
    (void)content_type;
    (void)body;
    (void)body_len;
    (void)remote;
    (void)server_name;
    (void)server_port;
    (void)extra;

    if (!g_inited || out == NULL)
        return -1;
    return appengine_fill_hello(out, "c", path);
}

void appengine_shutdown(void)
{
    g_inited = 0;
}
'''

FILES["libs/app-engines/samples/go-plugin/go.mod"] = r'''module crucible/app-engines/go-plugin

go 1.21
'''

FILES["libs/app-engines/samples/go-plugin/main.go"] = r'''package main

/*
#cgo CFLAGS: -I../../include -I../../common
#include <stdlib.h>
#include "appengine.h"
*/
import "C"

import (
	"fmt"
	"unsafe"
)

var inited bool

//export appengine_init
func appengine_init(engine *C.char, libHint *C.char) C.int {
	_ = libHint
	inited = true
	fmt.Printf("go-plugin: init engine=%s\n", C.GoString(engine))
	return 0
}

//export appengine_execute
func appengine_execute(
	script *C.char,
	docroot *C.char,
	method *C.char,
	path *C.char,
	query *C.char,
	contentType *C.char,
	body *C.char,
	bodyLen C.size_t,
	remote *C.char,
	serverName *C.char,
	serverPort C.int,
	extra *C.char,
	out *C.AppEngineResult,
) C.int {
	_ = script
	_ = docroot
	_ = method
	_ = query
	_ = contentType
	_ = body
	_ = bodyLen
	_ = remote
	_ = serverName
	_ = serverPort
	_ = extra

	if !inited || out == nil {
		return -1
	}

	msg := fmt.Sprintf("hello from go engine path=%s\n", C.GoString(path))
	hdr := "Content-Type: text/plain; charset=utf-8\r\n"

	out.status = 200
	out.headers = C.CString(hdr)
	out.headers_len = C.size_t(len(hdr))
	out.body = C.CString(msg)
	out.body_len = C.size_t(len(msg))
	out.error = nil
	return 0
}

//export appengine_result_free
func appengine_result_free(out *C.AppEngineResult) {
	if out == nil {
		return
	}
	if out.headers != nil {
		C.free(unsafe.Pointer(out.headers))
		out.headers = nil
	}
	if out.body != nil {
		C.free(unsafe.Pointer(out.body))
		out.body = nil
	}
	if out.error != nil {
		C.free(unsafe.Pointer(out.error))
		out.error = nil
	}
	out.headers_len = 0
	out.body_len = 0
	out.status = 0
}

//export appengine_shutdown
func appengine_shutdown() {
	inited = false
}

func main() {}
'''

FILES["libs/app-engines/samples/rust-plugin/Cargo.toml"] = r'''[package]
name = "app-rust-plugin"
version = "0.1.0"
edition = "2021"

[lib]
name = "app_rust"
crate-type = ["cdylib"]

[dependencies]
libc = "0.2"
'''

FILES["libs/app-engines/samples/rust-plugin/src/lib.rs"] = r'''//! Rust cdylib app-engine plugin (hello world).

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};

#[repr(C)]
pub struct AppEngineResult {
    pub status: c_int,
    pub headers: *mut c_char,
    pub headers_len: usize,
    pub body: *mut c_char,
    pub body_len: usize,
    pub error: *mut c_char,
}

static INITED: AtomicBool = AtomicBool::new(false);

#[no_mangle]
pub unsafe extern "C" fn appengine_init(engine: *const c_char, _lib_hint: *const c_char) -> c_int {
    INITED.store(true, Ordering::SeqCst);
    if !engine.is_null() {
        let name = CStr::from_ptr(engine).to_string_lossy();
        eprintln!("rust-plugin: init engine={}", name);
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn appengine_execute(
    _script: *const c_char,
    _docroot: *const c_char,
    _method: *const c_char,
    path: *const c_char,
    _query: *const c_char,
    _content_type: *const c_char,
    _body: *const c_char,
    _body_len: usize,
    _remote: *const c_char,
    _server_name: *const c_char,
    _server_port: c_int,
    _extra: *const c_char,
    out: *mut AppEngineResult,
) -> c_int {
    if !INITED.load(Ordering::SeqCst) || out.is_null() {
        return -1;
    }

    let path_s = if path.is_null() {
        "/".to_string()
    } else {
        CStr::from_ptr(path).to_string_lossy().into_owned()
    };
    let msg = format!("hello from rust engine path={}\n", path_s);
    let hdr = "Content-Type: text/plain; charset=utf-8\r\n";

    let hdr_c = match CString::new(hdr) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let body_c = match CString::new(msg.as_str()) {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let r = &mut *out;
    r.status = 200;
    r.headers_len = hdr.len();
    r.body_len = msg.len();
    r.error = ptr::null_mut();
    r.headers = hdr_c.into_raw();
    r.body = body_c.into_raw();
    0
}

#[no_mangle]
pub unsafe extern "C" fn appengine_result_free(out: *mut AppEngineResult) {
    if out.is_null() {
        return;
    }
    let r = &mut *out;
    if !r.headers.is_null() {
        drop(CString::from_raw(r.headers));
        r.headers = ptr::null_mut();
    }
    if !r.body.is_null() {
        drop(CString::from_raw(r.body));
        r.body = ptr::null_mut();
    }
    if !r.error.is_null() {
        drop(CString::from_raw(r.error));
        r.error = ptr::null_mut();
    }
    r.headers_len = 0;
    r.body_len = 0;
    r.status = 0;
}

#[no_mangle]
pub extern "C" fn appengine_shutdown() {
    INITED.store(false, Ordering::SeqCst);
}
'''

FILES["libs/app-engines/lua/lua_engine.c"] = r'''/*
 * Minimal Lua app-engine stub.
 * Full PUC-Lua + ngx.say/header/var wiring is left for a later pass.
 * Built into libapp_lua.so
 */
#include "appengine.h"
#include "appengine_common.h"

#include <stdio.h>
#include <string.h>

static int g_inited;

int appengine_init(const char *engine, const char *lib_hint)
{
    (void)lib_hint;
    g_inited = 1;
    fprintf(stderr, "lua-engine stub: init engine=%s\n", engine ? engine : "(null)");
    return 0;
}

int appengine_execute(
    const char *script,
    const char *docroot,
    const char *method,
    const char *path,
    const char *query,
    const char *content_type,
    const char *body,
    size_t body_len,
    const char *remote,
    const char *server_name,
    int server_port,
    const char *extra,
    AppEngineResult *out)
{
    (void)script;
    (void)docroot;
    (void)method;
    (void)query;
    (void)content_type;
    (void)body;
    (void)body_len;
    (void)remote;
    (void)server_name;
    (void)server_port;
    (void)extra;

    if (!g_inited || out == NULL)
        return -1;
    /* Stub: no Lua VM yet — return a plain hello. */
    return appengine_fill_hello(out, "lua", path);
}

void appengine_shutdown(void)
{
    g_inited = 0;
}
'''

FILES["scripts/build_app_engines.sh"] = r'''#!/usr/bin/env bash
# Build Crucible app-engine shared libraries on OpenBSD.
# Uses gcc/gmake from /usr/local/bin; C plugins need -pthread.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${ROOT}/target/app-engines"
INC="${ROOT}/libs/app-engines/include"
COMMON="${ROOT}/libs/app-engines/common"
SAMPLES="${ROOT}/libs/app-engines/samples"
LUA_DIR="${ROOT}/libs/app-engines/lua"

export PATH="/usr/local/bin:/usr/bin:/bin:${PATH:-}"

# Prefer ports gcc; fall back to system cc.
if [[ -x /usr/local/bin/gcc ]]; then
  CC=/usr/local/bin/gcc
elif command -v gcc >/dev/null 2>&1; then
  CC="$(command -v gcc)"
else
  CC=cc
fi

mkdir -p "${OUT}"

CFLAGS="-O2 -fPIC -pthread -I${INC} -I${COMMON}"
LDFLAGS="-shared -fPIC -pthread"

echo "==> building libapp_c.so (CC=${CC})"
${CC} ${CFLAGS} ${LDFLAGS} \
  -o "${OUT}/libapp_c.so" \
  "${SAMPLES}/c-plugin/plugin.c" \
  "${COMMON}/appengine_common.c"

echo "==> building libapp_lua.so (stub)"
${CC} ${CFLAGS} ${LDFLAGS} \
  -o "${OUT}/libapp_lua.so" \
  "${LUA_DIR}/lua_engine.c" \
  "${COMMON}/appengine_common.c"

echo "==> building libapp_go.so"
if command -v go >/dev/null 2>&1; then
  (
    cd "${SAMPLES}/go-plugin"
    # Unset CARGO_TARGET_DIR pollution is for cargo; for go just build c-shared.
    CGO_ENABLED=1 go build -buildmode=c-shared -o "${OUT}/libapp_go.so" .
  )
else
  echo "WARN: go not found; skipping libapp_go.so" >&2
fi

echo "==> building libapp_rust.so"
if command -v cargo >/dev/null 2>&1; then
  (
    # Critical: sample cargo must not leak CARGO_TARGET_DIR into main webserver build.
    unset CARGO_TARGET_DIR || true
    cd "${SAMPLES}/rust-plugin"
    cargo build --release
    # Locate cdylib (name app_rust)
    SO=""
    for cand in \
      "${SAMPLES}/rust-plugin/target/release/libapp_rust.so" \
      "${SAMPLES}/rust-plugin/target/release/libapp_rust.dylib" \
      "${ROOT}/target/release/libapp_rust.so"
    do
      if [[ -f "${cand}" ]]; then SO="${cand}"; break; fi
    done
    if [[ -z "${SO}" ]]; then
      SO="$(find "${SAMPLES}/rust-plugin/target" -name 'libapp_rust.so' 2>/dev/null | head -n1 || true)"
    fi
    if [[ -n "${SO}" && -f "${SO}" ]]; then
      cp -f "${SO}" "${OUT}/libapp_rust.so"
    else
      echo "WARN: libapp_rust.so not found after cargo build" >&2
    fi
  )
else
  echo "WARN: cargo not found; skipping libapp_rust.so" >&2
fi

echo "==> done. artifacts in ${OUT}"
ls -la "${OUT}" || true
'''

FILES["scripts/build_release.sh"] = r'''#!/usr/bin/env bash
# Build Crucible webserver release binary.
# MUST unset CARGO_TARGET_DIR (app-engine go/rust sample builds can pollute it).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT}"

export PATH="${HOME}/.cargo/bin:/usr/local/bin:/usr/bin:/bin:${PATH:-}"

# Critical: www-apps/rust and sample engines may leave CARGO_TARGET_DIR set.
unset CARGO_TARGET_DIR || true

RESTART=0
if [[ "${1:-}" == "--restart" ]]; then
  RESTART=1
fi

echo "==> cargo build --release (binary: webserver)"
cargo build --release

BIN="${ROOT}/target/release/webserver"
if [[ ! -x "${BIN}" ]]; then
  echo "ERROR: missing ${BIN}" >&2
  exit 1
fi

echo "==> built ${BIN}"
ls -la "${BIN}"
# Quick sanity: native sidecar env symbol should be present after rebuild.
if command -v strings >/dev/null 2>&1; then
  strings "${BIN}" | grep -q WEBSERVER_LISTEN_UNIX \
    && echo "OK: WEBSERVER_LISTEN_UNIX present" \
    || echo "WARN: WEBSERVER_LISTEN_UNIX string not found" >&2
fi

if [[ "${RESTART}" -eq 1 ]]; then
  LOG=/tmp/webserver-restart.log
  echo "==> restarting webserver (log: ${LOG})"
  {
    echo "---- $(date) restart ----"
    pkill -x webserver 2>/dev/null || true
    sleep 1
    nohup "${BIN}" --config "${ROOT}/config.toml" >>"${LOG}" 2>&1 &
    echo "started pid=$!"
  } | tee -a "${LOG}"
fi
'''

FILES["bench/h2_fair_gate.py"] = r'''#!/usr/bin/env python3
"""H2 fair gate stub: compare webserver vs h2o with wrk/h2load.

Full gate: throughput gap h2o/ours <= 1.2 and latency gap ours/h2o <= 1.2.
This stub wraps wrk and records placeholders until h2o endpoints are wired.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


def run_wrk(url: str, threads: int = 2, conns: int = 8, duration: str = "3s") -> str:
    cmd = ["wrk", f"-t{threads}", f"-c{conns}", f"-d{duration}", url]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
        return out
    except FileNotFoundError:
        return "wrk not installed\n"
    except subprocess.CalledProcessError as e:
        return e.output or str(e)


def main() -> int:
    ap = argparse.ArgumentParser(description="H2 fair gate (wrk wrapper stub)")
    ap.add_argument("--ours", default="http://127.0.0.1:9082/", help="webserver URL")
    ap.add_argument("--h2o", default="http://127.0.0.1:8444/", help="h2o URL")
    ap.add_argument("--out", default="bench/overnight/h2_fair_gate.json")
    args = ap.parse_args()

    ours = run_wrk(args.ours)
    h2o = run_wrk(args.h2o)
    result = {
        "status": "stub",
        "gate": {"throughput_max_ratio": 1.2, "latency_max_ratio": 1.2},
        "ours_url": args.ours,
        "h2o_url": args.h2o,
        "ours_wrk": ours,
        "h2o_wrk": h2o,
        "pass": None,
        "note": "Parse wrk RPS/latency and enforce dual gate when wired.",
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''

FILES["bench/app_engine_overhead.py"] = r'''#!/usr/bin/env python3
"""App-engine overhead vs static — wrk wrapper stub.

Default: wrk -t2 -c8 -d3s against :9095 routes (static, rust, c, go, php, ...).
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


ROUTES = [
    ("static", "/"),
    ("rust", "/rust/"),
    ("c", "/c/"),
    ("go", "/go/"),
    ("php", "/php/"),
    ("lua", "/lua/"),
]


def run_wrk(url: str, threads: int = 2, conns: int = 8, duration: str = "3s") -> str:
    cmd = ["wrk", f"-t{threads}", f"-c{conns}", f"-d{duration}", url]
    try:
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
    except FileNotFoundError:
        return "wrk not installed\n"
    except subprocess.CalledProcessError as e:
        return e.output or str(e)


def main() -> int:
    ap = argparse.ArgumentParser(description="App engine overhead (wrk stub)")
    ap.add_argument("--base", default="http://127.0.0.1:9095")
    ap.add_argument("--out", default="bench/overnight/app_engines_overhead.json")
    args = ap.parse_args()

    results = {}
    for name, path in ROUTES:
        url = args.base.rstrip("/") + path
        print(f"==> wrk {url}", flush=True)
        results[name] = {"url": url, "wrk": run_wrk(url)}

    payload = {
        "status": "stub",
        "base": args.base,
        "wrk_args": "-t2 -c8 -d3s",
        "results": results,
        "note": "Parse Requests/sec and Latency; compare engines to static.",
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(json.dumps({"wrote": str(out), "engines": list(results)}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''

FILES["www-apps/rust/main.rs"] = r'''//! Native Rust sidecar / docroot entry for www-apps/rust.
//! When libapp_rust.so is unavailable, init.sh builds this as deps/bin/index
//! listening on WEBSERVER_LISTEN_UNIX.

use std::env;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;

fn handle(mut stream: UnixStream) {
    let mut buf = [0u8; 4096];
    let _ = stream.read(&mut buf);
    let body = b"hello from rust www-app\n";
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(resp.as_bytes());
    let _ = stream.write_all(body);
}

fn main() {
    let sock = env::var("WEBSERVER_LISTEN_UNIX").unwrap_or_else(|_| "/tmp/rust-app.sock".into());
    if Path::new(&sock).exists() {
        let _ = std::fs::remove_file(&sock);
    }
    let listener = UnixListener::bind(&sock).expect("bind unix");
    eprintln!("rust www-app listening on {}", sock);
    for conn in listener.incoming() {
        if let Ok(stream) = conn {
            handle(stream);
        }
    }
}
'''

FILES["www-apps/rust/init.sh"] = r'''#!/usr/bin/env bash
# Build native sidecar binary into deps/bin/index
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "${ROOT}/deps/bin"
unset CARGO_TARGET_DIR || true
export PATH="${HOME}/.cargo/bin:/usr/local/bin:${PATH:-}"

if command -v rustc >/dev/null 2>&1; then
  rustc -O -o "${ROOT}/deps/bin/index" "${ROOT}/main.rs"
  echo "built deps/bin/index (rustc)"
elif command -v cargo >/dev/null 2>&1; then
  # fallback tiny cargo project inline
  TMP="${ROOT}/deps/.build"
  mkdir -p "${TMP}/src"
  cp "${ROOT}/main.rs" "${TMP}/src/main.rs"
  cat > "${TMP}/Cargo.toml" <<'EOF'
[package]
name = "www-rust-app"
version = "0.1.0"
edition = "2021"
EOF
  (cd "${TMP}" && unset CARGO_TARGET_DIR && cargo build --release)
  cp -f "${TMP}/target/release/www-rust-app" "${ROOT}/deps/bin/index"
  echo "built deps/bin/index (cargo)"
else
  echo "ERROR: rustc/cargo required" >&2
  exit 1
fi
'''

FILES["www-apps/c/main.c"] = r'''/*
 * Native C sidecar for www-apps/c (pthread keep-alive).
 * Listens on WEBSERVER_LISTEN_UNIX when libapp_c.so is absent.
 */
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static void *handle_client(void *arg)
{
    int fd = (int)(intptr_t)arg;
    char buf[4096];
    const char *body = "hello from c www-app\n";
    char hdr[256];
    int n;

    (void)read(fd, buf, sizeof(buf));
    n = snprintf(hdr, sizeof(hdr),
                 "HTTP/1.1 200 OK\r\n"
                 "Content-Type: text/plain\r\n"
                 "Content-Length: %zu\r\n"
                 "Connection: close\r\n\r\n",
                 strlen(body));
    if (n > 0)
        (void)write(fd, hdr, (size_t)n);
    (void)write(fd, body, strlen(body));
    close(fd);
    return NULL;
}

int main(void)
{
    const char *path;
    struct sockaddr_un addr;
    int listen_fd, cfd;
    pthread_t th;

    path = getenv("WEBSERVER_LISTEN_UNIX");
    if (path == NULL || path[0] == '\0')
        path = "/tmp/c-app.sock";

    unlink(path);
    listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("socket");
        return 1;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }
    if (listen(listen_fd, 128) < 0) {
        perror("listen");
        return 1;
    }
    fprintf(stderr, "c www-app listening on %s\n", path);

    for (;;) {
        cfd = accept(listen_fd, NULL, NULL);
        if (cfd < 0) {
            if (errno == EINTR)
                continue;
            perror("accept");
            break;
        }
        if (pthread_create(&th, NULL, handle_client, (void *)(intptr_t)cfd) != 0) {
            close(cfd);
            continue;
        }
        pthread_detach(th);
    }
    close(listen_fd);
    return 0;
}
'''

FILES["www-apps/c/init.sh"] = r'''#!/usr/bin/env bash
# Build C native sidecar with -pthread (OpenBSD: /usr/local/bin/gcc)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "${ROOT}/deps/bin"
export PATH="/usr/local/bin:/usr/bin:/bin:${PATH:-}"

if [[ -x /usr/local/bin/gcc ]]; then
  CC=/usr/local/bin/gcc
elif command -v gcc >/dev/null 2>&1; then
  CC="$(command -v gcc)"
else
  CC=cc
fi

${CC} -O2 -pthread -o "${ROOT}/deps/bin/index" "${ROOT}/main.c"
echo "built deps/bin/index with ${CC} -pthread"
'''

FILES["www-apps/go/main.go"] = r'''package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
)

func main() {
	sock := os.Getenv("WEBSERVER_LISTEN_UNIX")
	if sock == "" {
		sock = "/tmp/go-app.sock"
	}
	_ = os.Remove(sock)

	ln, err := net.Listen("unix", sock)
	if err != nil {
		panic(err)
	}
	if ul, ok := ln.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(true)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprint(w, "hello from go www-app\n")
	})

	fmt.Fprintf(os.Stderr, "go www-app listening on %s\n", sock)
	if err := http.Serve(ln, mux); err != nil {
		panic(err)
	}
}
'''

FILES["www-apps/go/init.sh"] = r'''#!/usr/bin/env bash
# Build Go native sidecar into deps/bin/index
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "${ROOT}/deps/bin"
export PATH="/usr/local/bin:${HOME}/go/bin:${PATH:-}"

if ! command -v go >/dev/null 2>&1; then
  echo "ERROR: go required" >&2
  exit 1
fi

(
  cd "${ROOT}"
  if [[ ! -f go.mod ]]; then
    go mod init www-apps-go >/dev/null 2>&1 || true
  fi
  CGO_ENABLED=0 go build -o "${ROOT}/deps/bin/index" .
)
echo "built deps/bin/index (go)"
'''

FILES["www-apps/php/index.php"] = r'''<?php
header('Content-Type: text/plain; charset=utf-8');
echo "hello from php www-app\n";
echo "APP_HELLO=" . getenv('APP_HELLO') . "\n";
'''

# Optional small README for app-engines tree
FILES["libs/app-engines/README.md"] = r'''# app-engines

Modular `.so` engines loaded by Crucible via `dlopen` / `dlsym`.

ABI: `include/appengine.h` — `appengine_init`, `appengine_execute`,
`appengine_result_free`, `appengine_shutdown`.

Build: `bash scripts/build_app_engines.sh` → `target/app-engines/libapp_*.so`
'''


def ensure_remote_dir(sftp: paramiko.SFTPClient, path: str) -> None:
    parts = path.strip("/").split("/")
    cur = ""
    for part in parts:
        cur += "/" + part
        try:
            sftp.stat(cur)
        except OSError:
            sftp.mkdir(cur)


def write_file(sftp: paramiko.SFTPClient, remote_path: str, content: str, mode: int = 0o644) -> None:
    parent = remote_path.rsplit("/", 1)[0]
    ensure_remote_dir(sftp, parent)
    data = content.encode("utf-8")
    with sftp.file(remote_path, "wb") as f:
        f.write(data)
    sftp.chmod(remote_path, mode)


def main() -> int:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    print(f"Connecting to {USER}@{HOST} ...")
    client.connect(
        HOST,
        username=USER,
        password=PASSWORD,
        timeout=30,
        banner_timeout=30,
        auth_timeout=30,
        allow_agent=False,
        look_for_keys=False,
    )
    sftp = client.open_sftp()

    ensure_remote_dir(sftp, REMOTE_ROOT)
    created: list[str] = []

    executable = {
        "scripts/build_app_engines.sh",
        "scripts/build_release.sh",
        "bench/h2_fair_gate.py",
        "bench/app_engine_overhead.py",
        "www-apps/rust/init.sh",
        "www-apps/c/init.sh",
        "www-apps/go/init.sh",
    }

    for rel, content in sorted(FILES.items()):
        remote = f"{REMOTE_ROOT}/{rel}"
        mode = 0o755 if rel in executable else 0o644
        write_file(sftp, remote, content, mode=mode)
        created.append(remote)
        print(f"  wrote {remote}")

    # Self-signed certs via openssl on the remote
    print("Generating cert.pem / key.pem via openssl ...")
    cert_cmd = (
        f"cd {REMOTE_ROOT} && "
        "openssl req -x509 -newkey rsa:2048 -nodes "
        "-keyout key.pem -out cert.pem -days 365 "
        "-subj '/CN=crucible.local/O=Crucible/C=US' "
        "&& openssl ecparam -name prime256v1 -genkey -noout -out key_ec.pem "
        "&& openssl req -x509 -new -key key_ec.pem -out cert_ec.pem -days 365 "
        "-subj '/CN=crucible.local/O=Crucible/C=US' "
        "&& chmod 600 key.pem key_ec.pem && chmod 644 cert.pem cert_ec.pem "
        "&& ls -la cert.pem key.pem cert_ec.pem key_ec.pem"
    )
    _stdin, stdout, stderr = client.exec_command(cert_cmd)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    rc = stdout.channel.recv_exit_status()
    print(out)
    if err.strip():
        print(err, file=sys.stderr)
    if rc != 0:
        print(f"openssl failed rc={rc}", file=sys.stderr)
        sftp.close()
        client.close()
        return 1

    for name in ("cert.pem", "key.pem", "cert_ec.pem", "key_ec.pem"):
        created.append(f"{REMOTE_ROOT}/{name}")

    sftp.close()
    client.close()

    print("\n=== Files created ===")
    for p in created:
        print(p)
    print(f"\nTotal: {len(created)} files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
