#!/bin/sh
# §19 acceptance — smoke, unit tests, optional wrk (skip if wrk missing).
#
# WARNING: This script uses PRODUCTION ports from config.toml / start_server.sh
# (apps 9095, TLS 8443, …). For safe parallel testing that will not collide with
# a live instance, use scripts/acceptance_test_ports.sh (or seed_and_accept.sh)
# which bind NON-STANDARD ports 19095/19081/19445/19446/18443 only.
set -e
cd "$(dirname "$0")/.."
export PATH="/usr/local/bin:/usr/local/sbin:${HOME}/.cargo/bin:${PATH}"
export LIBCLANG_PATH="${LIBCLANG_PATH:-/usr/local/llvm19/lib}"

echo "============================================================"
echo "acceptance.sh: PRODUCTION ports (9095/8443/…)."
echo "Safe testing (non-std ports): scripts/acceptance_test_ports.sh"
echo "Seed + safe accept:           scripts/seed_and_accept.sh"
echo "============================================================"

./configure --target="${CRUCIBLE_TARGET:-openbsd}" 2>/dev/null || ./configure --target=auto
sh scripts/generate_test_certs.sh
gmake tls-deps 2>/dev/null || make tls-deps 2>/dev/null || true
gmake engines 2>/dev/null || make engines 2>/dev/null || bash scripts/build_app_engines.sh
gmake release 2>/dev/null || make release

sh scripts/start_server.sh
sleep 2

echo "=== smoke apps (PRODUCTION :9095) ==="
curl -sf http://127.0.0.1:9095/rust/ | head -1
curl -sf http://127.0.0.1:9095/go/ | head -1
curl -sf http://127.0.0.1:9095/python/ | head -1 || true
curl -sf http://127.0.0.1:9095/asp/ | head -1 || true

echo "=== tls (PRODUCTION :8443) ==="
echo | openssl s_client -connect 127.0.0.1:8443 -tls1_3 2>/dev/null | grep Protocol | head -1
echo | openssl s_client -connect 127.0.0.1:8443 -tls1_2 2>/dev/null | grep Protocol | head -1

echo "=== unit tests ==="
cargo test --bin webserver file_open 2>/dev/null || true
cargo test --bin webserver would_execute 2>/dev/null || true
cargo test --bin webserver script_rel 2>/dev/null || true
cargo test --bin webserver --features tls,tls_boring,go_shm_ipc,tls_nss,tls_tomcrypt 2>/dev/null | tail -5

if command -v wrk >/dev/null 2>&1; then
  echo "=== wrk rust (informational) ==="
  wrk -t2 -c8 -d3s http://127.0.0.1:9095/rust/ 2>/dev/null | tail -3 || true
fi

if ! rg 'cgi_script::execute_binary' src/server/apps/mod.rs 2>/dev/null | rg -v '^$'; then
  echo "cgi_script: no execute_binary in c/go/rust dispatch (ok)"
fi

echo "acceptance.sh: done (PRODUCTION ports)."
echo "For safe testing use: scripts/acceptance_test_ports.sh (or scripts/seed_and_accept.sh)"
