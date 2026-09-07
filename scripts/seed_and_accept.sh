#!/bin/sh
# Seed GeoIP + start server on NON-STANDARD ports + run acceptance_test_ports.sh.
# Ports: apps=19095 plain=19081 tls12=19445 tls13=19446 prod-tls=18443
# NEVER uses production ports 9095/9081/9445/9446/8443.
#
# Pipeline: geoip seed → start_server_test.sh → acceptance_test_ports.sh
set -e
cd "$(dirname "$0")/.."
ROOT="$(pwd)"
# Prefer /crucible layout when running inside the build VM.
if [ -d /crucible ] && [ -f /crucible/config-test.toml ]; then
  cd /crucible
  ROOT=/crucible
fi

export PATH="/usr/local/bin:/usr/local/sbin:${HOME}/.cargo/bin:${PATH}"
export LIBCLANG_PATH="${LIBCLANG_PATH:-/usr/local/llvm19/lib}"
export RUST_LOG="${RUST_LOG:-info}"

DB="${ROOT}/data/geoip/current/geoip.sqlite"
mkdir -p "${ROOT}/data/geoip/current" "${ROOT}/data/geoip/logs"

echo "==> geoip seed ($DB)"
python3 "${ROOT}/scripts/geoip_merge.py" --db "$DB" --init-schema --seed \
  || echo "warn: geoip seed failed (continuing)"

echo "==> start_server_test.sh (non-std ports 19095/19081/19445/19446/18443)"
sh "${ROOT}/scripts/start_server_test.sh"
sleep 2

echo "==> acceptance_test_ports.sh"
sh "${ROOT}/scripts/acceptance_test_ports.sh"

echo "seed_and_accept.sh: done (NON-STANDARD ports only)"
