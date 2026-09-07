#!/bin/sh
# Generate RSA + EC test certs for config.toml listeners.
set -e
cd "$(dirname "$0")/.."
if ! openssl version >/dev/null 2>&1; then
  echo "openssl required" >&2
  exit 1
fi
if [[ ! -f cert.pem || ! -f key.pem ]]; then
  openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 3650 -nodes -subj /CN=crucible.local
fi
if [[ ! -f cert_ec.pem || ! -f key_ec.pem ]]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout key_ec.pem -out cert_ec.pem -days 3650 -nodes -subj /CN=crucible.local
fi
mkdir -p state/ech
if [[ ! -f state/ech/ech_keys.pem ]]; then
  if [[ -x scripts/generate_ech.sh ]]; then
    sh scripts/generate_ech.sh crucible.local || true
  fi
fi
echo "test certs ready: cert.pem key.pem cert_ec.pem key_ec.pem"
