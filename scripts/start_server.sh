#!/bin/sh
# Start Crucible webserver (generate TLS/ECH material if missing).
set -e
cd /crucible

# Self-signed RSA cert for plain TLS listeners when absent.
if [ ! -f cert.pem ] || [ ! -f key.pem ]; then
  openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 3650 -nodes \
    -subj /CN=crucible.local 2>/dev/null || true
fi

# ECDSA leaf for dual-cert BoringSSL selection.
if [ ! -f cert_ec.pem ] || [ ! -f key_ec.pem ]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout key_ec.pem -out cert_ec.pem -days 3650 -nodes \
    -subj /CN=crucible.local 2>/dev/null || true
fi

# ECH keys referenced by production listener ssl.ech_keys.
if [ ! -f state/ech/ech_keys.pem ]; then
  if sh scripts/generate_ech.sh crucible.local 2>/dev/null; then
    :
  else
    echo "start_server: ECH keys not generated (install boringssl pkg for bssl); TLS works without ECH" >&2
  fi
fi

pkill -f target/release/webserver 2>/dev/null || true
sleep 1
nohup ./target/release/webserver --config /crucible/config.toml >>/tmp/webserver-restart.log 2>&1 &
echo "pid $!"
