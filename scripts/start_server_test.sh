#!/bin/sh
# Start Crucible on NON-STANDARD test ports (config-test.toml).
# Ports: apps=19095 plain=19081 tls12=19445 tls13=19446 prod=18443
# NEVER bind 9095/9081/9445/9446/8443.
set -e
cd /crucible

CFG="${1:-/crucible/config-test.toml}"
LOG="${CRUCIBLE_TEST_LOG:-/tmp/crucible-test.log}"

# Refuse accidental production-port configs.
case "$CFG" in
  *config.toml)
    if [ "$CFG" = "/crucible/config.toml" ] || [ "$CFG" = "config.toml" ]; then
      echo "FAIL: start_server_test.sh is for config-test.toml NON-STANDARD ports only" >&2
      exit 2
    fi
    ;;
esac

if [ ! -f cert.pem ] || [ ! -f key.pem ]; then
  openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 3650 -nodes \
    -subj /CN=crucible.local 2>/dev/null || true
fi
if [ ! -f cert_ec.pem ] || [ ! -f key_ec.pem ]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout key_ec.pem -out cert_ec.pem -days 3650 -nodes \
    -subj /CN=crucible.local 2>/dev/null || true
fi
if [ ! -f state/ech/ech_keys.pem ]; then
  sh scripts/generate_ech.sh crucible.local 2>/dev/null || true
fi

# JSP sidecar on UDS for test listener
mkdir -p state/jsp
pkill -f 'jsp_sidecar.py' 2>/dev/null || true
nohup python3 libs/jsp-sidecar/jsp_sidecar.py \
  --socket /crucible/state/jsp/test.sock \
  --docroot /crucible/www-apps/jsp \
  >>/tmp/jsp-sidecar.log 2>&1 &

# Kill only the previous test instance when possible (pidfile / config-test match).
if [ -f /tmp/crucible-test.pid ]; then
  OLD=$(cat /tmp/crucible-test.pid 2>/dev/null || true)
  if [ -n "$OLD" ] && kill -0 "$OLD" 2>/dev/null; then
    kill "$OLD" 2>/dev/null || true
    sleep 1
  fi
  rm -f /tmp/crucible-test.pid
fi
pkill -f 'webserver --config .*config-test.toml' 2>/dev/null || true
sleep 1

nohup ./target/release/webserver --config "$CFG" >>"$LOG" 2>&1 &
WPID=$!
echo "$WPID" >/tmp/crucible-test.pid
echo "pid $WPID config=$CFG ports=19095,19081,19445,19446,18443 log=$LOG"
