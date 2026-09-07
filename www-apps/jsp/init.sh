#!/bin/sh
# JSP — start Jetty Embedded UDS sidecar (Java preferred; Python fallback)
set -e
export JAVA_HOME="${JAVA_HOME:-/usr/local/jdk-17}"
export PATH="${JAVA_HOME}/bin:${PATH}"
ROOT="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "${ROOT}/../.." && pwd)"
SIDE="${REPO}/libs/jsp-sidecar"
STATE="${REPO}/state/jsp"
SOCK="${STATE}/jsp.sock"
mkdir -p "${ROOT}/deps/bin" "${STATE}"
chmod +x "${SIDE}/jsp_sidecar.sh" 2>/dev/null || true
# Wrapper as deps/bin/index for native_http sidecar spawn
cat > "${ROOT}/deps/bin/index" <<EOF
#!/bin/sh
exec "${SIDE}/jsp_sidecar.sh" "\${WEBSERVER_LISTEN_UNIX:-${SOCK}}" "${ROOT}"
EOF
chmod +x "${ROOT}/deps/bin/index"
echo "jsp: sidecar ${SOCK} (also config socket=state/jsp/jsp.sock)" > "${ROOT}/deps/manifest.txt"
echo "start manually: ${SIDE}/jsp_sidecar.sh ${SOCK} ${ROOT}"
