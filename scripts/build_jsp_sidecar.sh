#!/usr/bin/env bash
# JSP sidecar — Python UDS HTTP/1.1 (default) + optional Maven Java JAR.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SIDE="${ROOT}/libs/jsp-sidecar"
STATE="${ROOT}/state/jsp"
SOCK="${STATE}/test.sock"
DOC="${ROOT}/www-apps/jsp"
JAVA_DIR="${SIDE}/java"
mkdir -p "${STATE}" "${SIDE}/target"
chmod +x "${SIDE}/jsp_sidecar.sh" "${SIDE}/jsp_sidecar.py" 2>/dev/null || true
echo "jsp sidecar: ${SIDE}/jsp_sidecar.sh"
echo "  default socket: ${SOCK}"
echo "  default docroot: ${DOC}"
echo "  start: ${SIDE}/jsp_sidecar.sh ${SOCK} ${DOC}"

if command -v mvn >/dev/null 2>&1 && [[ -f "${JAVA_DIR}/pom.xml" ]]; then
  echo "==> building Java JSP sidecar (Maven)"
  if (cd "${JAVA_DIR}" && mvn -q -DskipTests package); then
    if [[ -f "${JAVA_DIR}/target/jsp-sidecar.jar" ]]; then
      cp -f "${JAVA_DIR}/target/jsp-sidecar.jar" "${SIDE}/target/jsp-sidecar.jar"
      echo "jetty/java jar: ${SIDE}/target/jsp-sidecar.jar"
    fi
  else
    echo "note: Maven package failed; Python UDS shim remains the demo path"
  fi
elif command -v java >/dev/null 2>&1 && [[ -f "${SIDE}/target/jsp-sidecar.jar" ]]; then
  echo "jetty jar present: ${SIDE}/target/jsp-sidecar.jar"
else
  echo "note: Maven/JDK optional; Python UDS shim is the OpenBSD demo path"
fi
