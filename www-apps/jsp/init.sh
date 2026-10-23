#!/bin/sh
# JSP — 生成 deps/bin/index 启动器：优先真 Jetty（Maven Fat JAR + JDK），
# 没有 JDK/JAR 的机器退回 Python UDS shim（同一套 HTTP/JSP 语义，诚实降级）。
set -e
ROOT="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "${ROOT}/../.." && pwd)"
SIDE="${REPO}/libs/jsp-sidecar"
STATE="${REPO}/state/jsp"
SOCK="${STATE}/jsp.sock"
JAR="${SIDE}/target/jsp-sidecar.jar"
mkdir -p "${ROOT}/deps/bin" "${STATE}"

# JDK 探测：JAVA_HOME → 用户级 ~/local JVM（install_app_runtimes.sh）→ 系统 JVM → PATH。
JAVA_BIN=""
if [ -n "${JAVA_HOME:-}" ] && [ -x "${JAVA_HOME}/bin/java" ]; then
  JAVA_BIN="${JAVA_HOME}/bin/java"
else
  for cand in "${HOME}"/local/usr/lib/jvm/*/bin/java \
              /usr/local/jdk-17/bin/java /usr/local/jdk-21/bin/java \
              /usr/lib/jvm/*/bin/java; do
    if [ -x "${cand}" ]; then JAVA_BIN="${cand}"; break; fi
  done
  if [ -z "${JAVA_BIN}" ] && command -v java >/dev/null 2>&1; then
    JAVA_BIN="$(command -v java)"
  fi
fi

if [ -n "${JAVA_BIN}" ] && [ -f "${JAR}" ]; then
  cat > "${ROOT}/deps/bin/index" <<WRAP
#!/bin/sh
exec "${SIDE}/jsp_sidecar.sh" "\${WEBSERVER_LISTEN_UNIX:-${SOCK}}" "${ROOT}"
WRAP
  chmod +x "${ROOT}/deps/bin/index"
  echo "jsp: jetty sidecar jar=${JAR} java=${JAVA_BIN} (socket from WEBSERVER_LISTEN_UNIX)" \
    > "${ROOT}/deps/manifest.txt"
else
  PY_BIN=""
  for cand in python3 /usr/bin/python3 /usr/local/bin/python3; do
    if command -v "${cand}" >/dev/null 2>&1; then PY_BIN="$(command -v "${cand}")"; break; fi
  done
  if [ -n "${PY_BIN}" ]; then
    cat > "${ROOT}/deps/bin/index" <<WRAP
#!/bin/sh
exec "${PY_BIN}" "${SIDE}/jsp_sidecar.py" --socket "\${WEBSERVER_LISTEN_UNIX:-${SOCK}}" --docroot "${ROOT}"
WRAP
    chmod +x "${ROOT}/deps/bin/index"
    reason="no JDK"
    [ -z "${JAVA_BIN}" ] || reason="jar missing (run scripts/build_jsp_sidecar.sh)"
    echo "jsp: python UDS shim (${reason}; jetty preferred when JDK+jar present)" \
      > "${ROOT}/deps/manifest.txt"
  else
    rm -f "${ROOT}/deps/bin/index"
    echo "jsp: no JDK (jar=${JAR}) and no python3 — sidecar unavailable" \
      > "${ROOT}/deps/manifest.txt"
  fi
fi
