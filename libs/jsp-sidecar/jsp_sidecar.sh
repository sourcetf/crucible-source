#!/bin/sh
# JSP sidecar launcher — Java/Jetty jar required (no Python fallback in production).
set -e
ROOT="$(cd "$(dirname "$0")" && pwd)"
SOCK="${1:-${JSP_SOCKET:-/crucible/state/jsp/jsp.sock}}"
DOC="${2:-${JSP_DOCROOT:-.}}"
mkdir -p "$(dirname "$SOCK")"
rm -f "$SOCK"
export JSP_SOCKET="$SOCK"
export JSP_DOCROOT="$DOC"
JAR="${ROOT}/target/jsp-sidecar.jar"

JAVA_BIN=""
if [ -n "${JAVA_HOME:-}" ] && [ -x "${JAVA_HOME}/bin/java" ]; then
  JAVA_BIN="${JAVA_HOME}/bin/java"
else
  # 用户级 JDK（scripts/install_app_runtimes.sh → ~/local/usr/lib/jvm/*）优先，
  # 其次 OpenBSD pkg_add 的 /usr/local/jdk-*，最后系统 JVM / PATH。
  for cand in "${HOME}"/local/usr/lib/jvm/*/bin/java \
              /usr/local/jdk-17/bin/java /usr/local/jdk-21/bin/java /usr/local/jdk-11/bin/java \
              /usr/lib/jvm/*/bin/java; do
    if [ -x "$cand" ]; then JAVA_BIN="$cand"; break; fi
  done
  if [ -z "$JAVA_BIN" ] && command -v java >/dev/null 2>&1; then
    JAVA_BIN="$(command -v java)"
  fi
fi

if [ ! -f "$JAR" ]; then
  echo "jsp_sidecar: missing $JAR — run scripts/build_jsp_sidecar.sh" >&2
  exit 1
fi
if [ -z "$JAVA_BIN" ]; then
  echo "jsp_sidecar: java required (OpenBSD: pkg_add jdk)" >&2
  exit 1
fi
echo "jsp_sidecar: starting Java jar via $JAVA_BIN ($JAR)" >&2
exec "$JAVA_BIN" -jar "$JAR" --socket "$SOCK" --docroot "$DOC"
