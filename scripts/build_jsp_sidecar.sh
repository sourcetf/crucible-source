#!/usr/bin/env bash
# JSP sidecar — 构建 Maven/Jetty Fat JAR（真 Jetty + Jasper，UDS），
# Python UDS shim 仅作为「没有 JDK 的机器」的 demo 兜底（见 jsp_sidecar.sh）。
#
# 用户级运行时（JDK 17 + Maven）由 scripts/install_app_runtimes.sh 装到 ~/local；
# 本脚本自动 source scripts/runtime_env.sh，所以只要装好就能 `bash scripts/build_jsp_sidecar.sh`。
#
# 退出码语义（与 build_app_engines.sh 一致）：
#   0  jar 已构建/已存在（或有 mvn 但显式 --allow-missing 降级）
#   1  mvn 存在但构建失败 / jar 里缺主类或 Jetty 依赖 —— 不再静默「note」后返回 0
#      （旧行为会让 build_app_engines.sh 以为成功，/jsp/ /do/ 到运行时才 502）
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=scripts/runtime_env.sh
. "${ROOT}/scripts/runtime_env.sh"
SIDE="${ROOT}/libs/jsp-sidecar"
STATE="${ROOT}/state/jsp"
SOCK="${STATE}/test.sock"
DOC="${ROOT}/www-apps/jsp"
JAVA_DIR="${SIDE}/java"
JAR="${SIDE}/target/jsp-sidecar.jar"
ALLOW_MISSING=0
for a in "$@"; do
  case "$a" in
    --allow-missing) ALLOW_MISSING=1 ;;
  esac
done
mkdir -p "${STATE}" "${SIDE}/target"
chmod +x "${SIDE}/jsp_sidecar.sh" "${SIDE}/jsp_sidecar.py" 2>/dev/null || true
echo "jsp sidecar: ${SIDE}/jsp_sidecar.sh"
echo "  default socket: ${SOCK}"
echo "  default docroot: ${DOC}"
echo "  start: ${SIDE}/jsp_sidecar.sh ${SOCK} ${DOC}"
echo "  JAVA_HOME=${JAVA_HOME:-<unset>}"

verify_jar() {
  local jar="$1" listing=""
  [[ -s "${jar}" ]] || { echo "FAIL: ${jar} 不存在或为空" >&2; return 1; }
  if command -v unzip >/dev/null 2>&1; then
    # 先把清单读进变量：`unzip -l | grep -q` 在 `set -o pipefail` 下会因 grep 提前
    # 退出导致 unzip 收到 SIGPIPE（141），管道整体判失败 —— 即使类确实在包里。
    listing="$(unzip -l "${jar}" 2>/dev/null || true)"
    case "${listing}" in
      *com/crucible/jsp/JspSidecarMain.class*) : ;;
      *) echo "FAIL: jar 里没有 JspSidecarMain.class" >&2; return 1 ;;
    esac
    if ! grep -qE 'org/eclipse/jetty/unixdomain|com/kohlschutter/junixsocket' <<<"${listing}"; then
      echo "WARN: jar 里未见 jetty-unixdomain/junixsocket 类（UDS 可能不可用）" >&2
    fi
  fi
  return 0
}

if ! command -v mvn >/dev/null 2>&1; then
  if [[ -f "${JAR}" ]]; then
    echo "note: mvn 不在 PATH；沿用已有 jar ${JAR}"
    verify_jar "${JAR}" || exit 1
    exit 0
  fi
  echo "note: 没有 Maven/JDK → Java JAR 未构建（Python UDS shim 仍可用于 demo）" >&2
  echo "      装运行时：bash scripts/install_app_runtimes.sh --only=java,maven" >&2
  if [[ "${ALLOW_MISSING}" == "1" ]]; then exit 0; fi
  # 没有 mvn 不是构建失败（生产机可能故意只用 python shim）；但要在汇总里可见，
  # 由 build_app_engines.sh 的 BUILD_FAILURES 决定是否致命。这里返回 0 并明确告警。
  exit 0
fi

if ! command -v javac >/dev/null 2>&1 && ! [[ -x "${JAVA_HOME:-}/bin/javac" ]]; then
  echo "FAIL: 找到 mvn 但没有 javac（需要 JDK 17+，不是 JRE）" >&2
  [[ "${ALLOW_MISSING}" == "1" ]] && exit 0
  exit 1
fi

echo "==> building Java JSP sidecar (Maven, Java: $( "${JAVA_HOME:-/usr}/bin/javac" -version 2>&1 | head -n1 ))"
if (cd "${JAVA_DIR}" && mvn -B -q -DskipTests package); then
  :
else
  echo "FAIL: Maven package 失败（libs/jsp-sidecar/java）" >&2
  [[ "${ALLOW_MISSING}" == "1" ]] && exit 0
  exit 1
fi

BUILT="${JAVA_DIR}/target/jsp-sidecar.jar"
if [[ ! -f "${BUILT}" ]]; then
  echo "FAIL: Maven 成功但没有产出 ${BUILT}" >&2
  [[ "${ALLOW_MISSING}" == "1" ]] && exit 0
  exit 1
fi
cp -f "${BUILT}" "${JAR}"
verify_jar "${JAR}" || { [[ "${ALLOW_MISSING}" == "1" ]] && exit 0; exit 1; }
echo "jetty/java jar: ${JAR} ($(stat -c '%s' "${JAR}" 2>/dev/null || wc -c <"${JAR}") bytes)"
