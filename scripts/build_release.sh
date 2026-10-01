#!/usr/bin/env bash
# Build Crucible release binary. Unset leaked CARGO_TARGET_DIR from www-apps.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Critical: www-apps/rust init may pollute CARGO_TARGET_DIR
unset CARGO_TARGET_DIR || true
export CARGO_TARGET_DIR="${ROOT}/target"

RESTART=0
for a in "$@"; do
  case "$a" in
    --restart) RESTART=1 ;;
  esac
done

echo "[build] release with features from config.mk / CARGO_FEATURES"
if [[ -f "${ROOT}/config.mk" ]]; then
  # shellcheck disable=SC1091
  # BSD grep/sed 无 \s（GNU 扩展）；曾导致永远读不到 config.mk 的 FEATURES，
  # 静默 fallback 到 tls,tls_boring（go_shm_ipc/NSS/TomCrypt 代码从未编进二进制）。
  CF="$(grep -E '^CARGO_FEATURES[[:space:]]*[:?]*=[[:space:]]*' "${ROOT}/config.mk" | tail -1 | sed 's/^[^=]*=[[:space:]]*//' | tr -d '"' | tr -d "'")" || true
  if [[ -n "${CF:-}" ]]; then
    CARGO_FEATURES="$CF"
  fi
fi
FEATURES="${CARGO_FEATURES:-tls,tls_boring}"
echo "[build] FEATURES=${FEATURES}"
if ! cargo build --release --features "${FEATURES}"; then
  echo "[build] retry with tls,tls_boring" >&2
  cargo build --release --features "tls,tls_boring"
fi

BIN="${ROOT}/target/release/webserver"
if [[ ! -x "$BIN" ]]; then
  echo "missing $BIN" >&2
  exit 1
fi
echo "[build] ok: $BIN"

if [[ "$RESTART" -eq 1 ]]; then
  # 生产入口是 bin/webserver（.gitignore 里写明：它与 target 产物是硬链接，重建后
  # 不指向新 inode，所以必须**显式拷贝**），启动方式统一走 /etc/rc.local。
  # 旧实现 pkill 的是 `target/release/webserver.*--config` —— 打不到生产进程，
  # 「重启」变成起第二个实例；日志还落在 /tmp（无轮转覆盖）。
  if [[ ! -f /etc/rc.local ]]; then
    echo "[restart] 缺少 /etc/rc.local：请先 cp scripts/deploy/rc.local /etc/rc.local" >&2
    exit 1
  fi
  # 先停（cp 覆盖正在执行的二进制会 ETXTBSY），再装，再起。
  pkill -x webserver 2>/dev/null || true
  # 不用 seq（OpenBSD base 里未必有）：显式计数
  n=0
  while pgrep -x webserver >/dev/null && [ "$n" -lt 20 ]; do
    sleep 1
    n=$((n + 1))
  done
  cp "$BIN" "${ROOT}/bin/webserver"
  echo "[restart] installed ${ROOT}/bin/webserver"
  sh /etc/rc.local
fi
