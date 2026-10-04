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
# 绝不静默降级 feature：旧实现在首次构建失败时回退到 `--features tls,tls_boring`，
# 丢掉 config.mk 声明的 go_shm_ipc / tls_nss / tls_tomcrypt —— 构建仍然打印 ok 并
# `--restart` 安装，于是 Go 引擎与 NSS/TomCrypt 遗留 TLS **无声消失**（运维以为部署成功）。
# 失败就失败：非零退出 + 明确提示怎么修。
if ! cargo build --release --features "${FEATURES}"; then
  echo "[build] FAILED with FEATURES=${FEATURES}" >&2
  echo "[build] 不自动降级 feature（降级会丢掉 go_shm_ipc/tls_nss/tls_tomcrypt 且看起来仍然成功）。" >&2
  echo "[build] 若确实缺少某个 legacy 库，请显式修 config.mk 或改用 --features 传参后重跑。" >&2
  exit 1
fi

BIN="${ROOT}/target/release/webserver"
if [[ ! -x "$BIN" ]]; then
  echo "missing $BIN" >&2
  exit 1
fi
# 产物新鲜度：cargo 成功但二进制没更新（例如被外部 CARGO_TARGET_DIR 污染）时，
# 旧实现会照常安装旧二进制。这里要求二进制比 Cargo.toml/src 里最新文件都新。
NEWEST_SRC="$(find "${ROOT}/src" "${ROOT}/Cargo.toml" "${ROOT}/build.rs" -type f -newer "$BIN" 2>/dev/null | head -1 || true)"
if [[ -n "${NEWEST_SRC}" ]]; then
  echo "[build] STALE: $BIN 比 $NEWEST_SRC 还旧 —— 构建没有真正更新产物，拒绝安装" >&2
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
