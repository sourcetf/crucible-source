#!/usr/bin/env bash
# 运行 crucible fuzz target（libFuzzer/cargo-fuzz）并输出机器可读摘要。
#
# 用法：
#   scripts/run_fuzz.sh [--target <name|all>] [--round <秒>] [--total <秒>]
#                       [--min-exec <N>] [--timeout <秒>] [--rss-mb <N>]
#                       [--max-len <N>] [--log-dir <dir>] [--check]
#
# 参数：
#   --target     fuzz target 名（h1fast|qmux_proto|dns_wire|upload_path|all），默认 all
#   --round      单轮 libFuzzer 运行时长（秒），默认 120；到 total 前可跑多轮
#   --total      每个 target 的总时长（秒），默认 300
#   --min-exec   每个 target 达到该 exec 数即可提前结束，默认 1000000
#   --timeout    单次执行的超时（秒），默认 10
#   --rss-mb     RSS 上限（MB），默认 4096
#   --max-len    输入长度上限（字节），默认 16384（各 target 可被环境覆盖）
#   --log-dir    日志目录，默认 ~/.cache/crucible-fuzz/logs
#   --check      只做「稳定工具链可编译」检查（cargo check --lib --bins）后退出
#
# 退出码：0 = 全部 target 无崩溃/超时/OOM；1 = 有 target 失败；2 = 用法/环境错误。
#
# 依赖：nightly 工具链 + cargo-fuzz（cargo install cargo-fuzz --locked）。
# 语料：fuzz/corpus/<target>/（可用 fuzz/gen_corpus.py 重新生成种子）；
# 崩溃产物：fuzz/artifacts/<target>/（本脚本只计数，不自动删除）。
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FUZZ_DIR="$ROOT/fuzz"

TARGETS=(h1fast qmux_proto dns_wire upload_path)
TARGET="all"
ROUND=120
TOTAL=300
MIN_EXEC=1000000
EXEC_TIMEOUT=10
RSS_MB=4096
MAX_LEN=16384
LOG_DIR="${FUZZ_LOG_DIR:-$HOME/.cache/crucible-fuzz/logs}"
CHECK_ONLY=0

die() { echo "run_fuzz: $*" >&2; exit 2; }

while [ $# -gt 0 ]; do
  case "$1" in
    --target)   TARGET="${2:-}"; shift 2 ;;
    --round)    ROUND="${2:-}"; shift 2 ;;
    --total)    TOTAL="${2:-}"; shift 2 ;;
    --min-exec) MIN_EXEC="${2:-}"; shift 2 ;;
    --timeout)  EXEC_TIMEOUT="${2:-}"; shift 2 ;;
    --rss-mb)   RSS_MB="${2:-}"; shift 2 ;;
    --max-len)  MAX_LEN="${2:-}"; shift 2 ;;
    --log-dir)  LOG_DIR="${2:-}"; shift 2 ;;
    --check)    CHECK_ONLY=1; shift ;;
    -h|--help)  sed -n '2,30p' "$0"; exit 0 ;;
    *)          die "未知参数: $1（--help 查看用法）" ;;
  esac
done

case "$TARGET" in
  all) RUN_TARGETS=("${TARGETS[@]}") ;;
  h1fast|qmux_proto|dns_wire|upload_path) RUN_TARGETS=("$TARGET") ;;
  *) die "未知 target: $TARGET" ;;
esac
for v in ROUND TOTAL MIN_EXEC EXEC_TIMEOUT RSS_MB MAX_LEN; do
  case "${!v}" in
    ''|*[!0-9]*) die "--$v 必须是正整数（得到 '${!v}'）" ;;
  esac
done
[ "$ROUND" -gt 0 ] && [ "$TOTAL" -gt 0 ] || die "--round/--total 必须 > 0"

CARGO_BIN="${CARGO:-cargo}"
command -v "$CARGO_BIN" >/dev/null 2>&1 || die "找不到 cargo（$CARGO_BIN）"
mkdir -p "$LOG_DIR"

# 每个 target 的输入上限（覆盖 --max-len）：长 HTTP 头 / 大记录需要更大空间。
max_len_for() {
  case "$1" in
    h1fast)     echo $(( MAX_LEN > 20480 ? MAX_LEN : 20480 )) ;;
    qmux_proto) echo $(( MAX_LEN > 20480 ? MAX_LEN : 20480 )) ;;
    upload_path) echo "$MAX_LEN" ;;
    *)          echo "$MAX_LEN" ;;
  esac
}

if [ "$CHECK_ONLY" = 1 ]; then
  # 稳定工具链：include! 进来的生产 `#[cfg(test)] mod tests` 在 lib-test 目标里没有完整
  # config 桩，所以只检查 lib + bins（fuzz target 自身不跑单测）。
  ( cd "$FUZZ_DIR" && "$CARGO_BIN" check --offline --lib --bins ) \
    || exit 1
  echo "run_fuzz: stable cargo check OK ($FUZZ_DIR)"
  exit 0
fi

command -v cargo-fuzz >/dev/null 2>&1 || {
  echo "run_fuzz: 未安装 cargo-fuzz；请运行: cargo install cargo-fuzz --locked" >&2
  exit 2
}

# nightly：cargo-fuzz 需要 -Zsanitizer；优先 FUZZ_TOOLCHAIN，其次已安装的 nightly。
if [ -n "${FUZZ_TOOLCHAIN:-}" ]; then
  export RUSTUP_TOOLCHAIN="$FUZZ_TOOLCHAIN"
elif command -v rustup >/dev/null 2>&1; then
  if rustup toolchain list 2>/dev/null | grep -q '^nightly'; then
    export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-nightly}"
  else
    die "cargo-fuzz 需要 nightly 工具链：rustup toolchain install nightly"
  fi
fi

: "${CARGO_TARGET_DIR:=$HOME/.cache/crucible-fuzz/target}"
export CARGO_TARGET_DIR
mkdir -p "$CARGO_TARGET_DIR"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-8}"

SUMMARY="$LOG_DIR/summary.tsv"
: > "$SUMMARY"
FAIL=0
START_ALL=$(date +%s)

echo "run_fuzz: root=$ROOT target=$TARGET round=${ROUND}s total=${TOTAL}s min_exec=$MIN_EXEC"
echo "run_fuzz: CARGO_TARGET_DIR=$CARGO_TARGET_DIR toolchain=${RUSTUP_TOOLCHAIN:-default}"

for t in "${RUN_TARGETS[@]}"; do
  log="$LOG_DIR/$t.log"
  : > "$log"
  art_dir="$FUZZ_DIR/artifacts/$t"
  mkdir -p "$art_dir"
  art_before=$(find "$art_dir" -maxdepth 1 -type f 2>/dev/null | wc -l)
  target_start=$(date +%s)
  execs=0
  rounds=0
  status=OK
  maxlen=$(max_len_for "$t")

  while :; do
    now=$(date +%s)
    elapsed=$(( now - target_start ))
    [ "$elapsed" -ge "$TOTAL" ] && break
    rem=$(( TOTAL - elapsed ))
    rt=$ROUND
    [ "$rt" -gt "$rem" ] && rt=$rem

    rounds=$(( rounds + 1 ))
    echo "---- [$t] round $rounds (${rt}s, max_len=$maxlen) ----" >> "$log"
    log_mark=$(wc -c < "$log")
    # 外层 timeout 防御 libFuzzer 自身挂死；正常路径由 -max_total_time 收尾。
    timeout $(( rt + 120 )) cargo fuzz run "$t" -- \
      -max_total_time="$rt" -timeout="$EXEC_TIMEOUT" -rss_limit_mb="$RSS_MB" \
      -max_len="$maxlen" -print_final_stats=1 >> "$log" 2>&1
    rc=$?
    # 只取**本轮**新增日志里的计数（崩溃轮可能没有 final stats ⇒ 该轮计 0，不重算旧值）。
    n=$(tail -c +$(( log_mark + 1 )) "$log" \
          | grep -oE 'stat::number_of_executed_units: +[0-9]+' | tail -1 \
          | grep -oE '[0-9]+$')
    if [ -n "$n" ]; then
      execs=$(( execs + n ))
    fi
    if [ "$rc" -eq 124 ]; then
      status=TIMEOUT
      break
    elif [ "$rc" -ne 0 ]; then
      # 77 = libFuzzer 捕获到崩溃（cargo-fuzz 映射为非零）。
      status=CRASH
      break
    fi
    if [ "$execs" -ge "$MIN_EXEC" ]; then
      break
    fi
  done

  art_after=$(find "$art_dir" -maxdepth 1 -type f 2>/dev/null | wc -l)
  art_new=$(( art_after - art_before ))
  if [ "$art_new" -gt 0 ] && [ "$status" = OK ]; then
    status=CRASH
  fi
  [ "$status" != OK ] && FAIL=1
  printf '%-12s rounds=%-3s execs=%-10s artifacts=%-3s status=%s log=%s\n' \
    "$t" "$rounds" "$execs" "$art_new" "$status" "$log"
  printf '%s\t%s\t%s\t%s\t%s\n' "$t" "$rounds" "$execs" "$art_new" "$status" >> "$SUMMARY"
done

END_ALL=$(date +%s)
echo "run_fuzz: total wall $(( END_ALL - START_ALL ))s; summary: $SUMMARY"
if [ "$FAIL" -ne 0 ]; then
  echo "run_fuzz: FAIL（崩溃/超时产物见 fuzz/artifacts/<target>/）" >&2
  exit 1
fi
echo "run_fuzz: OK"
exit 0
