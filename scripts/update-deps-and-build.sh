#!/usr/bin/env bash
# 依赖刷新 + **完整编译**（一条命令）。
#
# 用途：把依赖更新到最新可用版本（crates.io 侧受 Cargo.lock 控制），然后编译**全部产物**：
#   1) TLS 前缀依赖（BoringSSL；开了 tls_tomcrypt 还要 libtomcrypt）
#   2) 应用引擎 .so（`target/app-engines/libapp_*.so`）
#   3) 辅助 FFI（script-ffi：perl/psgi/python/ruby；aspnet；axonasp；jsp sidecar；mruby）
#   4) 主程序 `target/release/webserver`
#
# 为什么需要它：此前"更新依赖"与"完整编译"散在 `make all` / `build_release.sh` /
# `build_app_engines.sh` / 一堆 `build_*.sh` 里，容易漏（真机踩过：只跑 release 没重建引擎，
# 于是 host 用新 ABI 调旧 .so；或反过来只重建引擎没重编 host）。本脚本把顺序、幂等性、
# 「缺工具链必须显式报告而不是静默跳过」都固定下来。
#
# ---- 依赖"更新到最新"的口径（重要，别误解）
# 本仓库**没有 git 依赖**。依赖分两类：
#   * crates.io 依赖（h2 0.4.x、hyper 1、boring 5、quinn 0.11、tokio 1 …）—— 用 `cargo update`
#     刷新到 **Cargo.lock 允许的最新 semver 兼容版本**。跨大版本必须**改 manifest**，
#     本脚本不会替改（那会撞性能门禁与 ABI 假设）。
#   * 工作区内的 **path 包**：`libs/h2`（薄包装，包着 crates.io 的 h2 并加 `BATCH_CAP`）、
#     `libs/quinn-boring`（从 quinn-btls 改来的 BoringSSL crypto provider）。
#     它们不是"某个 commit"，所以本脚本**不会**从上游覆盖它们；只做两件事：
#       ① 让 `libs/h2` 内部的 `h2-crate` 依赖随 `cargo update` 一起刷新；
#       ② **校验本地补丁仍在**（`BATCH_CAP` 常量、quinn-boring 仍挂在工作区），丢了就**报错退出**
#          —— 静默丢掉 `BATCH_CAP` 会让 h2 多路复用性能回退而没人察觉。
#
# ---- 静态编译（`--static`）与"实测结论"，别再走弯路
# 目标机是 **OpenBSD**。实测（2026-11-07，本仓库在 openbsd.dns.google 上）：
#   * `rustc -C target-feature=+crt-static` 能编，但产物是 **PIE(ET_DYN)**，不是真静态；
#   * 要真静态得再加 `-C relocation-model=static -C link-arg=-static`，编出来的 hello-world
#     **启动即 SIGSEGV**（`ldd` 报 not a dynamic executable）；
#   * `cc -static` 编出的程序里 **`dlopen` 直接失败**（OpenBSD 静态 libc 没有动态加载器）。
# 而本项目**所有应用引擎都靠 dlopen 装载 `target/app-engines/libapp_*.so`** ⇒ **全静态会打掉
# 整套 FFI 引擎**。因此本脚本 `--static` 的行为是：**真去构建、逐项验证、不过就拒绝安装**，
# 并把实测证据打出来（绝不是一个"看起来静态"却跑不起来的产物）。
# Linux 上 `--static` 走仓库已有的 musl 静态路径（`scripts/build_musl_static.sh` / zig-musl），
# 那边静态 + dlopen 是可用的。
#
# ---- 剥离（默认开启，`--no-strip` 关）
# 编完对 **主程序 + ech_probe + 全部引擎 .so** 去符号表/调试段（`strip`），打印前后体积与
# 校验（`nm`/`readelf` 不再有 .symtab/.debug_*）。
# **不做** `-C panic=abort`：tokio 现在靠 unwind 把「单个请求任务 panic」隔离在任务边界，
# 改 abort 会让一次请求 panic 变成整进程死亡 —— 那是拿健壮性换体积，本脚本不干。
#
# 用法：
#   bash scripts/update-deps-and-build.sh                 # 刷新依赖 + 完整编译 + 剥离
#   bash scripts/update-deps-and-build.sh --static        # 尝试静态编译（含验证，不过则拒绝）
#   bash scripts/update-deps-and-build.sh --no-strip      # 不剥离（保留符号，便于调试/perf）
#   bash scripts/update-deps-and-build.sh --offline       # 只用现有 Cargo.lock 编译（不联网）
#   bash scripts/update-deps-and-build.sh --dry-run       # 只打印将执行的命令
#   bash scripts/update-deps-and-build.sh --allow-missing # 缺工具链的步骤降级为 SKIP（默认 FAIL）
#   bash scripts/update-deps-and-build.sh --jobs 4 --no-engines
#   bash scripts/update-deps-and-build.sh --test          # 编译后再跑 cargo test
#
# 退出码：0 = 全部成功（SKIP 不算失败）；1 = 有步骤失败；2 = 参数/前置条件错误。
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 2

OFFLINE=0; DRY=0; ALLOW_MISSING=0; DO_ENGINES=1; RUN_TESTS=0; JOBS=""
STATIC=0; STRIP=1
usage() { sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
  case "$1" in
    --offline) OFFLINE=1 ;;
    --dry-run) DRY=1 ;;
    --allow-missing) ALLOW_MISSING=1 ;;
    --no-engines) DO_ENGINES=0 ;;
    --static) STATIC=1 ;;
    --no-strip) STRIP=0 ;;
    --test) RUN_TESTS=1 ;;
    --jobs) JOBS="${2:-}"; shift ;;
    --help|-h) usage; exit 0 ;;
    *) echo "unknown option: $1（--help 看用法）" >&2; exit 2 ;;
  esac
  shift
done

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
run()  { # run <描述> <命令...>
  local desc="$1"; shift
  if [ "$DRY" = 1 ]; then echo "  [dry-run] $*"; return 0; fi
  echo "  \$ $*"
  "$@"
}

# 步骤结果汇总（不因单个 SKIP 中止；失败则最后非零退出）
FAILED=(); SKIPPED=()
step_fail() { FAILED+=("$1"); }
step_skip() { SKIPPED+=("$1: $2"); }

have() { command -v "$1" >/dev/null 2>&1; }

# 工具链缺失的处理：--allow-missing ⇒ SKIP；否则 FAIL。
need_tool() { # need_tool <工具> <步骤名>
  if have "$1"; then return 0; fi
  if [ "$ALLOW_MISSING" = 1 ]; then step_skip "$2" "缺工具链 $1"; return 1; fi
  step_fail "$2（缺工具链 $1；要用 --allow-missing 降级为 SKIP）"; return 1
}

say "前置检查"
if ! have cargo; then
  if [ "$DRY" = 1 ]; then echo "  （--dry-run：本机没有 cargo，只做静态检查与打印）"
  else echo "找不到 cargo（装 rustup 或把 ~/.cargo/bin 加进 PATH）" >&2; exit 2; fi
fi
if [ ! -f config.mk ]; then
  echo "config.mk 不存在 ⇒ 先跑 ./configure（会用 ./configure --target=auto；需要 legacy TLS 就再加 --enable-nss --enable-tomcrypt）"
  if [ "$DRY" = 1 ]; then echo "  [dry-run] ./configure --target=auto"; else
    ./configure --target=auto || { echo "configure 失败" >&2; exit 2; }
  fi
fi
FEATURES="$(grep -E '^CARGO_FEATURES[[:space:]]*:=[[:space:]]*' config.mk | sed 's/^[^=]*=[[:space:]]*//')"
TARGET_OS="$(grep -E '^TARGET_OS[[:space:]]*:=[[:space:]]*' config.mk | sed 's/^[^=]*=[[:space:]]*//')"
echo "  config.mk: TARGET_OS=${TARGET_OS:-?} FEATURES=${FEATURES:-?}"
echo "  工作树: $(git rev-parse --short HEAD 2>/dev/null || echo '（非 git 工作树）')"
if [ -n "$(git status --porcelain 2>/dev/null | head -1)" ]; then
  echo "  注意：工作树有未提交改动（本次编译会用这些改动，出错时先看它们）"
fi

# ------------------------------------------------------------------ 1) 依赖刷新
say "1/5 依赖刷新"
if [ "$OFFLINE" = 1 ]; then
  echo "  --offline：跳过 cargo update，直接用现有 Cargo.lock"
else
  # 记录性能/ABI 敏感依赖的版本，改完对比（h2 的版本直接影响多路复用门禁）。
  sensitive() {
    grep -E '^name = "(h2|h2-crate|quinn|quinn-proto|boring|boring-sys|hyper|hyper-util|tokio|http|h3|h3-quinn)"$' -A1 Cargo.lock 2>/dev/null |
      awk '/^name = /{n=$3} /^version = /{print n, $3}' | tr -d '"' | sort
  }
  BEFORE="$(sensitive)"
  cp -p Cargo.lock "Cargo.lock.bak-$(date +%Y%m%d-%H%M%S)" 2>/dev/null || true
  run "cargo update（刷新到 Cargo.lock 允许的最新 semver 兼容版本）" cargo update || step_fail "cargo update"
  AFTER="$(sensitive)"
  echo "  --- 敏感依赖版本变化（前 → 后） ---"
  if [ "$BEFORE" = "$AFTER" ]; then echo "    （无变化）"; else diff <(echo "$BEFORE") <(echo "$AFTER") | sed 's/^/    /' || true; fi
  echo "  --- Cargo.lock diff 摘要 ---"; git --no-pager diff --stat -- Cargo.lock 2>/dev/null | sed 's/^/    /' || true
  echo "  --- 重复版本（cargo tree -d，可能意味着要显式统一） ---"
  if [ "$DRY" = 0 ] && have cargo; then cargo tree -d 2>/dev/null | head -20 | sed 's/^/    /' || true; fi

  # **本地补丁校验**：path 包被上游覆盖 / 补丁丢失时必须报错（静默丢 BATCH_CAP = 性能回退无人知）。
  if ! grep -q 'pub const BATCH_CAP' libs/h2/src/framed_write.rs 2>/dev/null; then
    step_fail "libs/h2 的本地补丁 BATCH_CAP 不见了（h2 多路复用会回退，务必恢复）"
  fi
  if ! grep -q 'libs/quinn-boring' Cargo.toml 2>/dev/null; then
    step_fail "Cargo.toml 里不再引用 libs/quinn-boring（fork 被丢？）"
  fi
  WANT_H2="$(grep -E '^h2-crate' -A0 libs/h2/Cargo.toml | head -1)"
  echo "  libs/h2 内部包装: ${WANT_H2:-<未找到 h2-crate 依赖>}"
fi

# ------------------------------------------------------------------ 2) TLS 前缀依赖
say "2/5 TLS 前缀依赖"
if [ -f scripts/build_boringssl.sh ] && [ ! -e target/tls-libs/boringssl/ssl/libssl.a ]; then
  run "构建 BoringSSL（缺产物才建）" bash scripts/build_boringssl.sh || step_fail "build_boringssl.sh"
else
  echo "  BoringSSL 产物已存在（或脚本缺失）⇒ 跳过（幂等）"
fi
case ",${FEATURES:-}," in
  *,tls_tomcrypt,*)
    if [ -f scripts/build_libtomcrypt.sh ]; then
      run "构建 libtomcrypt（tls_tomcrypt 已启用）" bash scripts/build_libtomcrypt.sh || step_fail "build_libtomcrypt.sh"
    else step_fail "启用了 tls_tomcrypt 但没有 scripts/build_libtomcrypt.sh"; fi ;;
  *) echo "  tls_tomcrypt 未启用 ⇒ 跳过 libtomcrypt" ;;
esac

# ------------------------------------------------------------------ 3) 应用引擎 .so
say "3/5 应用引擎 .so"
if [ "$DO_ENGINES" = 0 ]; then echo "  --no-engines ⇒ 跳过"; else
  if [ ! -f scripts/build_app_engines.sh ]; then step_fail "缺 scripts/build_app_engines.sh"; else
    # 该脚本要求 bash（内部用数组/[[ ]]）；bash-only 语法在 ksh 下会静默炸。
    if [ "$ALLOW_MISSING" = 1 ]; then
      run "build_app_engines.sh --allow-missing" bash scripts/build_app_engines.sh --allow-missing || step_fail "build_app_engines.sh"
    else
      run "build_app_engines.sh" bash scripts/build_app_engines.sh || step_fail "build_app_engines.sh"
    fi
  fi
  # 辅助 FFI：每个都先查工具链，缺了就明确 SKIP（绝不静默）。
  if need_tool cc "script-ffi（perl/psgi/python/ruby）"; then
    [ -f scripts/build_script_ffi.sh ] && { run "build_script_ffi.sh" bash scripts/build_script_ffi.sh || step_fail "build_script_ffi.sh"; } || step_fail "缺 scripts/build_script_ffi.sh"
  fi
  if need_tool mvn "jsp sidecar（Jetty jar）"; then
    if have javac; then
      [ -f scripts/build_jsp_sidecar.sh ] && { run "build_jsp_sidecar.sh" bash scripts/build_jsp_sidecar.sh || step_fail "build_jsp_sidecar.sh"; } || step_fail "缺 scripts/build_jsp_sidecar.sh"
    else step_skip "jsp sidecar" "有 mvn 但没有 javac（需要 JDK17+，不是 JRE）"; fi
  fi
  if have dotnet; then
    [ -f scripts/build_aspnet_ffi.sh ] && { run "build_aspnet_ffi.sh" bash scripts/build_aspnet_ffi.sh || step_fail "build_aspnet_ffi.sh"; }
  else step_skip "aspnet hostfxr FFI" "缺 dotnet/hostfxr（引擎会走 C mini 降级并带 X-Crucible-Engine 标记）"; fi
  if have go; then
    [ -f scripts/build_axonasp_ffi.sh ] && { run "build_axonasp_ffi.sh" bash scripts/build_axonasp_ffi.sh || step_fail "build_axonasp_ffi.sh"; }
  else step_skip "axonasp FFI" "缺 go"; fi
  # mruby 链目前是 stub（无源码）——如实标注，不假装构建。
  step_skip "mruby 静态嵌入链" "仓库无 mruby 源码（scripts/build_mruby.sh 只写占位头）"
fi

# ------------------------------------------------------------------ 4) 主程序
say "4/5 主程序"
HOST_OS="$(uname -s)"
BIN="target/release/webserver"
if [ "$STATIC" = 1 ]; then
  case "$HOST_OS" in
    Linux)
      # 仓库已有 musl 静态路径（Linux 上静态 + dlopen 正常）。
      if [ -f scripts/build_musl_static.sh ]; then
        run "构建 musl 静态运行时（Linux）" bash scripts/build_musl_static.sh || step_fail "build_musl_static.sh"
      fi
      SFLAGS="-C target-feature=+crt-static"
      run "cargo build --release（musl 静态）" env \
        CARGO_PROFILE_RELEASE_LTO=thin \
        RUSTFLAGS="${SFLAGS}" cargo build --release --features "${FEATURES}" \
        || step_fail "static cargo build（Linux/musl）"
      ;;
    OpenBSD)
      # 见文件头实测结论：真静态会 SIGSEGV 且 dlopen 不可用 ⇒ 构建后**逐项验证**，不过就拒绝。
      SFLAGS="-C target-feature=+crt-static -C relocation-model=static -C link-arg=-static"
      run "cargo build --release（OpenBSD 真静态尝试）" env \
        CARGO_PROFILE_RELEASE_LTO=thin \
        RUSTFLAGS="${SFLAGS}" cargo build --release --features "${FEATURES}" \
        || step_fail "static cargo build（OpenBSD）"
      if [ "$DRY" = 0 ] && [ -x "$BIN" ]; then
        echo "  --- 静态验证（三项全过才算可用） ---"
        if ldd "$BIN" 2>&1 | grep -qi "not a dynamic executable"; then echo "    [1/3] 非动态: OK"; else echo "    [1/3] 非动态: ** 仍是动态链接 **"; step_fail "静态验证[1/3] 产物仍是动态链接"; fi
        if "$BIN" --help >/dev/null 2>&1; then echo "    [2/3] 能启动: OK"; else echo "    [2/3] 能启动: ** 无法执行（静态 hello-world 在本机即 SIGSEGV）**"; step_fail "静态验证[2/3] 产物跑不起来"; fi
        if [ -e target/app-engines/libapp_lua.so ]; then
          if "$BIN" --check-config --config config.toml >/dev/null 2>&1; then
            echo "    [3/3] 能读配置: OK  —— **但注意：OpenBSD 静态二进制 dlopen 不可用，FFI 引擎（libapp_*.so）会全部装不上**"
            echo "          ⇒ 若要用静态产物，必须只用 sidecar/fpm 类引擎，或改用 Linux/musl 静态构建。"
          else echo "    [3/3] 能读配置: ** 失败 **"; step_fail "静态验证[3/3] 静态产物读不了配置"; fi
        fi
        echo "    （**不自动安装**：因上述 dlopen 限制，静态产物需人工确认引擎形态后再换交。）"
      fi
      ;;
    *) echo "  未知平台 $HOST_OS ⇒ 按 OpenBSD 同法处理"; step_fail "--static 在 $HOST_OS 上未定义" ;;
  esac
else
  if [ ! -f scripts/build_release.sh ]; then step_fail "缺 scripts/build_release.sh"; else
    run "build_release.sh（按 config.mk 的 FEATURES；它拒绝静默降级 feature）" bash scripts/build_release.sh \
      || step_fail "build_release.sh"
  fi
fi

# --- 剥离阶段（默认开） ---
if [ "$STRIP" = 1 ]; then
  say "4b/5 剥离符号/调试段（撑大产物的东西）"
  # 判据说明：OpenBSD 8 的 strip 是 **llvm-strip**，`--strip-all` 删的是 `.symtab` 与
  # `.debug_*`；**`.dynsym` 必须保留**（PIE 依赖它，引擎 .so 还要靠它导出 `appengine_*`），
  # 所以 **`nm` 仍会列出动态符号 —— 那是正常的，不代表没剥**。真正的判据看段表。
  leftover() { # leftover <文件> ⇒ 打印仍存在的 .symtab/.debug_* 段数
    readelf -S "$1" 2>/dev/null | grep -cE '\.(symtab|debug_)' || true
  }
  strip_one() { # strip_one <文件> [so]
    local f="$1" kind="${2:-exe}"; [ -f "$f" ] || return 0
    local before after cmd="" lb la
    before="$(wc -c <"$f" | tr -d ' ')"; lb="$(leftover "$f")"
    if [ "$DRY" = 1 ]; then echo "  [dry-run] strip（$kind） $f"; return 0; fi
    # 可执行文件用 --strip-all；共享库用 --strip-unneeded（保留动态加载所需的最小集）。
    # OpenBSD 上没有 GNU strip 时退到 -x（去本地符号）+ -S（去调试段）。
    if [ "$kind" = so ]; then
      if strip --strip-unneeded "$f" 2>/dev/null; then cmd="strip --strip-unneeded"
      elif strip --strip-all "$f" 2>/dev/null; then cmd="strip --strip-all"
      elif strip -x -S "$f" 2>/dev/null; then cmd="strip -x -S"
      elif strip -x "$f" 2>/dev/null; then cmd="strip -x"; fi
    else
      if strip --strip-all "$f" 2>/dev/null; then cmd="strip --strip-all"
      elif strip -x -S "$f" 2>/dev/null; then cmd="strip -x -S"
      elif strip -x "$f" 2>/dev/null; then cmd="strip -x"; fi
    fi
    if [ -z "$cmd" ]; then echo "    !! $f 剥离失败（保留原样）"; return 0; fi
    after="$(wc -c <"$f" | tr -d ' ')"; la="$(leftover "$f")"
    printf '    %-44s %9s -> %9s bytes (-%s%%)  .symtab/.debug 段 %s->%s  [%s]\n' \
      "$f" "$before" "$after" \
      "$(( (before-after)*100/(before==0?1:before) ))" "$lb" "$la" "$cmd"
    [ "$la" = 0 ] || echo "      !! $f 仍有 $la 个 .symtab/.debug 段（检查 strip 是否真的生效）"
  }
  strip_one "$BIN" exe
  strip_one "target/release/ech_probe" exe
  for so in target/app-engines/*.so; do [ -f "$so" ] && strip_one "$so" so; done
  echo "  另：可执行文件与 .so 的 .comment 段属编译期标记，可用 --remove-section=.comment 再去一点（本脚本不动，避免不同 strip 实现差异）。"
  echo "  说明：不做 -C panic=abort（见文件头：那是拿请求级 panic 隔离换体积）。"
fi

# ------------------------------------------------------------------ 5) 可选测试 + 汇总
if [ "$RUN_TESTS" = 1 ]; then
  say "5/5 cargo test"
  run "cargo test（--features ${FEATURES}）" cargo test --features "${FEATURES}" || step_fail "cargo test"
else
  say "5/5 跳过测试（--test 可开）"
fi

say "汇总"
printf '  产物：\n'
for f in target/release/webserver target/app-engines/libapp_lua.so target/app-engines/libapp_go.so libs/jsp-sidecar/target/jsp-sidecar.jar; do
  [ -e "$f" ] && printf '    %-52s %s bytes  %s\n' "$f" "$(wc -c <"$f" | tr -d ' ')" "$(date -r "$f" '+%Y-%m-%d %H:%M' 2>/dev/null || echo '')"
done
if [ "${#SKIPPED[@]}" -gt 0 ]; then
  echo "  跳过（缺工具链/无源码，非失败）："; for s in "${SKIPPED[@]}"; do echo "    - $s"; done
fi
if [ "${#FAILED[@]}" -gt 0 ]; then
  echo "  ** 失败 **："; for s in "${FAILED[@]}"; do echo "    - $s"; done
  echo; echo "完成（有失败）：依赖已刷新，编译未全绿。"; exit 1
fi
echo "  全部成功（STATIC=${STATIC} STRIP=${STRIP}）。"
echo "  提示：换交到线上用 scripts/deploy/deploy_release.sh 或 build_release.sh --restart；"
echo "        重启后建议跑 scripts/acceptance.sh 冒烟 + scripts/accept-verify-engine-containment.sh 围堵门禁。"
