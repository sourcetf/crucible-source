#!/usr/bin/env bash
# Build script-ffi shared library + per-language app engines.
# Prefers in-process interpreters when headers are found:
#   -DCRUCIBLE_HAVE_PYTHON / -DCRUCIBLE_HAVE_RUBY / -DCRUCIBLE_HAVE_PERL
# Missing headers: library builds but execute() fails closed (no popen).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${ROOT}/target/app-engines"
SRC="${ROOT}/libs/script-ffi"
INC="${ROOT}/libs/app-engines/include"
COMMON="${ROOT}/libs/app-engines/common"
CC="${CC:-cc}"
mkdir -p "${OUT}"

export PATH="/usr/local/bin:/usr/bin:/bin:${PATH:-}"
if [[ -x /usr/local/bin/gcc ]]; then
  CC=/usr/local/bin/gcc
fi

CFLAGS="-O2 -fPIC -I${INC} -I${COMMON}"
LDFLAGS="-shared -fPIC"
EXTRA_CFLAGS=""
EXTRA_LIBS=""
# 语言专属的编译/链接参数：psgi 只该拿 Perl 的、rack 只该拿 Ruby 的。
# 混用 EXTRA_CFLAGS 会让 libapp_psgi.so 也链上 libpython/libruby（无害但会掩盖
# 「到底探测到了什么」），所以单独留一份。
PL_CFLAGS=""; PL_LIBS=""
RB_CFLAGS=""; RB_LIBS=""

detect_python() {
  if pkg-config --exists python3-embed 2>/dev/null; then
    EXTRA_CFLAGS="${EXTRA_CFLAGS} $(pkg-config --cflags python3-embed) -DCRUCIBLE_HAVE_PYTHON"
    EXTRA_LIBS="${EXTRA_LIBS} $(pkg-config --libs python3-embed)"
    echo "    in-process Python via python3-embed"
    return 0
  fi
  if pkg-config --exists python3 2>/dev/null; then
    EXTRA_CFLAGS="${EXTRA_CFLAGS} $(pkg-config --cflags python3) -DCRUCIBLE_HAVE_PYTHON"
    EXTRA_LIBS="${EXTRA_LIBS} $(pkg-config --libs python3)"
    echo "    in-process Python via python3"
    return 0
  fi
  for cand in \
    /usr/local/include/python3.*/Python.h \
    /usr/include/python3.*/Python.h
  do
    for f in ${cand}; do
      if [[ -f "${f}" ]]; then
        local idir
        idir="$(dirname "${f}")"
        EXTRA_CFLAGS="${EXTRA_CFLAGS} -I${idir} -DCRUCIBLE_HAVE_PYTHON"
        EXTRA_LIBS="${EXTRA_LIBS} -lpython3"
        echo "    in-process Python headers at ${f}"
        return 0
      fi
    done
  done
  echo "    Python headers missing → embed-missing (no popen) for python"
  return 1
}

detect_ruby() {
  # **默认关闭**：嵌入式 MRI 在 OpenBSD + Ruby 3.4 上启动阶段就 rb_bug → SIGSEGV 整个
  # webserver 进程（script_engine.c 里的专用 MRI 线程 + RUBY_INIT_STACK + 最小 prelude
  # 都试过，core 栈一致：sigsegv → rb_bug_for_fatal_signal → ruby_default_signal）。
  # 与 rack 引擎同款风险，因此同样做成显式开关；稳定的 /ruby/ 路径是常驻 Ruby sidecar。
  if [[ "${CRUCIBLE_ENABLE_RUBY_EMBED:-0}" != "1" ]]; then
    echo "    Ruby embed disabled by default (CRUCIBLE_ENABLE_RUBY_EMBED=1 to opt in) → embed-missing (no popen)"
    return 1
  fi
  if pkg-config --exists ruby 2>/dev/null; then
    EXTRA_CFLAGS="${EXTRA_CFLAGS} $(pkg-config --cflags ruby) -DCRUCIBLE_HAVE_RUBY"
    EXTRA_LIBS="${EXTRA_LIBS} $(pkg-config --libs ruby)"
    RB_CFLAGS="$(pkg-config --cflags ruby)"
    RB_LIBS="$(pkg-config --libs ruby)"
    echo "    in-process Ruby via pkg-config"
    return 0
  fi
  # OpenBSD 的 ruby 端口装的是**版本化**二进制（ruby34/ruby33…），没有 `ruby` 这个名字，
  # 所以 `command -v ruby` 探测在目标机上恒失败——这正是 libapp_rack.so 一直 embed-missing
  # 的原因。这里按版本号逐个试。
  local rb=""
  local cand
  for cand in ruby ruby34 ruby33 ruby32 ruby31; do
    if command -v "${cand}" >/dev/null 2>&1; then rb="${cand}"; break; fi
  done
  if [[ -n "${rb}" ]]; then
    local hdr arch libs
    hdr="$(${rb} -rrbconfig -e 'print RbConfig::CONFIG["rubyhdrdir"]' 2>/dev/null || true)"
    arch="$(${rb} -rrbconfig -e 'print RbConfig::CONFIG["rubyarchhdrdir"]' 2>/dev/null || true)"
    libs="$(${rb} -rrbconfig -e 'print RbConfig::CONFIG["LIBRUBYARG_SHARED"]' 2>/dev/null || true)"
    if [[ -n "${hdr}" && -f "${hdr}/ruby.h" ]]; then
      RB_CFLAGS="-I${hdr}"
      [[ -n "${arch}" ]] && RB_CFLAGS="${RB_CFLAGS} -I${arch}"
      RB_LIBS="${libs:--lruby}"
      EXTRA_CFLAGS="${EXTRA_CFLAGS} ${RB_CFLAGS} -DCRUCIBLE_HAVE_RUBY"
      EXTRA_LIBS="${EXTRA_LIBS} ${RB_LIBS}"
      echo "    in-process Ruby (${rb}) headers at ${hdr}"
      return 0
    fi
  fi
  # 最后兜底：直接看头文件目录（二进制与头文件来自不同子包时仍可用）。
  local d
  for d in /usr/local/include/ruby-* /usr/include/ruby-*; do
    if [[ -f "${d}/ruby.h" ]]; then
      RB_CFLAGS="-I${d}"
      for arch in "${d}"/*-openbsd "${d}"/*-linux; do
        [[ -d "${arch}" ]] && RB_CFLAGS="${RB_CFLAGS} -I${arch}"
      done
      # 从目录名推库名：ruby-3.4 -> -lruby34
      local ver
      ver="$(basename "${d}" | sed -E 's/^ruby-([0-9]+)\.([0-9]+).*/\1\2/')"
      RB_LIBS="-lruby${ver}"
      EXTRA_CFLAGS="${EXTRA_CFLAGS} ${RB_CFLAGS} -DCRUCIBLE_HAVE_RUBY"
      EXTRA_LIBS="${EXTRA_LIBS} ${RB_LIBS}"
      echo "    in-process Ruby headers at ${d} (lib=${RB_LIBS})"
      return 0
    fi
  done
  echo "    Ruby headers missing → embed-missing (no popen) for ruby"
  return 1
}

detect_perl() {
  if command -v perl >/dev/null 2>&1; then
    local cflags
    cflags="$(perl -MExtUtils::Embed -e 'ccopts' 2>/dev/null || true)"
    local ld
    ld="$(perl -MExtUtils::Embed -e 'ldopts' 2>/dev/null || true)"
    if echo "${cflags}" | grep -q -- '-I'; then
      EXTRA_CFLAGS="${EXTRA_CFLAGS} ${cflags} -DCRUCIBLE_HAVE_PERL"
      EXTRA_LIBS="${EXTRA_LIBS} ${ld}"
      PL_CFLAGS="${cflags}"
      PL_LIBS="${ld}"
      echo "    in-process Perl via ExtUtils::Embed"
      return 0
    fi
  fi
  echo "    Perl headers missing → embed-missing (no popen)"
  return 1
}

echo "==> detecting in-process script interpreters"
detect_python || true
detect_ruby || true
detect_perl || true

echo "==> building libscriptffi.so"
${CC} ${CFLAGS} ${EXTRA_CFLAGS} ${LDFLAGS} -o "${OUT}/libscriptffi.so" \
  "${SRC}/scriptffi.c" ${EXTRA_LIBS} || \
${CC} ${CFLAGS} ${LDFLAGS} -o "${OUT}/libscriptffi.so" "${SRC}/scriptffi.c"

for lang in python ruby perl; do
  echo "==> building libapp_${lang}.so (script_engine; flags=${EXTRA_CFLAGS:-(embed-missing)})"
  if ! ${CC} ${CFLAGS} ${EXTRA_CFLAGS} -DCRUCIBLE_SCRIPT_LANG='"'"${lang}"'"' ${LDFLAGS} \
    -o "${OUT}/libapp_${lang}.so" \
    "${SRC}/script_engine.c" \
    "${COMMON}/appengine_common.c" \
    ${EXTRA_LIBS}; then
    echo "WARN: in-process link failed for ${lang}; rebuilding without embeds (fail-closed)" >&2
    ${CC} ${CFLAGS} -DCRUCIBLE_SCRIPT_LANG='"'"${lang}"'"' ${LDFLAGS} \
      -o "${OUT}/libapp_${lang}.so" \
      "${SRC}/script_engine.c" \
      "${COMMON}/appengine_common.c"
  fi
done

# Ruby embed 关闭时：**删掉**可能残留的 libapp_ruby.so。
# 为什么删而不是留 stub：`native_http::lib_available()` 判的是「文件是否存在」，
# 留一个「每次请求都报 embed-missing」的 .so 会让 /ruby/ 恒 502，并抢在持久 sidecar
# （www-apps/ruby/deps/bin/index → sidecar.rb）之前把请求吃掉。删掉之后分派自动落到
# sidecar：不崩、能用（sidecar 崩了也只是重启它，不影响 webserver 主进程）。
if [[ "${CRUCIBLE_ENABLE_RUBY_EMBED:-0}" != "1" && -f "${OUT}/libapp_ruby.so" ]]; then
  rm -f "${OUT}/libapp_ruby.so"
  echo "removed ${OUT}/libapp_ruby.so (ruby embed disabled → persistent sidecar path)"
fi

# ---- psgi / rack：与 python/ruby/perl 同一套嵌入，只是引擎源文件不同 ----
# 此前这两个 .so 只由 build_app_engines.sh 的 `build_stub_engine` 编译（不带 HAVE_* 标志），
# 于是 psgi/rack **永远**返回「本引擎构建时未嵌入 Perl/Ruby」的 502 —— 规格 §7.3 要求它们是
# 可用的嵌入引擎。这里在探测到对应解释器时补编一次（探测失败保持现状：诚实失败、不 spawn）。
build_extra_engine() {
  local name="$1" src="$2" cflags="$3" libs="$4" have="$5"
  if [[ ! -f "${src}" ]]; then
    echo "    skip ${name}: ${src} missing"
    return 0
  fi
  if [[ -z "${cflags}" ]]; then
    echo "    ${name}: interpreter headers missing -> keep embed-missing build (no popen)"
    return 0
  fi
  echo "==> building libapp_${name}.so (in-process ${have})"
  if ! ${CC} ${CFLAGS} ${cflags} ${LDFLAGS} -o "${OUT}/libapp_${name}.so" "${src}" "${COMMON}/appengine_common.c" "${COMMON}/appengine_util.c" ${libs}; then
    echo "WARN: in-process link failed for ${name}; keeping previous artifact" >&2
    return 0
  fi
}

build_extra_engine psgi "${ROOT}/libs/app-engines/psgi/psgi_engine.c" "${PL_CFLAGS}${PL_CFLAGS:+-DCRUCIBLE_HAVE_PERL}" "${PL_LIBS}" "Perl"

# rack（嵌入式 MRI）：**默认不启用**，构建诚实失败版。
#
# 为什么：MRI 嵌入在本项目里会**周期性 SIGSEGV 整个进程**。实测（OpenBSD 7.9，
# ruby 3.4.9）：`GET /rack/` 返回 200 之后数秒到数十秒内进程崩溃（core 456MB，
# gdb: 信号 11，栈顶在 libruby34.so 的 sigsegv 处理器），**所有监听口一起下线**。
# 已排除的假设：dlclose（RTLD_NODELETE 常驻映射后仍崩）、shutdown 销毁 VM
# （appengine_shutdown 是 no-op）。剩下的高置信度原因：MRI 的定时器线程/信号处理
# 与「从任意原生线程（tokio worker）调用 Ruby API」的组合 —— MRI 要求调用线程先
# 注册到 VM（rb_thread_call_with_gvl / ruby_thread_init 一族），而 app_ffi 的线程池
# 不保证「初始化 VM 的线程 == 执行请求的线程」。
#
# 启用条件（谁修谁验）：把引擎改成「所有 Ruby 调用都经过一个专用的 Ruby 线程」
# （或每次调用用 rb_thread_call_with_gvl 包裹），并跑通
# `curl /rack/` 之后至少 5 分钟不崩 + 连续 1000 次请求。届时把下面这行的参数换成
# "${RB_CFLAGS}${RB_CFLAGS:+-DCRUCIBLE_HAVE_RUBY}" "${RB_LIBS}" "Ruby" 即可。
build_extra_engine rack "${ROOT}/libs/app-engines/rack/rack_engine.c" "" "" "Ruby-disabled"

echo "built ${OUT}/libscriptffi.so libapp_{python,ruby,perl,psgi,rack}.so"
