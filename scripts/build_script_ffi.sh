#!/usr/bin/env bash
# Build script-ffi shared library + per-language app engines.
# Prefers in-process interpreters when headers are found:
#   -DCRUCIBLE_HAVE_PYTHON / -DCRUCIBLE_HAVE_RUBY / -DCRUCIBLE_HAVE_PERL
# Missing headers: library builds but execute() fails closed (no popen).
#
# 语言 flag **按语言隔离**（PY_* / RB_* / PL_*）：每只 libapp_<lang>.so 只拿自己语言的
# cflags/libs。混用（旧 EXTRA_* 写法）会让「一个语言的链接失败」拖挂**所有**语言 ——
# 实测：perl 的 -lperl 不可用 ⇒ python3-embed 明明可用却一起降级为 embed-missing。
#
# 产物目录：默认 ${ROOT}/target/app-engines，可用 CRUCIBLE_APP_ENGINES_OUT 覆盖
# （build_app_engines.sh 会透传，远程真机验证/CI 可用它在不碰现役 .so 的前提下试建）。
#
# 解释器自检 —— 必须是文件里**第一段可执行代码**（理由同 build_app_engines.sh）：
# OpenBSD 的 /bin/sh 是 ksh，`sh scripts/build_script_ffi.sh` 会在解析到 bash-only
# 语法时报 syntax error 退出（本脚本有 `local x=()`/`[[ ]]`）。这里先 exec 到 bash。
# ---------------------------------------------------------------------------
if [ -z "${BASH_VERSION:-}" ]; then
  _cr_bash=""
  for _cr_cand in bash /usr/local/bin/bash /usr/bin/bash /bin/bash; do
    # 绝对路径候选同时用 -x 复核：`command -v /abs/path` 在各家 ksh 上行为不一。
    if command -v "${_cr_cand}" >/dev/null 2>&1 || [ -x "${_cr_cand}" ]; then
      _cr_bash="${_cr_cand}"; break
    fi
  done
  # 只有「可读且带 #! 的脚本文件」才敢再 exec：`sh < script` 时 $0 是 sh 自己，
  # 对二进制再 exec 只会得到 "cannot execute binary file"。
  _cr_self=""
  if [ -f "$0" ] && [ -r "$0" ]; then
    IFS= read -r _cr_line < "$0" 2>/dev/null || _cr_line=""
    case "${_cr_line}" in '#!'*) _cr_self="$0" ;; esac
  fi
  if [ -z "${_cr_bash}" ]; then
    echo "FATAL: $0 需要 bash（本脚本用数组/[[ ]] 语法，ksh/sh 不支持）。" >&2
    echo "       当前解释器没有 BASH_VERSION，PATH 里也找不到 bash。" >&2
    echo "       OpenBSD: pkg_add bash；或显式调用: bash $0 $*" >&2
    exit 1
  fi
  if [ -z "${_cr_self}" ]; then
    echo "FATAL: $0 需要 bash（本脚本用数组/[[ ]] 语法），但无法自动重新执行：" >&2
    echo "       \"$0\" 不是可读的脚本文件（例如把脚本管道进 sh）；请先落盘再执行：bash <脚本路径>" >&2
    exit 1
  fi
  echo "==> 检测到非 bash 解释器，自动改用 ${_cr_bash} 重新执行 ${_cr_self}" >&2
  exec "${_cr_bash}" "${_cr_self}" "$@"
fi
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=scripts/runtime_env.sh
. "${ROOT}/scripts/runtime_env.sh"
OUT="${CRUCIBLE_APP_ENGINES_OUT:-${ROOT}/target/app-engines}"
SRC="${ROOT}/libs/script-ffi"
INC="${ROOT}/libs/app-engines/include"
COMMON="${ROOT}/libs/app-engines/common"
CC="${CC:-cc}"
mkdir -p "${OUT}"

export PATH="/usr/local/bin:/usr/bin:/bin:${PATH:-}"
if [[ -x /usr/local/bin/gcc ]]; then
  CC=/usr/local/bin/gcc
fi
# 编译器的可读前置检查（否则第一条编译命令 `cc: not found` + set -e 退出 127）。
if ! command -v "${CC}" >/dev/null 2>&1; then
  echo "FATAL: C 编译器 '${CC}' 不存在（\$CC / PATH 里都没有）；无法构建 script-ffi。" >&2
  echo "       OpenBSD: 装了 base 的 cc，或 pkg_add gcc；也可显式 CC=/path/to/cc $0" >&2
  exit 1
fi

CFLAGS="-O2 -fPIC -I${INC} -I${COMMON}"
LDFLAGS="-shared -fPIC"
# 语言专属的编译/链接参数。**必须按语言分开**：
#
# 旧实现把三种解释器的 cflags/libs 累加进同一个 EXTRA_CFLAGS/EXTRA_LIBS，然后
# `for lang in python ruby perl` 用同一套参数编译三只 .so。后果（本机实测，
# logs/before-build-scriptffi.log）：只要**任一**语言的链接参数不可用，三只 .so 全部
# 降级为 embed-missing。典型：本机 perl 头在（ExtUtils::Embed 探测成功）但
# `-lperl` 找不到（Debian 只装 libperl.so.5.40 无开发符号链接）⇒ libapp_python.so
# 的链接也带 `-lperl` ⇒ `cannot find -lperl` ⇒ **python3-embed 明明可用却被降级**。
# 分开之后每个 .so 只拿自己语言的 flag：一个语言的失败不再拖挂其它语言。
PY_CFLAGS=""; PY_LIBS=""
PL_CFLAGS=""; PL_LIBS=""
RB_CFLAGS=""; RB_LIBS=""

# 记录「有头无库/链接失败」的降级项，结束时汇总（避免在几百行编译输出里被淹没）。
DEGRADED=()

detect_python() {
  if pkg-config --exists python3-embed 2>/dev/null; then
    PY_CFLAGS="$(pkg-config --cflags python3-embed) -DCRUCIBLE_HAVE_PYTHON"
    PY_LIBS="$(pkg-config --libs python3-embed)"
    echo "    in-process Python via python3-embed"
    return 0
  fi
  if pkg-config --exists python3 2>/dev/null; then
    PY_CFLAGS="$(pkg-config --cflags python3) -DCRUCIBLE_HAVE_PYTHON"
    PY_LIBS="$(pkg-config --libs python3)"
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
        PY_CFLAGS="-I${idir} -DCRUCIBLE_HAVE_PYTHON"
        PY_LIBS="-lpython3"
        echo "    in-process Python headers at ${f}"
        return 0
      fi
    done
  done
  echo "    Python headers missing → embed-missing (no popen) for python"
  return 1
}

detect_ruby() {
  # 始终**探测**（rack 的 MRI 嵌入由独立的 CRUCIBLE_ENABLE_RACK_EMBED 控制；
  # 脚本引擎 ruby 用不用 RB_* 由下面的 CRUCIBLE_ENABLE_RUBY_EMBED 决定）。
  # 历史：嵌入式 MRI 在 OpenBSD + Ruby 3.4 上启动阶段就 rb_bug → SIGSEGV 整个
  # webserver 进程（script_engine.c 里的专用 MRI 线程 + RUBY_INIT_STACK + 最小
  # prelude 都试过，core 栈一致：sigsegv → rb_bug_for_fatal_signal →
  # ruby_default_signal）。稳定的 /ruby/ 路径是常驻 Ruby sidecar。
  if [[ "${CRUCIBLE_ENABLE_RUBY_EMBED:-0}" != "1" ]]; then
    echo "    Ruby script-engine embed disabled by default (CRUCIBLE_ENABLE_RUBY_EMBED=1 to opt in); 仍探测 RB_* 供 rack 使用"
  fi
  # OpenBSD 的 ruby 端口装的是**版本化**二进制（ruby34/ruby33…），没有 `ruby` 这个名字；
  # Debian/Ubuntu 用户级解包也只有 ruby3.3 + update-alternatives 符号链接（install_app_runtimes.sh
  # 会补 ruby → ruby3.x）。按版本号逐个试。
  local rb=""
  local cand
  for cand in ruby ruby3.4 ruby34 ruby3.3 ruby33 ruby3.2 ruby32 ruby3.1 ruby31; do
    if command -v "${cand}" >/dev/null 2>&1; then rb="${cand}"; break; fi
  done
  if [[ -n "${rb}" ]]; then
    local hdr arch libs libdir
    hdr="$(${rb} -rrbconfig -e 'print RbConfig::CONFIG["rubyhdrdir"]' 2>/dev/null || true)"
    arch="$(${rb} -rrbconfig -e 'print RbConfig::CONFIG["rubyarchhdrdir"]' 2>/dev/null || true)"
    libs="$(${rb} -rrbconfig -e 'print RbConfig::CONFIG["LIBRUBYARG_SHARED"]' 2>/dev/null || true)"
    libdir="$(${rb} -rrbconfig -e 'print RbConfig::CONFIG["libdir"]' 2>/dev/null || true)"
    if [[ -n "${hdr}" && -f "${hdr}/ruby.h" ]]; then
      RB_CFLAGS="-I${hdr}"
      [[ -n "${arch}" ]] && RB_CFLAGS="${RB_CFLAGS} -I${arch}"
      RB_CFLAGS="${RB_CFLAGS} -DCRUCIBLE_HAVE_RUBY"
      RB_LIBS="${libs:--lruby}"
      # 用户级解包（aptlocal → ~/local）时 rbconfig 里的 libdir 仍是编译期 /usr/lib/...，
      # 但真实 libruby 在 ~/local/usr/lib/x86_64-linux-gnu。优先用**真实存在**的目录，
      # 并加 -rpath：宿主 dlopen(libapp_rack.so) 时 DT_NEEDED=libruby-3.3.so.1 才能解析
      #（不然只靠 LD_LIBRARY_PATH，运维漏设就 502）。
      local d real=""
      for d in "${CRUCIBLE_RUNTIME_ROOT:-$HOME/local}/usr/lib/x86_64-linux-gnu" \
               "${libdir}" \
               /usr/lib/x86_64-linux-gnu /usr/local/lib /usr/lib; do
        [[ -n "${d}" && -d "${d}" ]] || continue
        if compgen -G "${d}/libruby*.so*" >/dev/null 2>&1; then real="${d}"; break; fi
      done
      if [[ -n "${real}" ]]; then
        RB_LIBS="-L${real} ${RB_LIBS} -Wl,-rpath,${real}"
      fi
      echo "    in-process Ruby (${rb}) headers at ${hdr} libs=${RB_LIBS}"
      return 0
    fi
  fi
  if pkg-config --exists ruby 2>/dev/null; then
    # 只在 pkg-config 指出的头文件**真的存在**时才采纳：用户级解包场景里
    # pkg-config 可能指向系统的 /usr/include/ruby-3.3.0（未装），链接期才炸。
    local pc_hdr
    pc_hdr="$(pkg-config --cflags ruby 2>/dev/null | tr ' ' '\n' | sed -n 's/^-I//p' | head -n1)"
    if [[ -n "${pc_hdr}" && -f "${pc_hdr}/ruby.h" ]]; then
      RB_CFLAGS="$(pkg-config --cflags ruby) -DCRUCIBLE_HAVE_RUBY"
      RB_LIBS="$(pkg-config --libs ruby)"
      echo "    in-process Ruby via pkg-config"
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
      RB_CFLAGS="${RB_CFLAGS} -DCRUCIBLE_HAVE_RUBY"
      echo "    in-process Ruby headers at ${d} (lib=${RB_LIBS})"
      return 0
    fi
  done
  echo "    Ruby headers missing → embed-missing (no popen) for ruby"
  return 1
}

# 「能不能真的链上」探测（Perl）：ExtUtils::Embed 只描述**期望**的 flags，不代表本机
# 链接器一定解析得动。旧实现按**文件名**找 libperl.so / libperl.a，在 OpenBSD 上误判：
#   OpenBSD base perl 只有 /usr/lib/libperl.so.27.0，**没有** libperl.so 开发符号链接，
#   但该平台的 ld 本来就能把 `-lperl` 解析到 libperl.so.27.0（部署实测 -lperl 链接 rc=0、
#   DT_NEEDED=libperl.so.27.0）。旧守卫据此判「库缺失」→ perl/psgi 降级 embed-missing
#   → /perl/ /psgi/ **502 回归**（2026-10-16 部署实录；当时靠手工
#   `ln -s /usr/lib/libperl.so.27.0 /usr/local/lib/libperl.so` 才恢复 —— 这个 workaround
#   不该是部署步骤）。
# 现在改成**实际试链**：用与真正构建完全相同的 flags 编一只空 .so。判据与真实构建同源：
#   - OpenBSD（ld 认版本化 .so）：成功 → 保持 in-process Perl；
#   - Debian 只有 libperl.so.5.40、GNU ld 又只认 libperl.so：如实失败 → 降级（并打印
#     链接器输出的末几行，不再靠猜文件名）。
perl_link_probe() {
  local ldopts="$1" tmpdir rc=0
  tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/crucible-perlprobe.XXXXXX" 2>/dev/null || true)"
  if [[ -z "${tmpdir}" || ! -d "${tmpdir}" ]]; then
    # 临时目录都建不出来：不做判定，交给真正的构建（它会诚实地成功/失败）。
    echo "    NOTE: mktemp -d 不可用，跳过 Perl 试链（由实际构建决定）" >&2
    return 0
  fi
  printf 'int main(void){return 0;}\n' > "${tmpdir}/probe.c"
  # shellcheck disable=SC2086  # flag 串必须按空白拆开
  ${CC} ${CFLAGS} ${PL_CFLAGS} ${LDFLAGS} -o "${tmpdir}/probe.so" "${tmpdir}/probe.c" ${ldopts} \
    >"${tmpdir}/link.log" 2>&1 || rc=$?
  if [[ ${rc} -eq 0 ]]; then
    rm -rf "${tmpdir}"
    return 0
  fi
  PERL_PROBE_LOG="${tmpdir}/link.log"   # 失败时保留（很小）供排障
  return 1
}

detect_perl() {
  if command -v perl >/dev/null 2>&1; then
    local cflags ld
    cflags="$(perl -MExtUtils::Embed -e 'ccopts' 2>/dev/null || true)"
    ld="$(perl -MExtUtils::Embed -e 'ldopts' 2>/dev/null || true)"
    if echo "${cflags}" | grep -q -- '-I'; then
      if ! printf '%s\n' "${ld}" | grep -q -- '-lperl'; then
        echo "WARN: Perl 头文件在（${cflags}）但 ExtUtils::Embed ldopts 里没有 -lperl（'${ld}'）—— 链接期必然缺 Perl_* 库，降级 embed-missing。" >&2
        DEGRADED+=("perl (headers present, ldopts 无 -lperl → embed-missing)")
        return 1
      fi
      PL_CFLAGS="${cflags} -DCRUCIBLE_HAVE_PERL"
      PL_LIBS="${ld}"
      # 用户级 libperl-dev（aptlocal → ~/local/usr/lib/x86_64-linux-gnu/libperl.so）
      # 不在链接器默认搜索路径里：ExtUtils::Embed 的 ldopts 只写 `-lperl`（无 -L）。
      # 找到真实 libperl.so 就补 -L + rpath；否则维持原判据（OpenBSD lld 能直接解析
      # 版本化库，不需要 -L，也不受影响）。
      local pl_extra="" pl_dir
      for pl_dir in "${CRUCIBLE_RUNTIME_ROOT:-$HOME/local}/usr/lib/x86_64-linux-gnu" \
                     "${CRUCIBLE_RUNTIME_ROOT:-$HOME/local}/usr/lib" \
                     /usr/lib/x86_64-linux-gnu /usr/local/lib /usr/lib; do
        if [[ -e "${pl_dir}/libperl.so" || -e "${pl_dir}/libperl.a" ]]; then
          pl_extra="-L${pl_dir} -Wl,-rpath,${pl_dir}"
          break
        fi
      done
      if [[ -n "${pl_extra}" ]]; then
        PL_LIBS="${pl_extra} ${PL_LIBS}"
      fi
      if ! perl_link_probe "${PL_LIBS}"; then
        echo "WARN: Perl 头文件在（${cflags}），但用真实构建 flags 试链空 .so **失败** → perl/psgi 降级 embed-missing（不 spawn、不假成功）。" >&2
        echo "      ldopts=${PL_LIBS}" >&2
        echo "      链接器输出（末 5 行；完整日志 ${PERL_PROBE_LOG:-<none>}）：" >&2
        tail -n 5 "${PERL_PROBE_LOG:-/dev/null}" >&2 || true
        echo "      说明：只有 libperl.so.<ver> 而无 libperl.so 符号链接时，装 perl 开发包即可（用户级：aptlocal.sh install-deps libperl-dev）；OpenBSD 的 ld 能直接解析版本化库，无需补链接。" >&2
        DEGRADED+=("perl (headers present, real link probe failed → embed-missing)")
        PL_CFLAGS=""
        PL_LIBS=""
        return 1
      fi
      echo "    in-process Perl via ExtUtils::Embed (link probe OK)"
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
# libscriptffi.so 是各嵌入式 CPython 引擎的**共享初始化协调点**
#（crucible_py_ensure_init；crucible_pyinit.h 明确要求「不引用任何链接期 Py_* 符号」）。
# 它不需要、也不应该链接任何解释器：旧实现把三种解释器的 flag 一起塞进来，反而让
# 「任一解释器链接失败」连共享锁一起拖挂（本机实测：-lperl 找不到 → 整只降级）。
${CC} ${CFLAGS} ${LDFLAGS} -o "${OUT}/libscriptffi.so" "${SRC}/scriptffi.c"

build_script_engine() {
  local lang="$1" lflags="$2" llibs="$3"
  local src="${SRC}/script_engine.c"
  echo "==> building libapp_${lang}.so (script_engine; flags=${lflags:-(embed-missing)})"
  if [[ -n "${lflags}" ]]; then
    if ${CC} ${CFLAGS} ${lflags} -DCRUCIBLE_SCRIPT_LANG='"'"${lang}"'"' ${LDFLAGS} \
      -o "${OUT}/libapp_${lang}.so" "${src}" "${COMMON}/appengine_common.c" ${llibs}; then
      return 0
    fi
    echo "WARN: in-process link failed for ${lang}; rebuilding without embeds (fail-closed)" >&2
    DEGRADED+=("${lang} (in-process link failed → embed-missing)")
  fi
  ${CC} ${CFLAGS} -DCRUCIBLE_SCRIPT_LANG='"'"${lang}"'"' ${LDFLAGS} \
    -o "${OUT}/libapp_${lang}.so" "${src}" "${COMMON}/appengine_common.c"
}

# 每只 .so 只拿**自己语言**的 flag（见文件头注释：混用会让一个语言的链接失败拖挂全部）。
build_script_engine python "${PY_CFLAGS}" "${PY_LIBS}"
if [[ "${CRUCIBLE_ENABLE_RUBY_EMBED:-0}" == "1" ]]; then
  build_script_engine ruby "${RB_CFLAGS}" "${RB_LIBS}"
else
  # 脚本引擎默认不嵌入 MRI（见 detect_ruby 注释）；RB_* 仍供 rack 使用。
  build_script_engine ruby "" ""
fi
build_script_engine perl   "${PL_CFLAGS}" "${PL_LIBS}"

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
    DEGRADED+=("${name} (in-process link failed → keeping previous artifact)")
    return 0
  fi
}

# 没有嵌入标志时的「诚实失败」构建：**必须真编一只 stub**（覆盖掉上一次可能
# 留下的嵌入式产物）。旧行为是 cflags 为空就 return，结果「默认关」的构建会把
# 之前 CRUCIBLE_ENABLE_*=1 构建的 .so 原样留在 target/app-engines —— 运维以为
# 已退回安全版，实际还在跑嵌入式解释器。
build_extra_engine_stub() {
  local name="$1" src="$2"
  if [[ ! -f "${src}" ]]; then
    echo "    skip ${name}: ${src} missing"
    return 0
  fi
  echo "==> building libapp_${name}.so (embed-missing / honest failure)"
  ${CC} ${CFLAGS} ${LDFLAGS} -o "${OUT}/libapp_${name}.so" "${src}" \
    "${COMMON}/appengine_common.c" "${COMMON}/appengine_util.c"
}

build_extra_engine psgi "${ROOT}/libs/app-engines/psgi/psgi_engine.c" "${PL_CFLAGS}" "${PL_LIBS}" "Perl"

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
# `curl /rack/` 之后至少 5 分钟不崩 + 连续 1000 次请求。
#
# 2026-10-23（runtimes-wave14）：装了 ruby 3.3.8 + ruby-dev 后做了 A/B：
#   Linux / Ubuntu 26.04（Ruby 3.3.8，libruby-3.3.so.3.3，rack 3.2.4）：
#     1000 次顺序 + 400 次 32 并发（/rack/）全部 200，进程存活、无 crash；
#   生产 OpenBSD + Ruby 3.4 历史上是「返回 200 后数秒~数十秒 SIGSEGV 整个进程」。
# 因此默认策略按**平台**：Linux 默认开（否则 /rack/ 只有 502，规格 §7.3 不可用），
# OpenBSD 默认关（保持诚实失败 + 已知崩溃证据）；始终可用 CRUCIBLE_ENABLE_RACK_EMBED
# 显式覆盖（0/1）。
RACK_EMBED_DEFAULT=0
case "$(uname -s)" in
  Linux) RACK_EMBED_DEFAULT=1 ;;
esac
RACK_EMBED="${CRUCIBLE_ENABLE_RACK_EMBED:-${RACK_EMBED_DEFAULT}}"
if [[ "${RACK_EMBED}" == "1" && -n "${RB_CFLAGS}" ]]; then
  build_extra_engine rack "${ROOT}/libs/app-engines/rack/rack_engine.c" "${RB_CFLAGS}" "${RB_LIBS}" "Ruby"
else
  if [[ "${RACK_EMBED}" == "1" ]]; then
    echo "WARN: CRUCIBLE_ENABLE_RACK_EMBED=1 但未探测到 ruby 头文件/库 → rack 构建诚实失败版" >&2
  fi
  build_extra_engine_stub rack "${ROOT}/libs/app-engines/rack/rack_engine.c"
fi

echo "built ${OUT}/libscriptffi.so libapp_{python,ruby,perl,psgi,rack}.so"

# 降级汇总：把散落在几百行编译输出里的 embed-missing / 链接失败集中列一次。
# （降级本身是**显式失败**：请求 502 + 日志写明原因，不是静默假成功；但「探测到了
#   解释器却因链接问题降级」排障时很容易看漏，所以汇总。）
INPROCESS_OK=()
[[ -n "${PY_CFLAGS}" ]] && INPROCESS_OK+=("python")
# ruby 只在脚本引擎开关打开时才算「可用」（RB_* 探测成功也可能只供 rack 用）。
[[ -n "${RB_CFLAGS}" && "${CRUCIBLE_ENABLE_RUBY_EMBED:-0}" == "1" ]] && INPROCESS_OK+=("ruby")
[[ -n "${PL_CFLAGS}" ]] && INPROCESS_OK+=("perl")
[[ -n "${RB_CFLAGS}" && "${RACK_EMBED:-0}" == "1" ]] && INPROCESS_OK+=("rack")
if [[ ${#DEGRADED[@]} -gt 0 ]]; then
  echo "---- script-ffi 降级汇总（各语言 flag 已隔离，互不拖挂）----" >&2
  for d in "${DEGRADED[@]}"; do
    echo "  WARN: ${d}" >&2
  done
fi
echo "in-process 解释器可用: ${INPROCESS_OK[*]:-（none）}"
