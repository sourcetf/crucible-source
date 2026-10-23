#!/usr/bin/env bash
# 一条命令、普通用户、幂等：把 Crucible 应用引擎需要的**全部**运行时装到
# ${CRUCIBLE_RUNTIME_ROOT:-$HOME/local}（不碰 /usr、不需要 root）。
#
#   PHP      php-fpm / php-cgi / php-cli
#   Ruby     ruby + ruby-dev（头文件）+ rack gem
#   Java     JDK 17（javac）+ Maven（构建 libs/jsp-sidecar 的 Jetty Fat JAR）
#   Node     node + npm + esbuild（TSX 引擎；esbuild 也可 npm 装到应用 docroot）
#   .NET     dotnet host / hostfxr / runtime / SDK（ASP.NET 引擎与最小 managed 样例）
#   Go       若系统已有 go 则跳过（Linux 上用于 libapp_go.so c-shared）
#
# 安装方式复用 /home/dev123/bin/aptlocal.sh（apt-get download + dpkg-deb -x），
# 依赖递归解析；已存在的系统包跳过。装完写一个可直接 source 的环境文件：
#   $ROOT/crucible-runtimes.env
# 构建脚本（build_app_engines.sh / build_script_ffi.sh / build_jsp_sidecar.sh /
# build_aspnet_ffi.sh / build_axonasp_ffi.sh）会自动 source scripts/runtime_env.sh，
# 因此装完**无需**手工 export 就能重建引擎。
#
# 用法：
#   scripts/install_app_runtimes.sh              # 安装 + 校验（默认）
#   scripts/install_app_runtimes.sh --check      # 只校验，不下载
#   scripts/install_app_runtimes.sh --force      # 已装也重装（修复半截安装）
#   scripts/install_app_runtimes.sh --only php,ruby   # 只处理指定组
#   scripts/install_app_runtimes.sh --allow-missing   # 校验失败只告警（默认非零退出）
#
# 退出码：0 全部就绪；1 有运行时缺失/校验失败（会逐条列出）。
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
RUNTIME_ROOT="${CRUCIBLE_RUNTIME_ROOT:-${HOME}/local}"
APTLOCAL="${APTLOCAL:-${HOME}/bin/aptlocal.sh}"
DO_INSTALL=1
FORCE=0
ALLOW_MISSING=0
ONLY=""
for arg in "$@"; do
  case "${arg}" in
    --check|--verify) DO_INSTALL=0 ;;
    --force) FORCE=1 ;;
    --allow-missing) ALLOW_MISSING=1 ;;
    --only=*) ONLY="${arg#--only=}" ;;
    --only) echo "用法: $0 --only=php,ruby,java,maven,node,perl,dotnet" >&2; exit 2 ;;
    -h|--help)
      sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) echo "WARN: 未知参数 ${arg}（忽略）" >&2 ;;
  esac
done

export CRUCIBLE_RUNTIME_ROOT="${RUNTIME_ROOT}"
# shellcheck source=scripts/runtime_env.sh
. "${ROOT_DIR}/scripts/runtime_env.sh"

log()  { printf '==> %s\n' "$*"; }
warn() { printf 'WARN: %s\n' "$*" >&2; }
err()  { printf 'ERROR: %s\n' "$*" >&2; }
ver_line() { printf '   %-12s %s\n' "$1" "$2"; }

FAILED=()
INSTALLED=()

want_group() {
  [ -z "${ONLY}" ] && return 0
  case ",${ONLY}," in
    *",$1,"*) return 0 ;;
    *) return 1 ;;
  esac
}

pkg_candidate() {
  apt-cache policy "$1" 2>/dev/null | awk '/Candidate:/{print $2; exit}'
}

pkg_ok() {
  local c
  c="$(pkg_candidate "$1")"
  [ -n "${c}" ] && [ "${c}" != "(none)" ]
}

pick_pkg() {
  local p
  for p in "$@"; do
    if pkg_ok "${p}"; then echo "${p}"; return 0; fi
  done
  return 1
}

dpkg_installed() {
  dpkg -s "$1" >/dev/null 2>&1
}

aptlocal_install() {
  local pkg="$1"
  if dpkg_installed "${pkg}"; then
    log "  ${pkg}: 系统已安装（跳过）"
    return 0
  fi
  log "  ${pkg}: 下载 + 解包到 ${RUNTIME_ROOT}"
  if ! "${APTLOCAL}" install-deps "${pkg}" >>"${LOGFILE}" 2>&1; then
    err "aptlocal install-deps ${pkg} 失败（日志 ${LOGFILE}）"
    return 1
  fi
  return 0
}

install_group_pkgs() {
  local group="$1"; shift
  want_group "${group}" || return 0
  local pkg rc=0
  for pkg in "$@"; do
    aptlocal_install "${pkg}" || rc=1
  done
  INSTALLED+=("${group}")
  return ${rc}
}

[ -x "${APTLOCAL}" ] || { err "找不到 ${APTLOCAL}（可设 APTLOCAL=/path/to/aptlocal.sh）"; exit 1; }
mkdir -p "${RUNTIME_ROOT}"
LOGFILE="${RUNTIME_ROOT}/install-app-runtimes.log"
: >>"${LOGFILE}"

# ---------------------------------------------------------------------------
# 1) 选择包（按发行版实际可用版本；Ubuntu 26.04 是 PHP 8.5 / Ruby 3.3 / JDK 17 / .NET 10）
# ---------------------------------------------------------------------------
PHP_VER=""
for v in 8.5 8.4 8.3 8.2; do
  if pkg_ok "php${v}-fpm"; then PHP_VER="${v}"; break; fi
done
if [ -n "${PHP_VER}" ]; then
  PHP_PKGS=("php${PHP_VER}-fpm" "php${PHP_VER}-cli" "php${PHP_VER}-cgi")
else
  PHP_PKGS=("php-fpm" "php-cli" "php-cgi")
fi

JAVA_PKG=""
for p in openjdk-17-jdk-headless openjdk-21-jdk-headless openjdk-25-jdk-headless; do
  if pkg_ok "${p}"; then JAVA_PKG="${p}"; break; fi
done
[ -n "${JAVA_PKG}" ] || JAVA_PKG="openjdk-17-jdk-headless"

DOTNET_VER=""
DOTNET_VER="$(apt-cache search --names-only '^dotnet-hostfxr-[0-9][0-9.]*$' 2>/dev/null \
  | awk '{print $1}' | sed 's/^dotnet-hostfxr-//' | sort -V | tail -n1)"
[ -n "${DOTNET_VER}" ] || DOTNET_VER="10.0"
DOTNET_PKGS=("dotnet-host-${DOTNET_VER}" "dotnet-hostfxr-${DOTNET_VER}" \
             "dotnet-runtime-${DOTNET_VER}" "dotnet-sdk-${DOTNET_VER}")

# ---------------------------------------------------------------------------
# 2) 安装
# ---------------------------------------------------------------------------
if [ "${DO_INSTALL}" = "1" ]; then
  log "运行时根目录: ${RUNTIME_ROOT}"
  log "日志: ${LOGFILE}"

  want_group php && log "PHP: ${PHP_PKGS[*]}"
  install_group_pkgs php "${PHP_PKGS[@]}" || FAILED+=("php install")
  want_group ruby && log "Ruby: ruby ruby-dev ruby-rack"
  install_group_pkgs ruby ruby ruby-dev ruby-rack || FAILED+=("ruby install")
  want_group java && log "JDK: ${JAVA_PKG}"
  install_group_pkgs java "${JAVA_PKG}" || FAILED+=("java install")
  # aptlocal 会跳过「系统已装」的包；系统常常只有 JRE（无 javac）或只有 JDK（无
  # java 运行时）。用户级目录要自包含：强制把同版本 JRE 也解包到 ~/local
  # （`install` 不查 dpkg 状态；解包是幂等的）。
  if want_group java; then
    JRE_PKG="${JAVA_PKG/-jdk-/-jre-}"
    log "JRE: ${JRE_PKG}（强制解包，保证 ~/local 里有 java 运行时）"
    if ! "${APTLOCAL}" install "${JRE_PKG}" >>"${LOGFILE}" 2>&1; then
      warn "解包 ${JRE_PKG} 失败（java 启动器可能缺失；详见 ${LOGFILE}）"
    fi
  fi
  want_group maven && log "Maven: maven"
  install_group_pkgs maven maven || FAILED+=("maven install")
  want_group node && log "Node: nodejs npm esbuild"
  install_group_pkgs node nodejs npm esbuild || FAILED+=("node install")
  # Debian/Ubuntu 的 nodejs 是**非重定位**构建：二进制里编死了
  # /usr/share/nodejs/{cjs-module-lexer,undici,acorn,...}，解到 ~/local 后
  # `npm --version` 直接 abort（Cannot load externalized builtin）。npm 仍需要
  # 用来把 esbuild 装进应用（bundled）；改为下载官方可重定位 tarball：
  #   ~/local/node/{bin/node,bin/npm}
  # 已存在可用 npm 时跳过（幂等）；下载失败只告警（apt 的 esbuild 仍可用于 /tsx/）。
  if want_group node; then
    if [ ! -x "${RUNTIME_ROOT}/node/bin/npm" ] || ! "${RUNTIME_ROOT}/node/bin/npm" --version >/dev/null 2>&1; then
      NODE_VER="${CRUCIBLE_NODE_TARBALL_VERSION:-}"
      if [ -z "${NODE_VER}" ]; then
        NODE_VER="$(pkg_candidate nodejs | sed -E 's/^([0-9]+\.[0-9]+\.[0-9]+).*/\1/' | head -n1)"
      fi
      [ -n "${NODE_VER}" ] || NODE_VER="22.22.1"
      case "$(uname -m)" in
        aarch64|arm64) NODE_ARCH="arm64" ;;
        *) NODE_ARCH="x64" ;;
      esac
      NODE_URL="https://nodejs.org/dist/v${NODE_VER}/node-v${NODE_VER}-linux-${NODE_ARCH}.tar.xz"
      log "Node 官方 tarball: ${NODE_URL}"
      mkdir -p "${RUNTIME_ROOT}/node" "${RUNTIME_ROOT}/.dl"
      if curl -fsSL --retry 2 -o "${RUNTIME_ROOT}/.dl/node.tar.xz" "${NODE_URL}"; then
        rm -rf "${RUNTIME_ROOT}/node"
        mkdir -p "${RUNTIME_ROOT}/node"
        if tar -xJf "${RUNTIME_ROOT}/.dl/node.tar.xz" -C "${RUNTIME_ROOT}/node" --strip-components=1; then
          ver_line "node(tarball)" "$("${RUNTIME_ROOT}/node/bin/node" --version 2>/dev/null)"
          ver_line "npm(tarball)" "$("${RUNTIME_ROOT}/node/bin/npm" --version 2>/dev/null)"
        else
          warn "解包 Node tarball 失败"
        fi
      else
        warn "下载 Node tarball 失败（npm 不可用；esbuild 已由 apt 包提供）"
      fi
    fi
    # TSX 应用自带（bundled）转译器：装到 **docroot/node_modules**，不放 deps/
    #（deps/ 每次 ensure 都会整体 wipe）。引擎探测顺序 PATH → docroot/node_modules/.bin
    # → deps/node_modules/.bin；这样即使宿主没有全局 esbuild，/tsx/ 也能编译。
    TSX_APP="${ROOT_DIR}/www-apps/tsx"
    if [ -d "${TSX_APP}" ] && [ ! -x "${TSX_APP}/node_modules/.bin/esbuild" ]; then
      NPM_BIN="${RUNTIME_ROOT}/node/bin/npm"
      [ -x "${NPM_BIN}" ] || NPM_BIN="$(command -v npm 2>/dev/null || true)"
      if [ -n "${NPM_BIN}" ]; then
        log "bundling esbuild into ${TSX_APP}/node_modules"
        "${NPM_BIN}" install --prefix "${TSX_APP}" --no-save --no-package-lock \
          --no-audit --no-fund --silent esbuild >>"${LOGFILE}" 2>&1 || \
          warn "npm install esbuild 到 ${TSX_APP} 失败（/tsx/ 仍可用全局 esbuild）"
      fi
    fi
  fi
  # Perl：系统 perl 运行时通常已有，但**缺 libperl.so 开发符号链接** ⇒
  # build_script_ffi 的 -lperl 试链失败 ⇒ /perl/ /psgi/ 降级 502。
  # libperl-dev 提供 libperl.so + libperl.a；libperl5.40 提供版本化 .so
  # （aptlocal 会跳过系统已装的包，所以强制解包一次）。
  want_group perl && log "Perl dev: libperl-dev (+ libperl5.40)"
  if want_group perl; then
    install_group_pkgs perl libperl-dev || FAILED+=("perl install")
    PERL_VER="$(ls -1 /home/dev123/aptdl/libperl5.*_*.deb 2>/dev/null | sed -n 's/.*libperl5\.\([0-9][0-9]*\).*/\1/p' | sort -V | tail -n1)"
    if [ -n "${PERL_VER}" ]; then
      "${APTLOCAL}" install "libperl5.${PERL_VER}" >>"${LOGFILE}" 2>&1 || \
        warn "强制解包 libperl5.${PERL_VER} 失败（perl/psgi 可能仍 502）"
    fi
  fi
  want_group dotnet && log ".NET: ${DOTNET_PKGS[*]}"
  install_group_pkgs dotnet "${DOTNET_PKGS[@]}" || FAILED+=("dotnet install")
fi

# ---------------------------------------------------------------------------
# 3) 兼容符号链接（Debian 用 update-alternatives，用户级解包不会创建 php/php-fpm）
# ---------------------------------------------------------------------------
link_first() {
  # link_first <dest-link> <candidate...>
  local dest="$1"; shift
  [ -e "${dest}" ] && return 0
  local c
  for c in "$@"; do
    if [ -x "${c}" ]; then
      ln -sfn "$(basename "${c}")" "${dest}"
      return 0
    fi
  done
  return 1
}
if [ -d "${RUNTIME_ROOT}/usr/bin" ]; then
  link_first "${RUNTIME_ROOT}/usr/bin/php" "${RUNTIME_ROOT}"/usr/bin/php[0-9]* || true
  link_first "${RUNTIME_ROOT}/usr/bin/php-cgi" "${RUNTIME_ROOT}"/usr/bin/php-cgi[0-9]* || true
  link_first "${RUNTIME_ROOT}/usr/sbin/php-fpm" "${RUNTIME_ROOT}"/usr/sbin/php-fpm[0-9]* || true
  link_first "${RUNTIME_ROOT}/usr/bin/ruby" "${RUNTIME_ROOT}"/usr/bin/ruby3.* || true
  # Maven 包只有 /usr/share/maven/bin/mvn（没有 /usr/bin/mvn 符号链接）。
  if [ -x "${RUNTIME_ROOT}/usr/share/maven/bin/mvn" ] && [ ! -e "${RUNTIME_ROOT}/usr/bin/mvn" ]; then
    ln -sfn ../share/maven/bin/mvn "${RUNTIME_ROOT}/usr/bin/mvn"
  fi
  # Debian 的 maven 用**绝对**符号链接指向 /etc/maven（conf、bin/m2.conf）；
  # 解到 ~/local 后这些绝对链接指向不存在的系统路径 ⇒ mvn 启动即
  # NoSuchFileException。改成指向解包树内的 etc/maven。
  MAVEN_HOME_DIR="${RUNTIME_ROOT}/usr/share/maven"
  if [ -d "${MAVEN_HOME_DIR}" ]; then
    if [ -L "${MAVEN_HOME_DIR}/conf" ] && [ ! -d "${MAVEN_HOME_DIR}/conf" ]; then
      rm -f "${MAVEN_HOME_DIR}/conf"
      ln -sfn ../../../etc/maven "${MAVEN_HOME_DIR}/conf"
    fi
    if [ -L "${MAVEN_HOME_DIR}/bin/m2.conf" ] && [ ! -f "${MAVEN_HOME_DIR}/bin/m2.conf" ]; then
      rm -f "${MAVEN_HOME_DIR}/bin/m2.conf"
      cp -f "${RUNTIME_ROOT}/etc/maven/m2.conf" "${MAVEN_HOME_DIR}/bin/m2.conf" 2>/dev/null || true
    fi
  fi
  # npm/npx 在 Debian 包里是 share/nodejs/npm/bin/*.js；没有 /usr/bin 入口时补链接。
  if [ -f "${RUNTIME_ROOT}/usr/share/nodejs/npm/bin/npm-cli.js" ] && [ ! -e "${RUNTIME_ROOT}/usr/bin/npm" ]; then
    ln -sfn ../share/nodejs/npm/bin/npm-cli.js "${RUNTIME_ROOT}/usr/bin/npm"
    chmod +x "${RUNTIME_ROOT}/usr/share/nodejs/npm/bin/npm-cli.js" 2>/dev/null || true
  fi
  if [ -f "${RUNTIME_ROOT}/usr/share/nodejs/npm/bin/npx-cli.js" ] && [ ! -e "${RUNTIME_ROOT}/usr/bin/npx" ]; then
    ln -sfn ../share/nodejs/npm/bin/npx-cli.js "${RUNTIME_ROOT}/usr/bin/npx"
    chmod +x "${RUNTIME_ROOT}/usr/share/nodejs/npm/bin/npx-cli.js" 2>/dev/null || true
  fi
  [ -x "${RUNTIME_ROOT}/usr/lib/dotnet/dotnet" ] && \
    link_first "${RUNTIME_ROOT}/usr/bin/dotnet" "${RUNTIME_ROOT}/usr/lib/dotnet/dotnet" || true
fi

# 重新应用一次（新装的 javac/dotnet 现在才存在）。
crucible_runtime_apply

# rack gem：发行版 ruby-rack 装到 vendor_ruby；若 require 失败，用 --user-install 补。
if want_group ruby && command -v ruby >/dev/null 2>&1; then
  if ! ruby -e 'require "rack"; print Rack.release' >/dev/null 2>&1; then
    if command -v gem >/dev/null 2>&1; then
      log "rack gem 不可加载 → gem install --user-install rack"
      gem install --user-install --no-document rack >>"${LOGFILE}" 2>&1 || \
        warn "gem install rack 失败（详见 ${LOGFILE}）"
      # 让 GEM_PATH 包含 --user-install 目录
      rv="$(ruby -e 'print RbConfig::CONFIG["ruby_version"]' 2>/dev/null || true)"
      [ -n "${rv}" ] && export GEM_PATH="${HOME}/.local/share/gem/ruby/${rv}${GEM_PATH:+:${GEM_PATH}}"
    else
      warn "gem 不存在，无法补装 rack"
    fi
  fi
fi

# ---------------------------------------------------------------------------
# 4) 写环境文件（构建/运行脚本可直接 source）
# ---------------------------------------------------------------------------
ENV_FILE="${RUNTIME_ROOT}/crucible-runtimes.env"
{
  echo "# generated by scripts/install_app_runtimes.sh ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
  echo "# source this before building/running app engines (or use scripts/runtime_env.sh)"
  echo "export CRUCIBLE_RUNTIME_ROOT=\"${RUNTIME_ROOT}\""
  echo ". \"${ROOT_DIR}/scripts/runtime_env.sh\""
} >"${ENV_FILE}"

# ---------------------------------------------------------------------------
# 5) 校验（真实执行，不是只看文件存在）
# ---------------------------------------------------------------------------
CHECK_FAIL=0
have() { command -v "$1" >/dev/null 2>&1; }

log "运行时校验（${RUNTIME_ROOT}）"

if want_group php; then
  if have php && have php-fpm; then
    ver_line "php" "$(php -v 2>/dev/null | head -n1)"
    ver_line "php-fpm" "$(php-fpm -v 2>/dev/null | head -n1)"
    if have php-cgi; then ver_line "php-cgi" "$(php-cgi -v 2>/dev/null | head -n1)"; fi
  else
    err "PHP 不可用（php=$(command -v php || echo missing) php-fpm=$(command -v php-fpm || echo missing)）"
    CHECK_FAIL=1
  fi
fi

if want_group ruby; then
  if have ruby; then
    ver_line "ruby" "$(ruby -e 'print RUBY_DESCRIPTION' 2>/dev/null)"
    if ruby -e 'require "rack"; print Rack.release' >/dev/null 2>&1; then
      ver_line "rack" "$(ruby -e 'require "rack"; print Rack.release' 2>/dev/null)"
    else
      err "rack gem 不可加载（ruby -e 'require \"rack\"' 失败）"
      CHECK_FAIL=1
    fi
    if have gem; then ver_line "gem" "$(gem --version 2>/dev/null)"; fi
  else
    err "ruby 不可用"
    CHECK_FAIL=1
  fi
fi

if want_group perl; then
  if have perl; then
    ver_line "perl" "$(perl -v 2>/dev/null | sed -n 's/.*This is perl .* (v\([0-9.]*\)).*/v\1/p' | head -n1)"
    PERL_SO="$(ls -1 "${RUNTIME_ROOT}"/usr/lib/x86_64-linux-gnu/libperl.so 2>/dev/null | head -n1)"
    if [ -n "${PERL_SO}" ]; then
      ver_line "libperl.so" "${PERL_SO}"
    else
      err "libperl.so 缺失（/perl/ /psgi/ 会降级 502；装 libperl-dev）"
      CHECK_FAIL=1
    fi
  else
    err "perl 解释器不可用"
    CHECK_FAIL=1
  fi
fi

if want_group java; then
  if [ -n "${JAVA_HOME:-}" ] && [ -x "${JAVA_HOME}/bin/javac" ] && [ -x "${JAVA_HOME}/bin/java" ]; then
    ver_line "javac" "$("${JAVA_HOME}/bin/javac" -version 2>&1 | head -n1)"
    ver_line "java" "$("${JAVA_HOME}/bin/java" -version 2>&1 | head -n1)"
  else
    err "JDK(javac) 不可用（JAVA_HOME=${JAVA_HOME:-unset}）"
    CHECK_FAIL=1
  fi
fi

if want_group maven; then
  if have mvn; then
    ver_line "mvn" "$(mvn -v 2>/dev/null | head -n1)"
  else
    err "mvn 不可用"
    CHECK_FAIL=1
  fi
fi

if want_group node; then
  if have node; then ver_line "node" "$(node --version 2>/dev/null)"; else err "node 不可用"; CHECK_FAIL=1; fi
  if have npm; then ver_line "npm" "$(npm --version 2>/dev/null)"; else err "npm 不可用"; CHECK_FAIL=1; fi
  if have esbuild; then ver_line "esbuild" "$(esbuild --version 2>/dev/null)"; else err "esbuild 不可用"; CHECK_FAIL=1; fi
fi

if want_group dotnet; then
  if have dotnet; then
    ver_line "dotnet" "$(dotnet --version 2>/dev/null || echo sdk-missing)"
  else
    err "dotnet 不可用"
    CHECK_FAIL=1
  fi
  HOSTFXR="$(ls -1 "${DOTNET_ROOT:-/nonexistent}"/host/fxr/*/libhostfxr.so 2>/dev/null | sort -V | tail -n1)"
  if [ -n "${HOSTFXR}" ]; then
    ver_line "hostfxr" "${HOSTFXR}"
  else
    err "libhostfxr.so 未找到（DOTNET_ROOT=${DOTNET_ROOT:-unset}）"
    CHECK_FAIL=1
  fi
fi

if have go; then ver_line "go" "$(go version 2>/dev/null)"; else warn "go 不在 PATH（Linux 的 libapp_go.so c-shared 需要）"; fi

echo
echo "环境文件: ${ENV_FILE}"
echo "构建前:  . ${ENV_FILE}     （或依赖构建脚本内自动 source runtime_env.sh）"

if [ "${CHECK_FAIL}" -ne 0 ] || [ "${#FAILED[@]}" -gt 0 ]; then
  echo
  err "以下运行时/步骤未就绪："
  for f in "${FAILED[@]}"; do echo "   - ${f}"; done
  [ "${CHECK_FAIL}" -ne 0 ] && echo "   - 校验失败项见上方 ERROR"
  echo "   日志: ${LOGFILE}"
  if [ "${ALLOW_MISSING}" = "1" ]; then
    warn "--allow-missing：降级为警告继续。"
    exit 0
  fi
  exit 1
fi

log "全部运行时就绪。"
