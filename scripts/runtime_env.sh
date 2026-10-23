# shellcheck shell=bash
# 用户级应用运行时的统一环境发现（由 scripts/install_app_runtimes.sh 安装到
# ${CRUCIBLE_RUNTIME_ROOT:-$HOME/local}）。
#
# 用法：在 bash 构建/运行脚本里 `. "$ROOT/scripts/runtime_env.sh"`。
# 只导出环境、不打印、不修改仓库文件；可重复 source（幂等）。
#
# 为什么需要：aptlocal.sh 把 deb 解到 ~/local，但不会（也无权）改 /etc/ld.so.conf 或
# /usr/bin 里的 alternatives。因此 php-fpm/ruby/libruby/java/node/npm/dotnet 这些
# 运行时必须靠 PATH / LD_LIBRARY_PATH / JAVA_HOME / DOTNET_ROOT 被发现；否则：
#   * php.rs 只在 PATH 里找 php-fpm（找不到就 502）；
#   * libapp_rack.so 的 DT_NEEDED=libruby-3.3.so.1 加载失败（dlopen 报错）；
#   * mvn 找不到 JDK；aspnet_engine dlopen("libhostfxr.so") 失败退化成 mini。
#
# 已存在的 JAVA_HOME / DOTNET_ROOT **优先**（不覆盖运维显式设置）。

crucible_runtime_root() {
  printf '%s\n' "${CRUCIBLE_RUNTIME_ROOT:-${HOME:-/root}/local}"
}

crucible_runtime_fix_layout() {
  local root m
  root="$(crucible_runtime_root)"
  [ -d "${root}" ] || return 0
  # Debian maven 包用**绝对**符号链接指向 /etc/maven：在 ~/local 里是悬空的。
  # aptlocal 每次 install 都会重新解包（把修好的链接覆盖回绝对链接），所以这里
  # 每次 apply 都自愈一次（幂等、只动 ~/local，不碰系统）。
  m="${root}/usr/share/maven"
  if [ -d "${m}" ]; then
    if [ -L "${m}/bin/m2.conf" ] && [ ! -f "${m}/bin/m2.conf" ]; then
      rm -f "${m}/bin/m2.conf"
      [ -f "${root}/etc/maven/m2.conf" ] && cp -f "${root}/etc/maven/m2.conf" "${m}/bin/m2.conf"
    fi
    if [ -L "${m}/conf" ] && [ ! -d "${m}/conf" ]; then
      rm -f "${m}/conf"
      ln -sfn ../../../etc/maven "${m}/conf"
    fi
  fi
  return 0
}

crucible_runtime_apply() {
  local root multi binpath
  root="$(crucible_runtime_root)"
  [ -d "${root}" ] || return 0

  multi="${root}/usr/lib/x86_64-linux-gnu"
  binpath="${root}/usr/bin:${root}/usr/sbin:${root}/bin"
  case ":${PATH:-}:" in
    *":${root}/usr/bin:"*) : ;;
    *) PATH="${binpath}:${PATH:-/usr/local/bin:/usr/bin:/bin}" ;;
  esac
  # 官方 Node tarball（install_app_runtimes.sh 下载到 ~/local/node）：Debian/
  # Ubuntu 的 nodejs/npm 包把共享内置模块路径编死成 /usr/share/nodejs，解到
  # ~/local 后 npm 会 abort（Cannot load externalized builtin…）。官方 tarball
  # 是可重定位的，**必须排在 ~/local/usr/bin 之前**（后者也有 node/npm）。
  if [ -x "${root}/node/bin/node" ]; then
    case ":${PATH:-}:" in
      *":${root}/node/bin:"*) : ;;
      *) PATH="${root}/node/bin:${PATH:-/usr/local/bin:/usr/bin:/bin}" ;;
    esac
  fi
  export PATH

  # 共享库：多架构目录 + usr/lib + 每个 JVM 的 lib/lib/server（java 启动器用
  # RPATH=$ORIGIN/../lib，但 libjli 再链接的 libjava 等仍依赖这里的目录）。
  local ld="${multi}:${root}/usr/lib"
  local j
  if [ -d "${root}/usr/lib/jvm" ]; then
    for j in "${root}"/usr/lib/jvm/*; do
      if [ -d "${j}/lib" ]; then
        ld="${ld}:${j}/lib:${j}/lib/server"
      fi
    done
  fi
  export LD_LIBRARY_PATH="${ld}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"

  export PKG_CONFIG_PATH="${multi}/pkgconfig:${root}/usr/share/pkgconfig:${root}/usr/lib/pkgconfig${PKG_CONFIG_PATH:+:${PKG_CONFIG_PATH}}"

  # JAVA_HOME：显式值优先（但必须真有 javac，否则退回探测）。
  if [ -z "${JAVA_HOME:-}" ] || [ ! -x "${JAVA_HOME:-}/bin/javac" ]; then
    local cand
    for cand in "${root}"/usr/lib/jvm/* /usr/lib/jvm/*; do
      if [ -x "${cand}/bin/javac" ]; then
        JAVA_HOME="${cand}"
      fi
    done
    [ -n "${JAVA_HOME:-}" ] && export JAVA_HOME
  fi
  if [ -n "${JAVA_HOME:-}" ] && [ -d "${JAVA_HOME}/bin" ]; then
    case ":${PATH:-}:" in
      *":${JAVA_HOME}/bin:"*) : ;;
      *) PATH="${JAVA_HOME}/bin:${PATH}" ;;
    esac
    export PATH
  fi

  # DOTNET_ROOT：hostfxr 位于 $DOTNET_ROOT/host/fxr/<ver>/libhostfxr.so。
  if [ -z "${DOTNET_ROOT:-}" ] || [ ! -d "${DOTNET_ROOT:-}/host/fxr" ]; then
    local d
    for d in "${root}/usr/lib/dotnet" "${root}/usr/share/dotnet" /usr/lib/dotnet /usr/share/dotnet; do
      if [ -d "${d}/host/fxr" ]; then
        DOTNET_ROOT="${d}"
        export DOTNET_ROOT
        break
      fi
    done
  fi
  if [ -n "${DOTNET_ROOT:-}" ]; then
    export DOTNET_ROOT_X64="${DOTNET_ROOT}"
  fi

  # Ruby：Debian/Ubuntu 的 ruby 是**非重定位**构建（$LOAD_PATH 硬编码 /usr/lib/ruby/
  # 3.3.0），用 aptlocal 解到 ~/local 后直接运行会报 "RubyGems were not loaded"，
  # rack 也 require 不到。用户级修法是 RUBYLIB 指向解包目录（不改系统）。
  # 只在目录真实存在时添加，不影响 OpenBSD/系统 ruby 的原生查找。
  local ruby_ver="" d
  if command -v ruby >/dev/null 2>&1; then
    ruby_ver="$(ruby -v 2>/dev/null | sed -n 's/^ruby \([0-9][0-9]*\.[0-9][0-9]*\).*/\1/p')"
    if [ -n "${ruby_ver}" ]; then
      local rb_ver="${ruby_ver}.0" rubylib="" rdir
      for rdir in \
        "${root}/usr/lib/ruby/${rb_ver}" \
        "${root}/usr/lib/ruby/vendor_ruby/${rb_ver}" \
        "${root}/usr/lib/ruby/vendor_ruby" \
        "${root}/usr/lib/x86_64-linux-gnu/ruby/${rb_ver}" \
        "${root}/usr/local/lib/site_ruby/${rb_ver}" \
        "${root}/usr/local/lib/site_ruby"; do
        if [ -d "${rdir}" ]; then
          rubylib="${rubylib:+${rubylib}:}${rdir}"
        fi
      done
      if [ -n "${rubylib}" ]; then
        case ":${RUBYLIB:-}:" in
          *":${root}/usr/lib/ruby/${rb_ver}:"*) : ;;
          *) export RUBYLIB="${rubylib}${RUBYLIB:+:${RUBYLIB}}" ;;
        esac
      fi
      ruby_ver="${rb_ver}"
    fi
  fi

  # Ruby gems（rack 等 --user-install / 发行版包都放进来）。
  if [ -d "${root}/usr/lib/ruby/gems" ] || [ -d "${HOME}/.local/share/gem" ]; then
    local rv="${ruby_ver}" gems=""
    for d in "${root}"/usr/lib/ruby/gems/*/ "${root}/usr/share/rubygems-integration/all/" "${HOME}"/.local/share/gem/ruby/*/; do
      [ -d "${d}" ] || continue
      case ":${GEM_PATH:-}:" in
        *":${d%/}:"*) continue ;;
      esac
      gems="${gems:+${gems}:}${d%/}"
    done
    if [ -n "${rv}" ]; then
      case ":${gems}:" in
        *":${HOME}/.local/share/gem/ruby/${rv}:"*) : ;;
        *) gems="${gems:+${gems}:}${HOME}/.local/share/gem/ruby/${rv}" ;;
      esac
    fi
    if [ -n "${gems}" ]; then
      export GEM_PATH="${gems}${GEM_PATH:+:${GEM_PATH}}"
    fi
  fi
  crucible_runtime_fix_layout
  return 0
}

crucible_runtime_apply
