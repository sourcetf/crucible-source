#!/bin/sh
# Ruby app engine — 常驻 sidecar（deps/bin/index）。
#
# 为什么不是 libapp_ruby.so：MRI 嵌入在 OpenBSD + Ruby 3.4 上 boot 阶段就崩
# （见 libs/script-ffi/script_engine.c 与 scripts/build_script_ffi.sh 的说明）。
# 这里生成 deps/bin/index，让 native_http 拉起**一次、长期驻留**的 sidecar.rb：
# 不是 per-request spawn（不是 CGI），崩溃也不会带走 webserver。
set -e
ROOT="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "${ROOT}/deps/bin"

RUBY_BIN=""
# PATH 优先；其次用户级运行时（scripts/install_app_runtimes.sh → ~/local）的
# 绝对路径。**为什么需要绝对兜底**：deps/ 是 docroot 级的（多个 webserver 实例
# 共用同一个 www-apps 时会互相 rebuild）；别的实例若没有把 ~/local 放进 PATH，
# 它跑本 init.sh 会写「no ruby interpreter」并删掉 deps/bin/index，把本机已经
# 可用的 /ruby/ 打回 502（本机 2026-10-23 真机遇到）。
for cand in ruby ruby34 ruby33 ruby32 ruby31 \
            /usr/local/bin/ruby34 /usr/local/bin/ruby \
            "${HOME}/local/usr/bin/ruby" "${HOME}"/local/usr/bin/ruby3.*; do
  if command -v "${cand}" >/dev/null 2>&1; then RUBY_BIN="$(command -v "${cand}")"; break; fi
done

if [ -z "${RUBY_BIN}" ]; then
  echo "ruby: no ruby interpreter found (pkg_add ruby34) — sidecar unavailable" \
    > "${ROOT}/deps/manifest.txt"
  # 不生成 deps/bin/index ⇒ 分派给出诚实的 502，而不是留下一个必然失败的包装脚本。
  rm -f "${ROOT}/deps/bin/index"
  exit 0
fi

# 用户级 Ruby（aptlocal 解到 ~/local）是**非重定位**构建：libruby 不在系统
# loader 路径、stdlib 的 $LOAD_PATH 也硬编码 /usr/lib/ruby。sidecar 由宿主以
# 「启动期基底 env」spawn；若启动实例的运维没 export LD_LIBRARY_PATH/RUBYLIB，
# 直接跑 ~/local/usr/bin/ruby 会 `libruby-3.3.so.3.3: cannot open shared object`。
# 把关卡写进生成的 wrapper（只在本机确实存在 ~/local 时启用），sidecar 就自包含。
RV=""
LOCAL_LD=""
LOCAL_RUBYLIB=""
if [ -d "${HOME}/local/usr/lib/x86_64-linux-gnu" ]; then
  LOCAL_LD="${HOME}/local/usr/lib/x86_64-linux-gnu:${HOME}/local/usr/lib"
fi
# 探版本时必须先带上 LOCAL_LD：用户级 ruby 的 libruby 不在系统 loader 路径，
# 否则 `ruby -v` 本身就跑不起来（RV 为空 → RUBYLIB 判断失效）。
if [ -n "${LOCAL_LD}" ]; then
  RV="$(LD_LIBRARY_PATH="${LOCAL_LD}${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
        "${RUBY_BIN}" -v 2>/dev/null | sed -n 's/^ruby \([0-9][0-9]*\.[0-9][0-9]*\).*/\1/p')"
else
  RV="$("${RUBY_BIN}" -v 2>/dev/null | sed -n 's/^ruby \([0-9][0-9]*\.[0-9][0-9]*\).*/\1/p')"
fi
if [ -n "${RV}" ] && [ -d "${HOME}/local/usr/lib/ruby/${RV}.0" ]; then
  LOCAL_RUBYLIB="${HOME}/local/usr/lib/ruby/${RV}.0:${HOME}/local/usr/lib/ruby/vendor_ruby/${RV}.0:${HOME}/local/usr/lib/ruby/vendor_ruby:${HOME}/local/usr/lib/x86_64-linux-gnu/ruby/${RV}.0"
fi
LD_LINE=""
RUBYLIB_LINE=""
[ -n "${LOCAL_LD}" ] && LD_LINE="LD_LIBRARY_PATH=\"${LOCAL_LD}\${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}\"; export LD_LIBRARY_PATH"
[ -n "${LOCAL_RUBYLIB}" ] && RUBYLIB_LINE="RUBYLIB=\"${LOCAL_RUBYLIB}\${RUBYLIB:+:\$RUBYLIB}\"; export RUBYLIB"

cat > "${ROOT}/deps/bin/index" <<EOF
#!/bin/sh
# 由 www-apps/ruby/init.sh 生成：${RUBY_BIN} 常驻 sidecar（UDS）
${LD_LINE}
${RUBYLIB_LINE}
exec "${RUBY_BIN}" "${ROOT}/sidecar.rb"
EOF
chmod +x "${ROOT}/deps/bin/index"
echo "ruby: sidecar ${RUBY_BIN} sidecar.rb (socket from WEBSERVER_LISTEN_UNIX)" \
  > "${ROOT}/deps/manifest.txt"
