#!/bin/sh
# Rack app engine — 常驻 sidecar（deps/bin/index）。
#
# 为什么不是 libapp_rack.so 嵌入 MRI：OpenBSD 上把 MRI 嵌进多线程宿主会在 boot/
# 请求期崩掉整个 webserver（见 libs/app-engines/rack/rack_engine.c 与
# scripts/build_script_ffi.sh 的说明），该平台默认只产出「诚实失败」stub。
# 这里生成 deps/bin/index，让 native_http 拉起**一次、长期驻留**的 sidecar.rb：
# 不是 per-request spawn（不是 CGI），崩溃也不会带走 webserver。
#
# 与 www-apps/ruby/init.sh 同款：PATH 优先，其次用户级运行时（scripts/
# install_app_runtimes.sh → ~/local）的绝对路径。deps/ 是 docroot 级的（多个
# webserver 实例共用同一份 www-apps 时会互相 rebuild）；别的实例若没把 ~/local
# 放进 PATH，它跑本 init.sh 会写「no ruby interpreter」并删掉 deps/bin/index，
# 把本机已经可用的 /rack/ 打回 502。
set -e
ROOT="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "${ROOT}/deps/bin"

RUBY_BIN=""
# PATH 优先；其次用户级运行时（scripts/install_app_runtimes.sh → ~/local）的
# 绝对路径。OpenBSD 的 ruby 端口装的是版本化二进制（ruby34/ruby33…），没有
# `ruby` 这个名字。
for cand in ruby ruby34 ruby3.4 ruby33 ruby3.3 ruby32 ruby3.2 ruby31 ruby3.1 \
            /usr/local/bin/ruby34 /usr/local/bin/ruby \
            "${HOME}/local/usr/bin/ruby" "${HOME}"/local/usr/bin/ruby3.*; do
  if command -v "${cand}" >/dev/null 2>&1; then RUBY_BIN="$(command -v "${cand}")"; break; fi
done

if [ -z "${RUBY_BIN}" ] || [ ! -f "${ROOT}/sidecar.rb" ]; then
  if [ -z "${RUBY_BIN}" ]; then
    echo "rack: no ruby interpreter found (pkg_add ruby34) — sidecar unavailable" \
      > "${ROOT}/deps/manifest.txt"
  else
    echo "rack: sidecar.rb missing — sidecar unavailable" > "${ROOT}/deps/manifest.txt"
  fi
  # 不生成 deps/bin/index ⇒ 分派给出诚实的 502（或继续走可用的嵌入 .so），
  # 而不是留下一个必然失败的包装脚本。
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
# 由 www-apps/rack/init.sh 生成：${RUBY_BIN} 常驻 Rack sidecar（UDS）
${LD_LINE}
${RUBYLIB_LINE}
exec "${RUBY_BIN}" "${ROOT}/sidecar.rb"
EOF
chmod +x "${ROOT}/deps/bin/index"
echo "rack: sidecar ${RUBY_BIN} sidecar.rb (socket from WEBSERVER_LISTEN_UNIX)" \
  > "${ROOT}/deps/manifest.txt"
