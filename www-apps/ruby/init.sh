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
for cand in ruby ruby34 ruby33 ruby32 ruby31 /usr/local/bin/ruby34 /usr/local/bin/ruby; do
  if command -v "${cand}" >/dev/null 2>&1; then RUBY_BIN="$(command -v "${cand}")"; break; fi
done

if [ -z "${RUBY_BIN}" ]; then
  echo "ruby: no ruby interpreter found (pkg_add ruby34) — sidecar unavailable" \
    > "${ROOT}/deps/manifest.txt"
  # 不生成 deps/bin/index ⇒ 分派给出诚实的 502，而不是留下一个必然失败的包装脚本。
  rm -f "${ROOT}/deps/bin/index"
  exit 0
fi

cat > "${ROOT}/deps/bin/index" <<EOF
#!/bin/sh
# 由 www-apps/ruby/init.sh 生成：${RUBY_BIN} 常驻 sidecar（UDS）
exec "${RUBY_BIN}" "${ROOT}/sidecar.rb"
EOF
chmod +x "${ROOT}/deps/bin/index"
echo "ruby: sidecar ${RUBY_BIN} sidecar.rb (socket from WEBSERVER_LISTEN_UNIX)" \
  > "${ROOT}/deps/manifest.txt"
