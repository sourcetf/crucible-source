# App engines

Modular `.so` engines loaded via `dlopen(RTLD_GLOBAL)`.

ABI: `include/appengine.h`

Discovery: `apps[].lib` → `APPENGINE_<NAME>_LIB` → `target/app-engines/libapp_<name>.so`

## Platform notes

| engine | Linux (default) | OpenBSD |
|--------|-----------------|---------|
| c/rust | in-process FFI `.so` | in-process FFI `.so` |
| go | in-process FFI `libapp_go.so` (c-shared) | **Unix HTTP sidecar** `www-apps/go/deps/bin/index` (c-shared unavailable) |
| lua | PUC-Lua + ngx.say/header when headers found (`CRUCIBLE_HAVE_LUA`) | same |
| python/ruby/perl | `libapp_*.so`，`script_engine.c` 进程内嵌入（`build_script_ffi.sh` 探测并加 `CRUCIBLE_HAVE_*`）；缺头文件则该语言显式失败（无 popen） | same |
| wsgi/asgi/uwsgi | `libapp_*.so`，**进程内嵌入 CPython**（`common/crucible_pyembed.h`：运行时 dlopen libpython + dlsym 解析 C API；应用异常 → 500 + traceback） | same（宿主有 libpython3.13 即可用） |
| psgi | 定义 `CRUCIBLE_HAVE_PERL` 时进程内嵌入 Perl；未定义则显式报 "not built with embedded Perl"（无 popen） | same（需在构建脚本里加 `perl -MExtUtils::Embed` 的 ccopts/ldopts） |
| rack | 未嵌入 MRI Ruby：显式报错（本机无 ruby/libruby；需 `pkg-config ruby` + `-DCRUCIBLE_HAVE_RUBY`） | same |
| cgi | fork + `execve`（真实 argv，无 shell 字符串；stdin=body、stderr→错误文本、30s 超时） | same |
| tsx | 不按请求执行：契约是"一键编译 + watch 部署"或 node 侧车（见 `src/server/apps/tsx.rs`）；本引擎只给显式错误 | same |
| asp | AxonASP `libapp_asp.so` | same |
| aspnet | hostfxr stub `libapp_aspnet.so` | same |
| jsp | Python UDS HTTP sidecar | same |

Go on OpenBSD: set `GO_ENGINE_MODE=shm` or use sidecar; c-shared may be unavailable. **No CGI fallback for missing engines (502).**

解释器类引擎（python/ruby/perl/wsgi/asgi/uwsgi/psgi/rack）禁止每请求 spawn（"能 FFI 就不 spawn"）：
失败一律 `rc != 0` + `error` 文本（502），绝不用 `appengine_fill_hello` 假装成功——该函数现在只有
`libapp_c.so` 这个 hello-world 样例在用。

Build: `bash scripts/build_app_engines.sh` → `target/app-engines/libapp_*.so` (+ script/aspnet/axonasp/jsp helpers)
