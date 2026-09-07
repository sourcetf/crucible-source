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
| python/ruby/perl | `libapp_*.so` via scriptffi popen | same |
| wsgi/asgi/psgi/rack/cgi/uwsgi/tsx | interpreter file-exec engines | same |
| asp | AxonASP `libapp_asp.so` | same |
| aspnet | hostfxr stub `libapp_aspnet.so` | same |
| jsp | Python UDS HTTP sidecar | same |

Go on OpenBSD: set `GO_ENGINE_MODE=shm` or use sidecar; c-shared may be unavailable. **No CGI fallback for missing engines (502).**

Build: `bash scripts/build_app_engines.sh` → `target/app-engines/libapp_*.so` (+ script/aspnet/axonasp/jsp helpers)
