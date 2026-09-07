# Optional Lua vendor amalgam

If system Lua headers are missing, place a PUC-Lua amalgam here:

- `lua.h`, `lauxlib.h`, `lualib.h`, `luaconf.h` (and friends)
- `onelua.c` (or equivalent single-translation-unit build)

`scripts/build_app_engines.sh` will detect this directory and compile
`libapp_lua.so` with `-DCRUCIBLE_HAVE_LUA`. Without it, the engine builds a
clear stub that reports missing headers in the response.
