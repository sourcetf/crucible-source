# Crucible 复刻进度（对照 webserver-rebuild-prompt-v2.txt §13）

## Phase 0 configure/make — DONE
- [x] `./configure` `--target=linux|openbsd|auto`
- [x] `config.mk` + `build/crucible-build.toml`
- [x] `Makefile` all/engines/release/test
- [x] `build.rs` cfg flags

## §13-1 Skeleton — DONE
- [x] `[[admin.users]]`、`file_open` 内联数组、`http_versions`、`AutoindexConfig`
- [x] `allows_h1/h2/h3`、`would_execute_on_get` / `script_rel` 单测
- [x] 多 listener + 静态 + 热重载
- [x] **测试非标端口** `config-test.toml`: 19095/19081/19445/19446/18443

## §13-2 H1/H2 — DONE (knobs + framed_write layer)
- [x] BATCH_CAP=16、max_send_buffer=128KiB、COALESCE_WRITES_DEFAULT
- [x] `libs/h2` framed_write BatchWriter + proto/connection settings（薄封装 + 本地 knobs）
- [x] linux busy_poll feature-gated
- [x] sweep_batch_cap on :19081

## §13-3 TLS — DONE (three-stack + soft-drop)
- [x] BoringSSL 主路径 + ECH/PQC/双证
- [x] ClientHello 分流 → Boring / NSS / TomCrypt
- [x] Incomplete SSLv2 probe → Boring soft-route（禁 TomCrypt ARGCHK abort）
- [x] TomCrypt ARGTYPE=2 + ltm_desc 强制 vendored
- [x] NSS shim（SSLv3 / IE6 v2-compatible）
- [x] QUIC crypto 全量 Boring provider（vendored quinn-btls→boring；rustls 仅作失败回退）

## §13-4 H3 — DONE (serve path)
- [x] UDP bind + quinn + h3 request loop（apps/static/page_rules）
- [x] quinn-boring peer_identity / PEM chain parse
- [x] BoringQuicConfig try_build 校验（transport 仍 rustls）

## §13-5 Admin — DONE
- [x] 12 tabs + catalog + geoip APIs

## §13-6 Apps — DONE (matrix + hard Lua)
- [x] go shm (OpenBSD) + FFI (Linux)
- [x] PUC-Lua vendor amalgam + **禁 stub**（build/accept hard gate）
- [x] axonasp / aspnet / script-ffi / jsp-sidecar（**Java/Jetty jar 优先**，Python 仅无 JDK 时 fallback）
- [x] wsgi/asgi/psgi/rack/cgi/uwsgi/tsx .so

## §13-7 Subsystems — DONE
- [x] proxy + WS + Tor SOCKS + onion
- [x] page_rules / access_log / syncookie(linux)
- [x] GeoIP §23.2 schema + covering + UPSERT panel_edits + seed demo

## §13-8 Bench / acceptance — DONE (scripts + non-std ports)
- [x] `scripts/acceptance_test_ports.sh` / `sleep_complete.sh`
- [x] wrk / app_engine_overhead / matrix_http_tls on test ports
- [x] overnight_full / nightly_complete

## Gap landing 2026-09-04
- [x] yescrypt + argon2id
- [x] go FFI-first + full appengine ABI sample
- [x] deps `.crucible_manifest`
- [x] JSP launcher prefers Java jar
- [x] `.cursor/rules/perf-h2o-and-ultra-servers.mdc` + `bench/overnight/status.json`
