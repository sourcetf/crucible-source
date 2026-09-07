# Go app-engine build notes (OpenBSD)
#
# `go build -buildmode=c-shared` is **not supported** on openbsd/amd64
# (verified Go 1.26). Spec §7.3's default `libapp_go.so` in-process FFI
# applies on Linux; on OpenBSD the production path is:
#
#   target/app-engines/go-shm-server  +  feature `go_shm_ipc`
#
# `scripts/build_app_engines.sh` still *attempts* c-shared for Linux/CI
# parity and logs a WARN when it fails. Do not add a CGI spawn fallback.
