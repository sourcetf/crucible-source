#!/usr/bin/env bash
# OpenBSD dependency bootstrap for Crucible (PHP + app engines + webserver).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT}"

export PATH="/usr/local/bin:/usr/bin:/bin:${HOME}/.cargo/bin:${PATH:-}"

install_php() {
  if command -v php-fpm >/dev/null 2>&1 || command -v php-fpm83 >/dev/null 2>&1; then
    echo "[setup] php-fpm already available"
    return 0
  fi
  echo "[setup] installing PHP (includes php-fpm on OpenBSD)..."
  if pkg_add -I php-8.3 2>/dev/null; then
    :
  elif pkg_add -I php-8.2 2>/dev/null; then
    :
  elif pkg_add -I php 2>/dev/null; then
    :
  else
    echo "WARN: pkg_add php failed; /php/ route needs php-fpm in PATH" >&2
    return 1
  fi
  command -v php-fpm >/dev/null 2>&1 || command -v php-fpm83 >/dev/null 2>&1 || {
    echo "WARN: php-fpm binary not found after install" >&2
    return 1
  }
  echo "[setup] php ok: $(command -v php-fpm 2>/dev/null || command -v php-fpm83)"
}

echo "[setup] TLS deps (BoringSSL / libtomcrypt when configured)..."
if [[ -f "${ROOT}/config.mk" ]]; then
  make -C "${ROOT}" tls-deps || true
fi

echo "[setup] ECH keys (optional, for ssl.ech on :8443)..."
bash "${ROOT}/scripts/generate_ech.sh" crucible.local 2>/dev/null || \
  echo "[setup] skip ECH (pkg_add boringssl for bssl generate-ech)"

echo "[setup] building app engines..."
bash "${ROOT}/scripts/build_app_engines.sh"

echo "[setup] building webserver..."
unset CARGO_TARGET_DIR || true
bash "${ROOT}/scripts/build_release.sh"

install_php || true

echo "[setup] prebuilding www-apps sidecars..."
for app in go; do
  if [[ -x "${ROOT}/www-apps/${app}/init.sh" ]]; then
    (cd "${ROOT}/www-apps/${app}" && DEPS_DIR="${ROOT}/www-apps/${app}/deps" bash init.sh)
  fi
done

echo "[setup] done."
