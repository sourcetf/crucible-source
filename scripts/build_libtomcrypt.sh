#!/bin/sh
# Build static libtomcrypt when no system package exists (OpenBSD has no tomcrypt pkg).
set -e

if [ -n "${CRUCIBLE_ROOT:-}" ]; then
  ROOT="${CRUCIBLE_ROOT}"
else
  ROOT="$(cd "$(dirname "$0")/.." && pwd)"
fi

PREFIX="${PREFIX:-/usr/local}"
OUT_DIR="${ROOT}/target/tls-libs"
SRC_DIR="${OUT_DIR}/libtomcrypt-src"
VENDOR="${SRC_DIR}/libtomcrypt"

export PATH="/usr/local/bin:/usr/local/sbin:${PATH:-}"
MAKE="${MAKE:-gmake}"

if [ ! -d "${ROOT}/libs" ]; then
  echo "libtomcrypt: invalid ROOT=${ROOT}" >&2
  exit 1
fi

# Always prefer vendored ARGTYPE=2 + LTC_LTM_DESC. System libs (if any) often
# abort on LTC_ARGCHK and lack ltm_desc — that killed the process on SSLv2 probes.
mkdir -p "${OUT_DIR}"
NEED_REBUILD=0
if [ ! -f "${OUT_DIR}/libtomcrypt.a" ]; then
  NEED_REBUILD=1
elif ! nm "${OUT_DIR}/libtomcrypt.a" 2>/dev/null | grep -q 'rc4_stream_setup'; then
  echo "libtomcrypt: rebuilding — missing rc4_stream_setup"
  NEED_REBUILD=1
elif ! nm "${OUT_DIR}/libtomcrypt.a" 2>/dev/null | grep -q 'ltm_desc'; then
  echo "libtomcrypt: rebuilding — missing ltm_desc (need LTC_LTM_DESC)"
  NEED_REBUILD=1
elif [ ! -f "${OUT_DIR}/.tomcrypt_with_ltm" ]; then
  echo "libtomcrypt: rebuilding — stamp missing (ARGTYPE/LTM rebuild)"
  NEED_REBUILD=1
fi
if [ "${NEED_REBUILD}" = 0 ]; then
  echo "libtomcrypt: ${OUT_DIR}/libtomcrypt.a exists (RC4 + ltm_desc + ARGTYPE=2 ok)"
  mkdir -p "${OUT_DIR}/include"
  if [ -d "${VENDOR}/src/headers" ]; then
    cp -f "${VENDOR}/src/headers"/tomcrypt*.h "${OUT_DIR}/include/" 2>/dev/null || true
  fi
  exit 0
fi
rm -f "${OUT_DIR}/libtomcrypt.a" "${OUT_DIR}/.tomcrypt_with_ltm"

if [ ! -f "${VENDOR}/makefile.shared" ]; then
  echo "libtomcrypt: downloading source tarball"
  mkdir -p "${SRC_DIR}"
  TARBALL="${SRC_DIR}/libtomcrypt.tar.gz"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL -o "${TARBALL}" \
      "https://github.com/libtom/libtomcrypt/archive/refs/heads/master.tar.gz"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "${TARBALL}" \
      "https://github.com/libtom/libtomcrypt/archive/refs/heads/master.tar.gz"
  else
    echo "libtomcrypt: need curl or wget" >&2
    exit 1
  fi
  tar -xzf "${TARBALL}" -C "${SRC_DIR}"
  if [ -d "${SRC_DIR}/libtomcrypt-master" ]; then
    mv "${SRC_DIR}/libtomcrypt-master" "${VENDOR}"
  fi
fi

if [ ! -f "${VENDOR}/makefile.shared" ]; then
  echo "libtomcrypt: source tree missing makefile.shared" >&2
  exit 1
fi

cd "${VENDOR}"
# Ensure SSLv2 path has RC4 stream + RSA + MD5 (OpenBSD has no system package).
if [ -f src/headers/tomcrypt_custom.h ]; then
  for def in LTC_RC4_STREAM LTC_MRSA LTC_MD5 LTC_PKCS_1; do
    if ! grep -q "^#define ${def}" src/headers/tomcrypt_custom.h 2>/dev/null; then
      # Prefer uncommenting existing undef lines when present.
      if grep -q "define ${def}" src/headers/tomcrypt_custom.h 2>/dev/null; then
        sed -i.bak -e "s|^/\\* #define ${def} \\*/|#define ${def}|" \
                   -e "s|^#undef ${def}|#define ${def}|" \
                   src/headers/tomcrypt_custom.h || true
      else
        printf '\n#ifndef %s\n#define %s\n#endif\n' "$def" "$def" >> src/headers/tomcrypt_custom.h
      fi
    fi
  done
fi

# ARGTYPE=2 → return CRYPT_INVALID_ARG instead of abort() on LTC_ARGCHK failure.
# LTM_DESC / LTC_LTM_DESC → export ltm_desc; requires linking -ltommath at final link.
# (Upstream math/ltm_desc.c gates on LTM_DESC — both macros for safety.)
CUSTOM_CFLAGS="-fPIC -O2 -DLTC_SOURCE -DARGTYPE=2 -DLTM_DESC -DLTC_LTM_DESC"
if [ -f /usr/local/include/tommath.h ]; then
  CUSTOM_CFLAGS="${CUSTOM_CFLAGS} -I/usr/local/include"
elif [ -f /usr/include/tommath.h ]; then
  CUSTOM_CFLAGS="${CUSTOM_CFLAGS} -I/usr/include"
fi

"${MAKE}" clean 2>/dev/null || true
"${MAKE}" -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)" -f makefile \
  CFLAGS="${CUSTOM_CFLAGS}" library

cp -f libtomcrypt.a "${OUT_DIR}/libtomcrypt.a"
mkdir -p "${OUT_DIR}/include"
cp -f src/headers/tomcrypt*.h "${OUT_DIR}/include/" 2>/dev/null || true
# Verify the export exists (OpenBSD nm: look for 'T ltm_desc' or 'D ltm_desc')
if ! nm "${OUT_DIR}/libtomcrypt.a" 2>/dev/null | grep -E ' [TD] ltm_desc$' >/dev/null; then
  echo "libtomcrypt: ERROR — ltm_desc symbol missing after build (need -DLTM_DESC)" >&2
  nm "${OUT_DIR}/libtomcrypt.a" 2>/dev/null | grep -i ltm | head -10 >&2 || true
  exit 1
fi
# Force rebuild next time if ARGTYPE/ltm_desc missing historically.
touch "${OUT_DIR}/.tomcrypt_with_ltm"
echo "libtomcrypt: installed ${OUT_DIR}/libtomcrypt.a (ARGTYPE=2 LTM_DESC)"
