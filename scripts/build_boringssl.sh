#!/bin/sh
# Prebuild BoringSSL static libs for boring-sys (OpenBSD pthread + gmake workaround).
set -e

if [ -n "${CRUCIBLE_ROOT:-}" ]; then
  ROOT="${CRUCIBLE_ROOT}"
else
  ROOT="$(cd "$(dirname "$0")/.." && pwd)"
fi

OUT="${ROOT}/target/tls-libs/boringssl"
LIB="${OUT}/lib"
INC="${OUT}/include"
SRC="${OUT}/src"
BUILD="${OUT}/build"
BSSL_BIN="${OUT}/bin/bssl"

export PATH="/usr/local/bin:/usr/local/sbin:${PATH:-}"

CMAKE_GEN="Unix Makefiles"
CMAKE_MAKE="/usr/local/bin/gmake"
if command -v ninja >/dev/null 2>&1; then
  CMAKE_GEN="Ninja"
  CMAKE_MAKE="ninja"
fi

install_bssl() {
  mkdir -p "${OUT}/bin"
  for candidate in "${BUILD}/bssl" "${BUILD}/tool/bssl" "${BUILD}/tools/bssl"; do
    if [ -x "${candidate}" ]; then
      cp -f "${candidate}" "${BSSL_BIN}"
      chmod 755 "${BSSL_BIN}"
      echo "boringssl: installed ${BSSL_BIN}"
      return 0
    fi
  done
  return 1
}

if [ -f "${LIB}/libssl.a" ] && [ -f "${LIB}/libcrypto.a" ] && [ -f "${INC}/openssl/ssl.h" ]; then
  if [ -x "${BSSL_BIN}" ]; then
    echo "boringssl: ${LIB}/libssl.a exists (bssl=${BSSL_BIN})"
    exit 0
  fi
  if [ -d "${BUILD}" ]; then
    echo "boringssl: libs exist; building bssl tool only"
    if [ "${CMAKE_GEN}" = "Ninja" ]; then
      ninja -C "${BUILD}" bssl || true
    else
      "${CMAKE_MAKE}" -C "${BUILD}" -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)" bssl || true
    fi
    install_bssl && exit 0
  fi
  echo "boringssl: warning — bssl tool missing (full rebuild will produce it)" >&2
fi

for cmd in cmake gmake; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "boringssl: missing $cmd (pkg_add cmake gmake)" >&2
    exit 1
  fi
done

mkdir -p "${LIB}" "${INC}" "${SRC}" "${BUILD}"

if [ ! -f "${SRC}/CMakeLists.txt" ]; then
  echo "boringssl: fetching source"
  rm -rf "${SRC}"
  mkdir -p "${SRC}"
  if command -v git >/dev/null 2>&1; then
    git clone --depth 1 https://github.com/google/boringssl.git "${SRC}" || \
      git clone --depth 1 https://boringssl.googlesource.com/boringssl "${SRC}"
  else
    echo "boringssl: need git to fetch source" >&2
    exit 1
  fi
fi

echo "boringssl: configuring (${CMAKE_GEN})"
cmake -S "${SRC}" -B "${BUILD}" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_FLAGS="-pthread -include pthread.h" \
  -DCMAKE_CXX_FLAGS="-pthread -include pthread.h" \
  -DCMAKE_MAKE_PROGRAM="${CMAKE_MAKE}" \
  -G "${CMAKE_GEN}"

echo "boringssl: building crypto + ssl + bssl (ECH CLI)"
if [ "${CMAKE_GEN}" = "Ninja" ]; then
  ninja -C "${BUILD}" crypto ssl bssl
else
  "${CMAKE_MAKE}" -C "${BUILD}" -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)" crypto ssl bssl
fi

for pair in \
  "${BUILD}/crypto/libcrypto.a:${LIB}/libcrypto.a" \
  "${BUILD}/ssl/libssl.a:${LIB}/libssl.a" \
  "${BUILD}/libcrypto.a:${LIB}/libcrypto.a" \
  "${BUILD}/libssl.a:${LIB}/libssl.a"; do
  src="${pair%%:*}"
  dst="${pair##*:}"
  if [ -f "${src}" ]; then
    cp -f "${src}" "${dst}"
  fi
done

if [ ! -f "${LIB}/libcrypto.a" ] || [ ! -f "${LIB}/libssl.a" ]; then
  echo "boringssl: libcrypto.a / libssl.a not found under ${BUILD}" >&2
  find "${BUILD}" -name 'libcrypto.a' -o -name 'libssl.a' 2>/dev/null | head -10 >&2 || true
  exit 1
fi

rm -rf "${INC}/openssl"
mkdir -p "${INC}"
cp -R "${SRC}/include/openssl" "${INC}/"

echo "boringssl: installed ${LIB}/libssl.a ${LIB}/libcrypto.a"
install_bssl || echo "boringssl: warning — bssl tool not found (ECH generate-ech unavailable)" >&2
