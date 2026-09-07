#!/usr/bin/env bash
# Build script-ffi shared library + per-language app engines.
# Prefers in-process interpreters when headers are found:
#   -DCRUCIBLE_HAVE_PYTHON / -DCRUCIBLE_HAVE_RUBY / -DCRUCIBLE_HAVE_PERL
# Missing headers: library builds but execute() fails closed (no popen).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${ROOT}/target/app-engines"
SRC="${ROOT}/libs/script-ffi"
INC="${ROOT}/libs/app-engines/include"
COMMON="${ROOT}/libs/app-engines/common"
CC="${CC:-cc}"
mkdir -p "${OUT}"

export PATH="/usr/local/bin:/usr/bin:/bin:${PATH:-}"
if [[ -x /usr/local/bin/gcc ]]; then
  CC=/usr/local/bin/gcc
fi

CFLAGS="-O2 -fPIC -I${INC} -I${COMMON}"
LDFLAGS="-shared -fPIC"
EXTRA_CFLAGS=""
EXTRA_LIBS=""

detect_python() {
  if pkg-config --exists python3-embed 2>/dev/null; then
    EXTRA_CFLAGS="${EXTRA_CFLAGS} $(pkg-config --cflags python3-embed) -DCRUCIBLE_HAVE_PYTHON"
    EXTRA_LIBS="${EXTRA_LIBS} $(pkg-config --libs python3-embed)"
    echo "    in-process Python via python3-embed"
    return 0
  fi
  if pkg-config --exists python3 2>/dev/null; then
    EXTRA_CFLAGS="${EXTRA_CFLAGS} $(pkg-config --cflags python3) -DCRUCIBLE_HAVE_PYTHON"
    EXTRA_LIBS="${EXTRA_LIBS} $(pkg-config --libs python3)"
    echo "    in-process Python via python3"
    return 0
  fi
  for cand in \
    /usr/local/include/python3.*/Python.h \
    /usr/include/python3.*/Python.h
  do
    for f in ${cand}; do
      if [[ -f "${f}" ]]; then
        local idir
        idir="$(dirname "${f}")"
        EXTRA_CFLAGS="${EXTRA_CFLAGS} -I${idir} -DCRUCIBLE_HAVE_PYTHON"
        EXTRA_LIBS="${EXTRA_LIBS} -lpython3"
        echo "    in-process Python headers at ${f}"
        return 0
      fi
    done
  done
  echo "    Python headers missing → embed-missing (no popen) for python"
  return 1
}

detect_ruby() {
  if pkg-config --exists ruby 2>/dev/null; then
    EXTRA_CFLAGS="${EXTRA_CFLAGS} $(pkg-config --cflags ruby) -DCRUCIBLE_HAVE_RUBY"
    EXTRA_LIBS="${EXTRA_LIBS} $(pkg-config --libs ruby)"
    echo "    in-process Ruby via pkg-config"
    return 0
  fi
  if command -v ruby >/dev/null 2>&1; then
    local hdr
    hdr="$(ruby -rrbconfig -e 'print RbConfig::CONFIG["rubyhdrdir"]' 2>/dev/null || true)"
    local arch
    arch="$(ruby -rrbconfig -e 'print RbConfig::CONFIG["rubyarchhdrdir"]' 2>/dev/null || true)"
    if [[ -n "${hdr}" && -f "${hdr}/ruby.h" ]]; then
      EXTRA_CFLAGS="${EXTRA_CFLAGS} -I${hdr}"
      [[ -n "${arch}" ]] && EXTRA_CFLAGS="${EXTRA_CFLAGS} -I${arch}"
      EXTRA_CFLAGS="${EXTRA_CFLAGS} -DCRUCIBLE_HAVE_RUBY"
      EXTRA_LIBS="${EXTRA_LIBS} -lruby"
      echo "    in-process Ruby headers at ${hdr}"
      return 0
    fi
  fi
  echo "    Ruby headers missing → embed-missing (no popen) for ruby"
  return 1
}

detect_perl() {
  if command -v perl >/dev/null 2>&1; then
    local cflags
    cflags="$(perl -MExtUtils::Embed -e 'ccopts' 2>/dev/null || true)"
    local ld
    ld="$(perl -MExtUtils::Embed -e 'ldopts' 2>/dev/null || true)"
    if echo "${cflags}" | grep -q -- '-I'; then
      EXTRA_CFLAGS="${EXTRA_CFLAGS} ${cflags} -DCRUCIBLE_HAVE_PERL"
      EXTRA_LIBS="${EXTRA_LIBS} ${ld}"
      echo "    in-process Perl via ExtUtils::Embed"
      return 0
    fi
  fi
  echo "    Perl headers missing → embed-missing (no popen)"
  return 1
}

echo "==> detecting in-process script interpreters"
detect_python || true
detect_ruby || true
detect_perl || true

echo "==> building libscriptffi.so"
${CC} ${CFLAGS} ${EXTRA_CFLAGS} ${LDFLAGS} -o "${OUT}/libscriptffi.so" \
  "${SRC}/scriptffi.c" ${EXTRA_LIBS} || \
${CC} ${CFLAGS} ${LDFLAGS} -o "${OUT}/libscriptffi.so" "${SRC}/scriptffi.c"

for lang in python ruby perl; do
  echo "==> building libapp_${lang}.so (script_engine; flags=${EXTRA_CFLAGS:-(embed-missing)})"
  if ! ${CC} ${CFLAGS} ${EXTRA_CFLAGS} -DCRUCIBLE_SCRIPT_LANG='"'"${lang}"'"' ${LDFLAGS} \
    -o "${OUT}/libapp_${lang}.so" \
    "${SRC}/script_engine.c" \
    "${COMMON}/appengine_common.c" \
    ${EXTRA_LIBS}; then
    echo "WARN: in-process link failed for ${lang}; rebuilding without embeds (fail-closed)" >&2
    ${CC} ${CFLAGS} -DCRUCIBLE_SCRIPT_LANG='"'"${lang}"'"' ${LDFLAGS} \
      -o "${OUT}/libapp_${lang}.so" \
      "${SRC}/script_engine.c" \
      "${COMMON}/appengine_common.c"
  fi
done

echo "built ${OUT}/libscriptffi.so libapp_{python,ruby,perl}.so"
