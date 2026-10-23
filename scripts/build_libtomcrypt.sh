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

# libtommath 静态库放进 target/tls-libs：build.rs 用 `-L target/tls-libs -ltommath`，
# 这样链接/运行都不需要额外 LD_LIBRARY_PATH（用户级 aptlocal 包没有系统 ldconfig 条目）。
# 可用 TOMATH_LIB 覆盖库目录。
install_tommath_a() {
  [ -f "${OUT_DIR}/libtommath.a" ] && return 0
  for lib in "${TOMATH_LIB:-}" "${HOME}/local/usr/lib/x86_64-linux-gnu" "${HOME}/local/lib" \
             /usr/local/lib /usr/lib/x86_64-linux-gnu /usr/lib; do
    if [ -n "${lib}" ] && [ -f "${lib}/libtommath.a" ]; then
      cp -f "${lib}/libtommath.a" "${OUT_DIR}/libtommath.a"
      echo "libtomcrypt: libtommath.a from ${lib} → ${OUT_DIR}/libtommath.a"
      return 0
    fi
  done
  echo "libtomcrypt: WARN — libtommath.a not found; final link needs -ltommath from the system" >&2
  return 1
}

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
elif strings "${OUT_DIR}/libtomcrypt.a" 2>/dev/null | grep -q 'warning: ARGCHK failed'; then
  # ARGTYPE=2 in libtomcrypt (1.18.2 与 master 相同) 是「打印 warning 后继续」——
  # 校验失败后函数会带着 NULL 指针继续跑 → SIGSEGV。要求 ARGTYPE=4（return error）。
  echo "libtomcrypt: rebuilding — archive was built with ARGTYPE=2 (warn+continue, SIGSEGV risk)"
  NEED_REBUILD=1
fi
if [ "${NEED_REBUILD}" = 0 ]; then
  echo "libtomcrypt: ${OUT_DIR}/libtomcrypt.a exists (RC4 + ltm_desc + ARGTYPE=4 ok)"
  mkdir -p "${OUT_DIR}/include"
  if [ -d "${VENDOR}/src/headers" ]; then
    cp -f "${VENDOR}/src/headers"/tomcrypt*.h "${OUT_DIR}/include/" 2>/dev/null || true
  fi
  install_tommath_a || true
  exit 0
fi
rm -f "${OUT_DIR}/libtomcrypt.a" "${OUT_DIR}/.tomcrypt_with_ltm"

if [ ! -f "${VENDOR}/makefile.shared" ]; then
  echo "libtomcrypt: downloading source tarball"
  mkdir -p "${SRC_DIR}"
  GOT=""
  # 1) 已放好的本地 tarball（离网/CI 可预放，免下载）
  for cand in "${SRC_DIR}/libtomcrypt.tar.xz" "${SRC_DIR}/libtomcrypt.tar.gz"; do
    if [ -f "${cand}" ]; then GOT="${cand}"; break; fi
  done
  # 2) GitHub 直连；3) Ubuntu/Debian 源码池镜像（国内可达；GitHub 在部分网络不可达）
  if [ -z "${GOT}" ]; then
    for url in \
      "https://github.com/libtom/libtomcrypt/archive/refs/heads/master.tar.gz" \
      "https://mirrors.tuna.tsinghua.edu.cn/ubuntu/pool/universe/libt/libtomcrypt/libtomcrypt_1.18.2+dfsg.orig.tar.xz"
    do
      TARBALL="${SRC_DIR}/$(basename "${url}")"
      if command -v curl >/dev/null 2>&1; then
        if curl -fsSL --connect-timeout 10 -m 180 -o "${TARBALL}" "${url}"; then
          GOT="${TARBALL}"
          break
        fi
      elif command -v wget >/dev/null 2>&1; then
        if wget -q -T 20 -O "${TARBALL}" "${url}"; then
          GOT="${TARBALL}"
          break
        fi
      else
        echo "libtomcrypt: need curl or wget" >&2
        exit 1
      fi
      rm -f "${TARBALL}"
    done
  fi
  if [ -z "${GOT}" ]; then
    echo "libtomcrypt: source download failed (GitHub + TUNA mirror unreachable)." >&2
    echo "  place a tarball at ${SRC_DIR}/libtomcrypt.tar.xz (or .tar.gz) and re-run." >&2
    exit 1
  fi
  echo "libtomcrypt: extracting ${GOT}"
  case "${GOT}" in
    *.tar.xz) tar -xJf "${GOT}" -C "${SRC_DIR}" ;;
    *)        tar -xzf "${GOT}" -C "${SRC_DIR}" ;;
  esac
  # 顶层目录名随来源变化（libtomcrypt-master / libtomcrypt-1.18.2 / …）
  for d in "${SRC_DIR}"/libtomcrypt-*; do
    if [ -d "$d" ] && [ "$d" != "${VENDOR}" ] && [ -f "$d/makefile.shared" ]; then
      mv "$d" "${VENDOR}"
      break
    fi
  done
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

# ARGTYPE=4 → LTC_ARGCHK 返回 CRYPT_INVALID_ARG（**不** abort、也不继续）。
# 注意：libtomcrypt 1.18.2 与 master 的编号都是
#   0=abort、1=assert、2=打印 warning 后继续（危险，会带着 NULL 指针跑 → SIGSEGV）、
#   3=空操作、4=return CRYPT_INVALID_ARG。
# 历史上这里写的是 ARGTYPE=2（误以为「返回错误」），实测 NULL 参数会先打印
# "warning: ARGCHK failed" 再段错误 —— 必须用 4。
# LTM_DESC / LTC_LTM_DESC → export ltm_desc; requires linking -ltommath at final link.
# (Upstream math/ltm_desc.c gates on LTM_DESC — both macros for safety.)
CUSTOM_CFLAGS="-fPIC -O2 -DLTC_SOURCE -DARGTYPE=4 -DLTM_DESC -DLTC_LTM_DESC"
# libtommath 头文件：用户级 aptlocal 安装（~/local/usr/include）优先，其次系统路径。
# 可用 TOMATH_INCLUDE 覆盖。
for inc in "${TOMATH_INCLUDE:-}" "${HOME}/local/usr/include" "${HOME}/local/include" \
           /usr/local/include /usr/include; do
  if [ -n "${inc}" ] && [ -f "${inc}/tommath.h" ]; then
    CUSTOM_CFLAGS="${CUSTOM_CFLAGS} -I${inc}"
    echo "libtomcrypt: libtommath headers from ${inc}"
    break
  fi
done

"${MAKE}" clean 2>/dev/null || true
"${MAKE}" -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)" -f makefile \
  CFLAGS="${CUSTOM_CFLAGS}" library

cp -f libtomcrypt.a "${OUT_DIR}/libtomcrypt.a"
mkdir -p "${OUT_DIR}/include"
cp -f src/headers/tomcrypt*.h "${OUT_DIR}/include/" 2>/dev/null || true
# libtommath 静态库一并放进 target/tls-libs（见上面的 install_tommath_a）。
install_tommath_a || true
# Verify the export exists (OpenBSD nm: look for 'T ltm_desc' or 'D ltm_desc')
if ! nm "${OUT_DIR}/libtomcrypt.a" 2>/dev/null | grep -E ' [TD] ltm_desc$' >/dev/null; then
  echo "libtomcrypt: ERROR — ltm_desc symbol missing after build (need -DLTM_DESC)" >&2
  nm "${OUT_DIR}/libtomcrypt.a" 2>/dev/null | grep -i ltm | head -10 >&2 || true
  exit 1
fi
# 运行期验证 ARGTYPE=4：NULL 参数必须「返回 CRYPT_INVALID_ARG(8)」，
# 既不能 abort(134) 也不能段错误(139)。仅靠 nm 无法区分 ARGTYPE。
LTC_CC="${CC:-cc}"
cat > "${OUT_DIR}/.argchk_probe.c" <<'PROBE_EOF'
#include <stdio.h>
#include <tomcrypt.h>
int main(void) {
    rsa_key k;
    int err = rsa_import(NULL, 0, &k);
    printf("%d\n", err);
    return err == CRYPT_INVALID_ARG ? 0 : 1;
}
PROBE_EOF
if ${LTC_CC} -o "${OUT_DIR}/.argchk_probe" "${OUT_DIR}/.argchk_probe.c" \
      -I"${OUT_DIR}/include" -I"${OUT_DIR}" -I"${HOME}/local/usr/include" \
      -L"${OUT_DIR}" -ltomcrypt -ltommath >/dev/null 2>&1; then
  if PROBE_OUT=$("${OUT_DIR}/.argchk_probe" 2>/dev/null); then
    echo "libtomcrypt: ARGTYPE=4 verified — rsa_import(NULL) returned CRYPT_INVALID_ARG (no abort)"
  else
    echo "libtomcrypt: ERROR — rsa_import(NULL) did not return CRYPT_INVALID_ARG (got ${PROBE_OUT:-<crash>})" >&2
    echo "  ARGTYPE must be 4 in this libtomcrypt version (2 = warn+continue → SIGSEGV)." >&2
    rm -f "${OUT_DIR}/libtomcrypt.a"
    exit 1
  fi
else
  echo "libtomcrypt: WARN — could not build ARGTYPE probe (link step skipped)" >&2
fi
rm -f "${OUT_DIR}/.argchk_probe" "${OUT_DIR}/.argchk_probe.c"
# Force rebuild next time if ARGTYPE/ltm_desc missing historically.
touch "${OUT_DIR}/.tomcrypt_with_ltm"
echo "libtomcrypt: installed ${OUT_DIR}/libtomcrypt.a (ARGTYPE=4 LTM_DESC)"
