#!/bin/sh
# 验收：**进程内只有一个嵌入式 Perl 解释器**（perl 与 psgi 共用同一个）。
#
# 为什么必须有这条门禁：目标机 OpenBSD 的 base perl 是 `useithreads=undef` /
# `usemultiplicity=undef` 构建 —— `PL_curinterp` 是**进程全局**的。两个 .so 各建一个
# 解释器并在两条线程上跑，就会互相把「当前解释器」切错，几秒内崩在
# `Perl_call_sv`/`Perl_rpp_free_2_`（真机 core 已确认；单跑 /perl/ 或单跑 /psgi/ 都不崩，
# 只有两者并发才崩 —— 这就是双解释器的指纹）。修复 = 两个 .so 共用一份解释器
# （libs/app-engines/common/crucible_perl_shared.h）+ 宿主让两者跑同一条线程
# （src/server/apps/app_ffi.rs::pool_family）。
#
# 本脚本用与宿主**相同**的装载方式（`dlopen(..., RTLD_NOW | RTLD_GLOBAL)`）把两个
# 引擎 .so 打开，再各自调用导出的验收探针 `crucible_perl_probe_interp()`：
# 两次必须返回**同一个**非空 PerlInterpreter*。两种装载顺序都要成立。
#
# 用法（在目标机上，对着已构建的引擎跑）：
#   sh scripts/accept-verify-perl-shared.sh
#   sh scripts/accept-verify-perl-shared.sh target/app-engines/libapp_perl.so target/app-engines/libapp_psgi.so
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
A=${1:-"$ROOT/target/app-engines/libapp_perl.so"}
B=${2:-"$ROOT/target/app-engines/libapp_psgi.so"}
CC=${CC:-cc}

for f in "$A" "$B"; do
	if [ ! -f "$f" ]; then
		echo "SKIP: 找不到 $f（先把引擎构建出来：sh scripts/build_app_engines.sh）"
		exit 0
	fi
done

TMP=$(mktemp -d "${TMPDIR:-/tmp}/crucible-perlshared.XXXXXX") || exit 1
trap 'rm -rf "$TMP"' EXIT INT TERM

cat > "$TMP/probe.c" <<'EOF'
/* dlopen 两个引擎 .so（与宿主同款 flag），各自调探针，断言拿到同一个解释器。 */
#include <dlfcn.h>
#include <stdio.h>

typedef void *(*probe_fn)(void);

static int one_order(const char *first, const char *second)
{
    void *h1 = dlopen(first, RTLD_NOW | RTLD_GLOBAL);
    void *h2;
    probe_fn p1, p2;
    void *i1, *i2;

    if (h1 == NULL) {
        printf("  dlopen(%s) 失败: %s\n", first, dlerror());
        return 1;
    }
    h2 = dlopen(second, RTLD_NOW | RTLD_GLOBAL);
    if (h2 == NULL) {
        printf("  dlopen(%s) 失败: %s\n", second, dlerror());
        return 1;
    }
    p1 = (probe_fn)dlsym(h1, "crucible_perl_probe_interp");
    p2 = (probe_fn)dlsym(h2, "crucible_perl_probe_interp");
    if (p1 == NULL || p2 == NULL) {
        printf("  缺探针符号 crucible_perl_probe_interp: %s\n", dlerror());
        printf("  （旧版引擎没有该符号 → 必须重建引擎）\n");
        return 1;
    }
    i1 = p1();
    i2 = p2();
    printf("  first=%s -> interp=%p\n", first, i1);
    printf("  second=%s -> interp=%p\n", second, i2);
    if (i1 == NULL || i2 == NULL) {
        printf("  解释器为空：初始化失败（见 stderr 的 Perl 报错）\n");
        return 1;
    }
    if (i1 != i2) {
        printf("  **两个不同的解释器** —— 非多解释器 perl 上必然堆损坏\n");
        return 1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    int rc = 0;

    if (argc < 3) {
        printf("用法: probe <a.so> <b.so>\n");
        return 2;
    }
    printf("装载顺序 1: %s → %s\n", argv[1], argv[2]);
    rc |= one_order(argv[1], argv[2]);
    return rc;
}
EOF

if ! $CC -O0 -o "$TMP/probe" "$TMP/probe.c" 2>"$TMP/cc.err"; then
	echo "FAIL: 编译探针失败："
	cat "$TMP/cc.err"
	exit 1
fi

echo "== 顺序 A：perl 先装载 =="
if ! "$TMP/probe" "$A" "$B"; then
	echo "FAIL: 两个引擎不共用解释器（顺序 A）"
	exit 1
fi
echo "== 顺序 B：psgi 先装载 =="
if ! "$TMP/probe" "$B" "$A"; then
	echo "FAIL: 两个引擎不共用解释器（顺序 B）"
	exit 1
fi

echo "ok: 两种装载顺序下 perl 与 psgi 都用同一个解释器（单解释器不变量成立）"
