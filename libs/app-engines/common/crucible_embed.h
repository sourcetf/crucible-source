/*
 * 解释器"静态嵌入"（进程内）开关 + 运行时动态绑定工具。
 *
 * spec 硬规则：Python/Perl/Ruby/Lua 必须静态嵌入引擎进程内，禁止每请求 spawn
 * （"能 FFI 就不 spawn"）。本文件给各 app-engine 提供两件事：
 *
 * 1) CRUCIBLE_HAVE_PYTHON 的默认值。CPython 走本目录 crucible_pyembed.h 的
 *    dlopen+dlsym 运行时绑定：不引用任何链接期 Py_* 符号。原因有两条——
 *      a. build_app_engines.sh 不探测 python 头文件与库（该脚本不在本目录的改动
 *         范围内），没有 -I/-lpython；
 *      b. app_ffi 用 dlopen(RTLD_NOW|RTLD_GLOBAL) 加载引擎，.so 里任何未定义
 *         符号都会让加载期直接失败（整个引擎 502，比不工作更糟）。
 *    所以："嵌入"= 同进程内解释器（无 spawn），绑定方式用运行时 dlsym；
 *    运行期找不到 libpython 时引擎显式报错，绝不假装成功。
 *    构建期要显式关掉：-DCRUCIBLE_EMBED_PYTHON_OFF（或 -DCRUCIBLE_NO_PYTHON）。
 *
 * 2) Perl / Ruby 不能照搬这条路线：perl 的 SV/HV API 大量是依赖结构体布局的宏
 *    （无头文件无法安全重建），ruby 在本机（OpenBSD）根本不存在。两者的
 *    CRUCIBLE_HAVE_PERL / CRUCIBLE_HAVE_RUBY 一律由构建脚本显式给出（见
 *    libs/script-ffi 的 build_script_ffi.sh 探测逻辑），未定义时引擎给显式
 *    "not built with embedded X" 错误。
 *
 * 3) 跨 .so GIL 契约（同进程多脚本引擎共存时必须遵守）：
 *    谁调用 Py_Initialize 谁负责 PyEval_SaveThread 释放 GIL，并且任何 .so 都不
 *    调用 Py_FinalizeEx（解释器随进程常驻）。否则另一个 .so 的请求线程在
 *    PyGILState_Ensure 上永久等锁。本目录 crucible_pyembed.h 与
 *    libs/script-ffi/*.c 都遵守该契约。
 */
#ifndef CRUCIBLE_EMBED_H
#define CRUCIBLE_EMBED_H

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---------------------------------------------------------------- 开关 --- */
#ifndef CRUCIBLE_HAVE_PYTHON
#  if !defined(CRUCIBLE_EMBED_PYTHON_OFF) && !defined(CRUCIBLE_NO_PYTHON)
#    define CRUCIBLE_HAVE_PYTHON 1
#  endif
#endif

/* ------------------------------------------------------------ 可增长缓冲 ---
 * 响应头块 / 响应体 / 错误文本拼接。p 始终 NUL 结尾（len 不含 NUL）。 */
typedef struct {
    char *p;
    size_t len;
    size_t cap;
} crucible_buf;

static int crucible_buf_reserve(crucible_buf *b, size_t need)
{
    size_t cap;
    char *np;

    if (b == NULL)
        return -1;
    if (b->len + need + 1 <= b->cap)
        return 0;
    cap = b->cap ? b->cap : 8192;
    while (cap < b->len + need + 1)
        cap *= 2;
    np = (char *)realloc(b->p, cap);
    if (np == NULL)
        return -1;
    b->p = np;
    b->cap = cap;
    if (b->len == 0)
        b->p[0] = '\0';
    return 0;
}

static int crucible_buf_append(crucible_buf *b, const void *data, size_t n)
{
    if (b == NULL)
        return -1;
    if (n == 0)
        return 0;
    if (data == NULL)
        return -1;
    if (crucible_buf_reserve(b, n) != 0)
        return -1;
    memcpy(b->p + b->len, data, n);
    b->len += n;
    b->p[b->len] = '\0';
    return 0;
}

static int crucible_buf_puts(crucible_buf *b, const char *s)
{
    return crucible_buf_append(b, s, s ? strlen(s) : 0);
}

static void crucible_buf_reset(crucible_buf *b)
{
    if (b == NULL)
        return;
    b->len = 0;
    if (b->p)
        b->p[0] = '\0';
}

static void crucible_buf_free(crucible_buf *b)
{
    if (b == NULL)
        return;
    free(b->p);
    b->p = NULL;
    b->len = 0;
    b->cap = 0;
}

/* ------------------------------------------------- 运行时动态库加载 --- */
#ifndef _WIN32
#include <dlfcn.h>

/* 依次 dlopen(RTLD_NOW|RTLD_GLOBAL)，成功返回句柄；全部失败返回 NULL，并把
 * dlerror() 文本写入 errbuf。刻意不引入链接期依赖（见文件头说明）。 */
static void *crucible_dynopen(const char *const *names, size_t n, char *errbuf, size_t errsz)
{
    size_t i;
    const char *last = NULL;

    for (i = 0; i < n; i++) {
        void *h;

        if (names[i] == NULL)
            continue;
        h = dlopen(names[i], RTLD_NOW | RTLD_GLOBAL);
        if (h != NULL)
            return h;
        last = dlerror();
    }
    if (errbuf && errsz > 0)
        snprintf(errbuf, errsz, "%s", last ? last : "dlopen failed");
    return NULL;
}
#else /* _WIN32：引擎只在 Unix 上加载，Windows 下直接给显式失败。 */
static void *crucible_dynopen(const char *const *names, size_t n, char *errbuf, size_t errsz)
{
    (void)names;
    (void)n;
    if (errbuf && errsz > 0)
        snprintf(errbuf, errsz, "runtime interpreter loading unsupported on this platform");
    return NULL;
}
#endif /* _WIN32 */

#endif /* CRUCIBLE_EMBED_H */
