/*
 * 跨 .so 的进程级 CPython 初始化协调（工号 1009 F2 修复）。
 *
 * 背景：libapp_python.so / libapp_wsgi.so / libapp_asgi.so / libapp_uwsgi.so 各
 * 自静态嵌入同一份 libpython，而初始化锁却是 .so 私有的（pthread_once / static
 * mutex 各一份）。并发冷启动时两个线程都看到 Py_IsInitialized()==false、都调用
 * Py_Initialize()，后到线程没有 thread state，它的 PyEval_SaveThread() 在 NULL
 * tstate 上直接 Py_FatalError（abort 整个进程）。
 *
 * 修法：初始化收敛到共享库 libscriptffi.so 导出的 crucible_py_ensure_init()
 * （内部一把进程级静态互斥锁；实现见 libs/script-ffi/scriptffi.c）。本头文件：
 *   1) 记录 appengine_init 收到的 lib_hint（引擎 .so 路径），用于定位同目录的
 *      libscriptffi.so；
 *   2) dlopen(RTLD_NOW|RTLD_GLOBAL|RTLD_NODELETE) 它并解析共享初始化函数；
 *   3) 每个嵌入点在拿 GIL / 任何 PyEval_* 之前调用 crucible_pyinit_ensure()；
 *      实现方用调用方传入的三个函数指针操作**调用方自己的** libpython 实例。
 *
 * libscriptffi.so 缺失时退回本 .so 私有锁直接初始化：保持引擎可用；该场景下
 * 只有本 .so 一个嵌入点，不存在跨 .so 竞争（构建脚本总会产出它）。
 *
 * 因为本文件是 header-only（static），每个 .so 各自持有一份解析逻辑与函数指针，
 * 真正的共享状态（互斥锁）在 libscriptffi.so 里，进程内只有一份。
 */
#ifndef CRUCIBLE_PYINIT_H
#define CRUCIBLE_PYINIT_H

#include <stddef.h>
#include <stdio.h>
#include <string.h>

/* 共享初始化函数签名。调用方传入本 .so 已解析好的三个 CPython API 指针，保证
 * 初始化的是与调用方相同的解释器实例（绝对路径 dlopen 同一文件 ⇒ 同一实例）。
 * 返回 0 = 解释器已初始化且初始化线程已释放 GIL；-1 = 失败（err 填原因）。 */
typedef int (*crucible_py_ensure_init_fn)(int (*is_initialized)(void),
                                          void (*initialize)(void),
                                          void *(*save_thread)(void),
                                          char *err, size_t errsz);

/* scriptffi.c 是提供方，只需借 typedef，不需要下列 static 辅助函数。 */
#ifndef CRUCIBLE_PYINIT_DECLARATIONS_ONLY

#if !defined(_WIN32)

#include <dlfcn.h>
#include <pthread.h>

static char g_crucible_pyinit_hint[1024];

/* appengine_init 时调用：记下本引擎 .so 的路径（Rust 侧 app_ffi 传的 lib_hint
 * 就是 lib_path）。 */
static void crucible_pyinit_set_hint(const char *lib_hint)
{
    if (lib_hint == NULL)
        return;
    snprintf(g_crucible_pyinit_hint, sizeof(g_crucible_pyinit_hint), "%s", lib_hint);
}

/* 定位并 dlopen 同目录的 libscriptffi.so；只尝试一次。 */
static void *crucible_pyinit_open_shared(void)
{
    static void *cached;
    static int tried;
    char cand[1200];
    const char *names[4];
    int n = 0, i;

    if (tried)
        return cached;
    tried = 1;
    /* 首选：与调用方 .so 同目录（lib_hint 的 dirname）。 */
    if (g_crucible_pyinit_hint[0] != '\0') {
        const char *slash = strrchr(g_crucible_pyinit_hint, '/');
        if (slash != NULL) {
            size_t d = (size_t)(slash - g_crucible_pyinit_hint);
            if (d + sizeof("/libscriptffi.so") <= sizeof(cand)) {
                memcpy(cand, g_crucible_pyinit_hint, d);
                memcpy(cand + d, "/libscriptffi.so", sizeof("/libscriptffi.so"));
                names[n++] = cand;
            }
        }
    }
    names[n++] = "libscriptffi.so";
    names[n++] = "target/app-engines/libscriptffi.so";
    names[n++] = "./target/app-engines/libscriptffi.so";
    for (i = 0; i < n; i++) {
        void *h = dlopen(names[i],
                         RTLD_NOW | RTLD_GLOBAL
#ifdef RTLD_NODELETE
                             | RTLD_NODELETE
#endif
        );
        if (h != NULL) {
            cached = h;
            return h;
        }
    }
    return NULL;
}

/* 确保解释器已初始化（可并发调用；内部跨 .so 只执行一次初始化）。 */
static int crucible_pyinit_ensure(int (*is_initialized)(void),
                                  void (*initialize)(void),
                                  void *(*save_thread)(void), char *err, size_t errsz)
{
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    static crucible_py_ensure_init_fn shared_fn;
    static int shared_resolved;
    static int local_state; /* 0 未初始化 1 就绪 -1 失败 */
    static char local_err[256];
    int rc;

    if (err != NULL && errsz > 0)
        err[0] = '\0';
    pthread_mutex_lock(&lock);
    if (!shared_resolved) {
        void *h = crucible_pyinit_open_shared();

        shared_resolved = 1;
        if (h != NULL) {
            *(void **)(&shared_fn) = dlsym(h, "crucible_py_ensure_init");
            if (shared_fn == NULL)
                fprintf(stderr,
                        "crucible: libscriptffi.so 缺少 crucible_py_ensure_init"
                        "（旧版本？）——初始化退回 .so 私有锁\n");
        } else {
            fprintf(stderr,
                    "crucible: 未找到 libscriptffi.so —— CPython 初始化退回 .so 私有锁"
                    "（多 .so 并发冷启动存在竞争风险）\n");
        }
    }
    if (shared_fn != NULL) {
        rc = shared_fn(is_initialized, initialize, save_thread, err, errsz);
        pthread_mutex_unlock(&lock);
        return rc;
    }
    /* 兜底：共享库缺失。单 .so 场景下私有锁足够。 */
    if (local_state == 1) {
        pthread_mutex_unlock(&lock);
        return 0;
    }
    if (local_state == -1) {
        if (err != NULL && errsz > 0)
            snprintf(err, errsz, "%s", local_err);
        pthread_mutex_unlock(&lock);
        return -1;
    }
    if (is_initialized == NULL || initialize == NULL) {
        snprintf(local_err, sizeof(local_err), "CPython API 指针为空");
        if (err != NULL && errsz > 0)
            snprintf(err, errsz, "%s", local_err);
        local_state = -1;
        pthread_mutex_unlock(&lock);
        return -1;
    }
    if (!is_initialized()) {
        initialize();
        if (save_thread != NULL)
            (void)save_thread(); /* 初始化线程持有 GIL，必须由它释放 */
    }
    local_state = 1;
    pthread_mutex_unlock(&lock);
    return 0;
}

#else /* _WIN32：引擎只在 Unix 上加载，这里保持可编译的最小实现。 */

static void crucible_pyinit_set_hint(const char *lib_hint) { (void)lib_hint; }

static int crucible_pyinit_ensure(int (*is_initialized)(void),
                                  void (*initialize)(void),
                                  void *(*save_thread)(void), char *err, size_t errsz)
{
    if (err != NULL && errsz > 0)
        err[0] = '\0';
    if (is_initialized == NULL || initialize == NULL)
        return -1;
    if (!is_initialized()) {
        initialize();
        if (save_thread != NULL)
            (void)save_thread();
    }
    return 0;
}

#endif /* _WIN32 */

#endif /* CRUCIBLE_PYINIT_DECLARATIONS_ONLY */

#endif /* CRUCIBLE_PYINIT_H */
