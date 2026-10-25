/*
 * scriptffi app-engine —— 进程内解释器（Python / Ruby / Perl），无 popen。
 *
 * Build with -DCRUCIBLE_HAVE_PYTHON / _RUBY / _PERL (see build_script_ffi.sh)。
 * 缺某个语言的嵌入头文件时：该语言**显式失败**（rc != 0 + error 文本），
 * 不回退 popen、不返回假 hello（旧实现的 appengine_fill_hello 已删除）。
 *
 * Built as libapp_python.so / libapp_ruby.so / libapp_perl.so with
 * -DCRUCIBLE_SCRIPT_LANG。
 *
 * 跨 .so GIL 契约（详见 libs/app-engines/common/crucible_embed.h 文件头）：
 * 解释器初始化经由 libscriptffi.so 的进程级共享锁（crucible_pyinit.h），
 * 谁真正执行 Py_Initialize 谁负责 PyEval_SaveThread，任何 .so 都不调用
 * Py_FinalizeEx。否则同进程的 libapp_wsgi/asgi/uwsgi（另走 dlopen+dlsym 嵌入）
 * 的请求线程会在 PyGILState_Ensure 上永久等待。
 *
 * 每请求隔离（P1 F1）：脚本在**每请求新建的 globals dict**（__name__="__main__"）
 * 里执行，不再共享 __main__ 的模块级状态；stdout/stdin/os.environ 经解释器启动时
 * 安装一次的**线程感知代理**按线程分流（threading.local），不再逐请求替换解释器
 * 全局 sys.stdout / os.environ —— 并发请求之间不串输出、不串请求环境。
 */
#include "../app-engines/include/appengine.h"
#include "../app-engines/common/appengine_common.h"
#include "../app-engines/common/crucible_pyinit.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
/* no setenv on MSVC; keep Unix path primary for OpenBSD/Linux engines */
#else
#include <unistd.h>
#endif

static int g_ready;

/* 脚本输出上限（与 Rust 侧 UPSTREAM_BODY_CAP / 其他引擎一致）。 */
#ifndef CRUCIBLE_SCRIPT_OUT_CAP
#define CRUCIBLE_SCRIPT_OUT_CAP (64u * 1024u * 1024u)
#endif

/* 语言判定：每个 .so 由 -DCRUCIBLE_SCRIPT_LANG 固定一种语言（libapp_python.so /
 * libapp_ruby.so / libapp_perl.so），没有编译期语言时按脚本扩展名推断。
 * 刻意不看 `extra`：Rust 侧现在把 .env 变量以 JSON 形式放在 extra 里（见
 * app_ffi::call_exec），旧实现会把整段 JSON 当成语言名而失败。 */
static const char *lang_name(const char *script)
{
#ifdef CRUCIBLE_SCRIPT_LANG
    (void)script;
    return CRUCIBLE_SCRIPT_LANG;
#else
    if (script) {
        const char *dot = strrchr(script, '.');
        if (dot) {
            if (strcmp(dot, ".rb") == 0)
                return "ruby";
            if (strcmp(dot, ".pl") == 0)
                return "perl";
            if (strcmp(dot, ".py") == 0)
                return "python";
        }
    }
    return "python";
#endif
}

static int resolve_script(const char *script, const char *docroot, const char *lang,
                          char *out, size_t out_sz)
{
    const char *idx = "index.py";
    FILE *f;

    if (script && script[0]) {
        f = fopen(script, "rb");
        if (f) {
            fclose(f);
            snprintf(out, out_sz, "%s", script);
            return 0;
        }
    }
    if (strcmp(lang, "ruby") == 0)
        idx = "index.rb";
    else if (strcmp(lang, "perl") == 0)
        idx = "index.pl";
    snprintf(out, out_sz, "%s/%s", docroot ? docroot : ".", idx);
    f = fopen(out, "rb");
    if (!f)
        return -1;
    fclose(f);
    return 0;
}

/* 显式失败：填 out->error 并返回 -1（不再用 appengine_fill_hello 假装成功）。 */
static int script_fail(AppEngineResult *out, const char *fmt, ...)
{
    char buf[1024];
    va_list ap;

    if (out == NULL)
        return -1;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    appengine_result_alloc(out);
    appengine_result_set_error(out, buf);
    return -1;
}

/* ---------- in-process Python ---------- */
#if defined(CRUCIBLE_HAVE_PYTHON)
#include <Python.h>

/*
 * 每请求隔离 shim（首次请求时安装一次，之后只操作本线程 TLS）。
 *
 * 为什么不逐请求换全局：CPython 在两条字节码之间按 switch interval 释放 GIL，
 * 逐请求改写解释器全局 sys.stdout/os.environ 时，T1 执行到一半会被 T2 改掉全局，
 * T1 之后的 print/环境读取就落到 T2 的响应体/环境上（跨请求数据泄露）。
 * 这里把 sys.stdout / sys.stdin / os.environ 一次性换成**线程感知代理**：
 * 请求期间只在 threading.local 上挂自己的 StringIO / BytesIO / env 覆盖 dict，
 * 代理优先读 TLS；没有 TLS（例如 wsgi/asgi 引擎在同一解释器里跑）时行为不变。
 * 脚本 import sys / import os 拿到的仍是同一模块对象，代理对两者都生效。
 */
static const char *g_shim_src =
    "import collections.abc as _cabc\n"
    "import os as _cos\n"
    "import sys as _csys\n"
    "import threading as _cth\n"
    "_c_tls = _cth.local()\n"
    "class _CrucibleOut:\n"
    "    def __init__(self, real):\n"
    "        self._real = real\n"
    "    def write(self, s):\n"
    "        b = getattr(_c_tls, 'out', None)\n"
    "        if b is not None:\n"
    "            return b.write(s)\n"
    "        return self._real.write(s)\n"
    "    def flush(self):\n"
    "        b = getattr(_c_tls, 'out', None)\n"
    "        if b is not None:\n"
    "            f = getattr(b, 'flush', None)\n"
    "            if f is not None:\n"
    "                return f()\n"
    "            return None\n"
    "        return self._real.flush()\n"
    "    def __getattr__(self, name):\n"
    "        return getattr(self._real, name)\n"
    "class _CrucibleIn:\n"
    "    def __init__(self, real):\n"
    "        self._real = real\n"
    "    def _cur(self):\n"
    "        return getattr(_c_tls, 'inp', None) or self._real\n"
    "    def read(self, *a):\n"
    "        return self._cur().read(*a)\n"
    "    def readline(self, *a):\n"
    "        return self._cur().readline(*a)\n"
    "    def readlines(self, *a):\n"
    "        return self._cur().readlines(*a)\n"
    "    def __iter__(self):\n"
    "        return iter(self._cur())\n"
    "    def __getattr__(self, name):\n"
    "        return getattr(self._real, name)\n"
    "class _CrucibleEnv(_cabc.MutableMapping):\n"
    "    def __init__(self, real, base):\n"
    "        self._real = real\n"
    "        self._base = base\n"
    "    def _ov(self):\n"
    "        return getattr(_c_tls, 'env', None)\n"
    "    def __getitem__(self, k):\n"
    "        ov = self._ov()\n"
    "        if ov is not None:\n"
    "            if k in ov:\n"
    "                v = ov[k]\n"
    "                if v is None:\n"
    "                    raise KeyError(k)\n"
    "                return v\n"
    "            return self._base[k]\n"
    "        return self._real[k]\n"
    "    def __setitem__(self, k, v):\n"
    "        ov = self._ov()\n"
    "        if ov is not None:\n"
    "            ov[k] = v\n"
    "        else:\n"
    "            self._real[k] = v\n"
    "    def __delitem__(self, k):\n"
    "        ov = self._ov()\n"
    "        if ov is not None:\n"
    "            ov[k] = None\n"
    "            return\n"
    "        del self._real[k]\n"
    "    def __iter__(self):\n"
    "        ov = self._ov()\n"
    "        if ov is None:\n"
    "            return iter(self._real)\n"
    "        return iter(self._merged_dict())\n"
    "    def __len__(self):\n"
    "        ov = self._ov()\n"
    "        if ov is None:\n"
    "            return len(self._real)\n"
    "        return len(self._merged_dict())\n"
    "    def _merged_dict(self):\n"
    "        d = dict(self._base)\n"
    "        ov = self._ov()\n"
    "        if ov is not None:\n"
    "            for k, v in ov.items():\n"
    "                if v is None:\n"
    "                    d.pop(k, None)\n"
    "                else:\n"
    "                    d[k] = v\n"
    "        return d\n"
    "    def copy(self):\n"
    "        ov = self._ov()\n"
    "        return self._merged_dict() if ov is not None else dict(self._real)\n"
    "_cos.environ = _CrucibleEnv(_cos.environ, _crucible_base)\n"
    "_csys.stdout = _CrucibleOut(_csys.stdout)\n"
    "_csys.stdin = _CrucibleIn(_csys.stdin)\n"
    "def _cr_set(out, inp, env):\n"
    "    _c_tls.out = out\n"
    "    _c_tls.inp = inp\n"
    "    _c_tls.env = env\n"
    "def _cr_clear():\n"
    "    _c_tls.out = None\n"
    "    _c_tls.inp = None\n"
    "    _c_tls.env = None\n";

static PyObject *g_shim_set;   /* _cr_set(out, inp, env) */
static PyObject *g_shim_clear; /* _cr_clear() */

/* ---- 解释器全局 os.environ 视图 ↔ 启动期基底 ----
 *
 * CPython 的 os.environ 是 import 时从 posix.environ 拷出的**快照**（_data），
 * 之后的 setenv 它看不见。嵌入解释器在**第一个请求**里才 Py_Initialize —— 那一刻
 * 进程 env 里可能装着**别的引擎**（wsgi/asgi/uwsgi）请求期 `.env`，于是这些键被
 * 永久烤进 os.environ 的视图。旧实现只在首次安装 shim 时清理**本请求**的键：
 * 别的引擎留下的键（本请求没有的不删）会一直留在视图里 —— 真机组合：
 * wsgi 带 `.env` 先跑过，随后 python 引擎的「无 .env」应用读到 `WINDOWMARK=...`。
 *
 * 正确语义：**真正执行 Py_Initialize 的那一刻**（在共享初始化锁内，见
 * py_env_scrub_on_init）把视图对齐到「启动期基底」（appengine_set_base_env 交来的
 * 快照，绝不含任何请求期 .env）：
 *   * 视图里不在基底中的键 → 删除（初始化瞬间装进 C environ 的请求期 .env）；
 *   * 基底键与视图值不同/缺失 → 写回基底值（运维环境照旧可见）。
 * 为什么是「初始化时一次」而不是每请求：每请求清理会在别的引擎（wsgi/asgi）
 * 同步窗口写入后把它们刚写的键删掉（跨引擎 `<unset>` 竞态）；初始化时锁内的
 * 清理则天然互斥（等待初始化的引擎还没开始同步）。
 * 本请求 `.env` 不写进视图：它只进线程本地覆盖表（见 py_extra_env_cb），并发请求
 * 之间不串值。整个函数只碰 `_data`（PyDict_*，纯 C），不 putenv/unsetenv ——
 * C environ 的安装/卸载只归宿主的 env_lock 管（与 pyembed 的同步窗口同一纪律）。
 * 键值是 fsencode 后的 bytes（POSIX _Environ 的命名空间）。 */
#ifndef _WIN32
static const char *py_base_env_lookup(const char *key, size_t klen, size_t *vlen)
{
    const char *base = appengine_base_env_block();
    const char *p;

    if (base == NULL)
        return NULL;
    for (p = base; *p != '\0'; p += strlen(p) + 1) {
        const char *eq = strchr(p, '=');

        if (eq != NULL && (size_t)(eq - p) == klen && memcmp(p, key, klen) == 0) {
            if (vlen != NULL)
                *vlen = strlen(eq + 1);
            return eq + 1;
        }
    }
    return NULL;
}

/* 启动期基底 → Python dict（str 键值）。shim 的请求期环境视图只读它（+ TLS 覆盖
 * 表），**不回退到全局 `_data`** —— 后者可能正装着别的引擎（wsgi/asgi）的 `.env`
 * 窗口值，而 python 引擎自报 env-free 后会与它们并发执行（读别人的秘密）。
 * 须持 GIL。 */
static PyObject *py_base_env_dict(void)
{
    const char *base = appengine_base_env_block();
    const char *p;
    PyObject *d;

    d = PyDict_New();
    if (d == NULL) {
        PyErr_Clear();
        return NULL;
    }
    for (p = base; base != NULL && *p != '\0'; p += strlen(p) + 1) {
        const char *eq = strchr(p, '=');
        PyObject *k, *v;

        if (eq == NULL || eq == p)
            continue;
        k = PyUnicode_FromStringAndSize(p, (Py_ssize_t)(eq - p));
        if (k == NULL) {
            PyErr_Clear();
            continue;
        }
        v = PyUnicode_FromString(eq + 1);
        if (v != NULL) {
            if (PyDict_SetItem(d, k, v) != 0)
                PyErr_Clear();
            Py_DECREF(v);
        } else {
            PyErr_Clear();
        }
        Py_DECREF(k);
    }
    return d;
}

/* 取解释器真实的 os.environ 底层 dict（代理形态沿 `_real` 链向下找 `_data`，
 * 最多 16 层防御）；返回新引用。 */
static PyObject *py_real_environ_data(void)
{
    PyObject *os_mod, *env, *cur, *data = NULL;
    int depth;

    os_mod = PyImport_ImportModule("os");
    if (os_mod == NULL) {
        PyErr_Clear();
        return NULL;
    }
    env = PyObject_GetAttrString(os_mod, "environ");
    Py_DECREF(os_mod);
    if (env == NULL) {
        PyErr_Clear();
        return NULL;
    }
    cur = env; /* 所有权转给 cur */
    for (depth = 0; depth < 16 && cur != NULL; depth++) {
        PyObject *next;

        data = PyObject_GetAttrString(cur, "_data");
        if (data != NULL)
            break;
        PyErr_Clear();
        next = PyObject_GetAttrString(cur, "_real"); /* _CrucibleEnv 代理 */
        Py_DECREF(cur);
        cur = next;
        if (cur == NULL)
            PyErr_Clear();
    }
    Py_XDECREF(cur);
    if (data == NULL)
        PyErr_Clear();
    return data;
}

/* 把 os.environ 视图对齐到启动期基底（见上面的长注释）。须持 GIL。 */
static void py_env_reconcile_to_base(void)
{
    PyObject *data;
    PyObject *keys;
    Py_ssize_t i, n;
    const char *base;

    base = appengine_base_env_block();
    if (base == NULL)
        return; /* 宿主未提供基底（旧宿主）：保持旧行为，绝不清空视图 */
    data = py_real_environ_data();
    if (data == NULL)
        return;
    keys = PyDict_Keys(data);
    if (keys == NULL) {
        PyErr_Clear();
        Py_DECREF(data);
        return;
    }
    n = PyList_GET_SIZE(keys);
    for (i = 0; i < n; i++) {
        PyObject *key = PyList_GET_ITEM(keys, i); /* 借用 */
        PyObject *cur;
        const char *k, *bv;
        Py_ssize_t klen;
        size_t vlen = 0;

        if (!PyBytes_Check(key))
            continue; /* 非 POSIX 形态（例如 Windows 大写化）：不碰 */
        k = PyBytes_AS_STRING(key);
        klen = PyBytes_GET_SIZE(key);
        bv = py_base_env_lookup(k, (size_t)klen, &vlen);
        if (bv == NULL) {
            if (PyDict_DelItem(data, key) != 0)
                PyErr_Clear();
            continue;
        }
        cur = PyDict_GetItem(data, key); /* 借用 */
        if (cur != NULL && PyBytes_Check(cur)) {
            char *cs = NULL;
            Py_ssize_t cn = 0;

            if (PyBytes_AsStringAndSize(cur, &cs, &cn) == 0 && (size_t)cn == vlen &&
                memcmp(cs, bv, vlen) == 0)
                continue; /* 已与基底一致 */
        }
        PyErr_Clear();
        {
            PyObject *val = PyBytes_FromStringAndSize(bv, (Py_ssize_t)vlen);

            if (val == NULL) {
                PyErr_Clear();
                continue;
            }
            if (PyDict_SetItem(data, key, val) != 0)
                PyErr_Clear();
            Py_DECREF(val);
        }
    }
    Py_DECREF(keys);
    /* 基底里有、视图里没有的键：补上（无 .env 的应用仍要看到运维环境）。 */
    {
        const char *p;

        for (p = base; *p != '\0'; p += strlen(p) + 1) {
            const char *eq = strchr(p, '=');
            PyObject *key, *val;

            if (eq == NULL || eq == p)
                continue;
            key = PyBytes_FromStringAndSize(p, (Py_ssize_t)(eq - p));
            if (key == NULL) {
                PyErr_Clear();
                continue;
            }
            if (PyDict_Contains(data, key) == 1) {
                Py_DECREF(key);
                continue;
            }
            PyErr_Clear();
            val = PyBytes_FromString(eq + 1);
            if (val != NULL) {
                if (PyDict_SetItem(data, key, val) != 0)
                    PyErr_Clear();
                Py_DECREF(val);
            } else {
                PyErr_Clear();
            }
            Py_DECREF(key);
        }
    }
    PyErr_Clear();
    Py_DECREF(data);
}
#endif /* !_WIN32 */

/* 安装 shim；失败返回 -1（已经带着异常，调用方清掉并显式报错）。
 * extra 仅用于**首次**安装时清理初始化快照（见上）。 */
#ifndef _WIN32
/* 首次安装的并发保护：guard 与「写 g_shim_set」之间隔着 PyRun_StringFlags，
 * 而字节码执行会在 switch interval 处释放 GIL —— 并发冷启动时多个线程都会看到
 * g_shim_set==NULL，各自执行一遍 shim 源码：os.environ 被套上 N 层 _CrucibleEnv
 * （每层有自己的 _c_tls 命名空间），请求级覆盖表只对其中一层生效，且层数随
 * 并发首请求无界增长。这里用 mutex+cond 串行化；等待者必须**先放 GIL** 再等，
 * 否则持 GIL 等 mutex、持有者又需要 GIL 才能跑完 PyRun ⇒ ABBA 死锁。 */
static pthread_mutex_t g_shim_mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_shim_cond = PTHREAD_COND_INITIALIZER;
static int g_shim_state; /* 0=未安装/失败 1=安装中 2=已安装 */
#endif

static int python_shim_install(const char *extra)
{
    PyObject *ns, *r;
    int rc = 0;

    (void)extra; /* 请求级 .env 由 TLS 覆盖表负责；视图对齐见 py_env_scrub_on_init */
    if (g_shim_set != NULL)
        return 0;
#ifndef _WIN32
    pthread_mutex_lock(&g_shim_mtx);
    while (g_shim_state == 1) {
        Py_BEGIN_ALLOW_THREADS
        pthread_cond_wait(&g_shim_cond, &g_shim_mtx);
        Py_END_ALLOW_THREADS
    }
    if (g_shim_state == 2) {
        pthread_mutex_unlock(&g_shim_mtx);
        return 0;
    }
    g_shim_state = 1;
    pthread_mutex_unlock(&g_shim_mtx);
#endif
    ns = PyDict_New();
    if (ns == NULL) {
        rc = -1;
        goto out;
    }
    /* shim 源码引用 `_crucible_base`（启动期基底；请求期视图 = 它 + TLS 覆盖表）。 */
    {
        PyObject *base = NULL;
#ifndef _WIN32
        base = py_base_env_dict();
#endif
        if (base == NULL)
            base = PyDict_New();
        if (base != NULL) {
            if (PyDict_SetItemString(ns, "_crucible_base", base) != 0)
                PyErr_Clear();
            Py_DECREF(base);
        } else {
            PyErr_Clear();
        }
    }
    r = PyRun_StringFlags(g_shim_src, Py_file_input, ns, ns, NULL);
    if (r == NULL) {
        PyErr_Print();
        Py_DECREF(ns);
        rc = -1;
        goto out;
    }
    Py_DECREF(r);
    g_shim_set = PyDict_GetItemString(ns, "_cr_set");     /* 借用 */
    g_shim_clear = PyDict_GetItemString(ns, "_cr_clear"); /* 借用 */
    if (g_shim_set == NULL || g_shim_clear == NULL) {
        Py_DECREF(ns);
        fprintf(stderr, "scriptffi: python 隔离 shim 缺少入口函数\n");
        rc = -1;
        goto out;
    }
    Py_INCREF(g_shim_set);
    Py_INCREF(g_shim_clear);
    Py_DECREF(ns); /* 函数对象经 __globals__ 自持 shim 命名空间 */

    /* 解释器视图的清理不在这里做：它由**真正执行 Py_Initialize 的那一次**在共享
     * 初始化锁内完成（见 py_env_scrub_on_init / py_env_reconcile_to_base）—— 只清
     * 本请求键的旧做法会让别的引擎先初始化时留下的 .env 残值永久可见。 */
out:
#ifndef _WIN32
    pthread_mutex_lock(&g_shim_mtx);
    g_shim_state = (rc == 0) ? 2 : 0; /* 失败回到 0：下一个请求可重试（旧语义） */
    pthread_cond_broadcast(&g_shim_cond);
    pthread_mutex_unlock(&g_shim_mtx);
#endif
    return rc;
}

/* 初始化回调（crucible_pyinit_ensure_cb 的 v2 形状）：在共享初始化锁内、初始化
 * 线程已 SaveThread 之后调用 —— 这里自己取/放 GIL。**只在真正执行 Py_Initialize
 * 的那一次**运行，因此不会与其它引擎在飞的 `.env` 窗口竞速（等待初始化的引擎
 * 还被挡在锁外，尚未同步视图）。 */
#ifndef _WIN32
static void py_env_scrub_on_init(void)
{
    PyGILState_STATE gil;

    if (!Py_IsInitialized())
        return;
    gil = PyGILState_Ensure();
    py_env_reconcile_to_base();
    PyGILState_Release(gil);
}
#endif /* !_WIN32 */

#ifdef _WIN32
#define CRUCIBLE_PY_SCRUB_ON_INIT NULL
#else
#define CRUCIBLE_PY_SCRUB_ON_INIT py_env_scrub_on_init
#endif

/* 脚本所在目录（写进 out，返回 out 或 NULL）。 */
static const char *script_dirname(const char *path, char *out, size_t outsz)
{
    const char *slash;
    size_t n;

    if (path == NULL || out == NULL || outsz == 0)
        return NULL;
    slash = strrchr(path, '/');
    if (slash == NULL)
        return ".";
    n = (size_t)(slash - path);
    if (n == 0)
        return "/";
    if (n >= outsz)
        n = outsz - 1;
    memcpy(out, path, n);
    out[n] = '\0';
    return out;
}

static void py_env_put(PyObject *d, const char *k, const char *v)
{
    PyObject *o = PyUnicode_FromString(v != NULL ? v : "");

    if (o != NULL) {
        (void)PyDict_SetItemString(d, k, o);
        Py_DECREF(o);
    }
}

/* ABI 请求头块 → 脚本环境 HTTP_*（CGI 语义；值按 Latin-1 落地，obs-text 不丢）。 */
struct py_env_hdr_ctx {
    PyObject *env;
};

static int py_env_put_http_cb(void *ctx, const char *name, size_t name_len,
                              const char *value, size_t value_len)
{
    struct py_env_hdr_ctx *c = (struct py_env_hdr_ctx *)ctx;
    char key[262];
    PyObject *o;

    if (c == NULL || c->env == NULL)
        return 1;
    if (appengine_cgi_http_key(key, sizeof(key), name, name_len) == 0)
        return 0;
    o = PyUnicode_DecodeLatin1(value, (Py_ssize_t)value_len, NULL);
    if (o == NULL) {
        PyErr_Clear();
        return 0;
    }
    (void)PyDict_SetItemString(c->env, key, o);
    Py_DECREF(o);
    return 0;
}

/* extra JSON 的 "env"（本请求 .env）→ 本线程环境覆盖表（TLS，见 _CrucibleEnv）。
 *
 * 为什么必须在这里补：Rust 侧把 .env 装进的是 **C environ**（env_lock 的 setenv），
 * 而 CPython 的 os.environ 是 import 时从 posix.environ 建出的缓存映射，之后的
 * setenv 它看不见 —— 所以脚本里 os.environ/os.getenv 读不到自己的 .env（wsgi/asgi
 * 走 pyembed 的同步窗口，cgi 直接构造子进程 envp，只有 python 脚本引擎漏了）。
 * 这里按请求落进 TLS 覆盖表：不碰进程 env、不碰解释器全局 os.environ 的 _data，
 * 因此同组 8 并发各自都能看到、不同组互不污染、请求结束即消失（无残值）。
 *
 * `.env` 的 `KEY=`（空值）= 该键不存在（与 env_lock::install 的 remove_var 及
 * cgi 子进程 envp 语义一致）：用 Python None 占位，_CrucibleEnv 读到 None 抛
 * KeyError 且**不回退**到真实 os.environ（基底里若有同名键也必须视为已删除）。 */
struct py_extra_env_ctx {
    PyObject *env;
};

static int py_extra_env_cb(void *ctx, const char *k, const char *v)
{
    struct py_extra_env_ctx *c = (struct py_extra_env_ctx *)ctx;
    PyObject *o;

    if (c == NULL || c->env == NULL || k == NULL)
        return 1;
    if (v == NULL || v[0] == '\0') {
        o = Py_None;
        Py_INCREF(o);
    } else {
        /* .env 值按 UTF-8 + surrogateescape 落地（与 os.environ 对非 UTF-8 的
         * fsdecode 语义一致；纯 UTF-8 时行为不变）。 */
        o = PyUnicode_DecodeUTF8(v, (Py_ssize_t)strlen(v), "surrogateescape");
        if (o == NULL) {
            PyErr_Clear();
            return 0;
        }
    }
    if (PyDict_SetItemString(c->env, k, o) != 0)
        PyErr_Clear();
    Py_DECREF(o);
    return 0;
}

static int run_python_inprocess(const char *script, const char *method, const char *path,
                                const char *query, const char *content_type,
                                const char *body, size_t body_len, const char *remote,
                                const char *headers, const char *extra, char **out_body,
                                size_t *out_len)
{
    FILE *fp = NULL;
    PyObject *io_mod = NULL, *buf = NULL, *stdin_obj = NULL, *envdict = NULL;
    PyObject *getvalue = NULL, *result = NULL, *sys_mod = NULL, *sys_path = NULL;
    PyObject *globals = NULL;
    PyGILState_STATE gil;
    char errbuf[256];
    char lenbuf[32];
    char dirbuf[1024];
    const char *dir;
    int rc = -1, shim_active = 0;

    /* 跨 .so 共享初始化锁：并发冷启动只有一个线程真正 Py_Initialize。
     * PyEval_SaveThread 的返回类型是 PyThreadState*，共享 ABI 用 void*（宽度一致）；
     * 新 GCC（15）把「函数指针类型不兼容」从告警升级为错误，故显式转换。 */
    if (crucible_pyinit_ensure_cb(Py_IsInitialized, Py_Initialize,
                                  (void *(*)(void))PyEval_SaveThread,
                                  CRUCIBLE_PY_SCRUB_ON_INIT, errbuf, sizeof(errbuf)) != 0) {
        fprintf(stderr, "scriptffi: CPython 初始化失败: %s\n", errbuf);
        return -1;
    }
    gil = PyGILState_Ensure(); /* 每请求拿 GIL；与 wsgi/asgi/uwsgi 共用同一解释器 */

    if (python_shim_install(extra) != 0)
        goto done;
    PyErr_Clear();

    io_mod = PyImport_ImportModule("io");
    if (io_mod == NULL)
        goto done;
    buf = PyObject_CallMethod(io_mod, "StringIO", NULL);
    /* 请求体 → 本线程 stdin（显式长度，NUL 安全；即使为空也置空 BytesIO，
     * 脚本读 stdin 不会阻塞在真实 tty 上）。*/
    stdin_obj = PyObject_CallMethod(io_mod, "BytesIO", "y#", body != NULL ? body : "",
                                    (Py_ssize_t)(body != NULL ? body_len : 0));
    Py_DECREF(io_mod);
    io_mod = NULL;
    if (buf == NULL || stdin_obj == NULL)
        goto done;

    /* 本请求的环境视图（不触碰进程 environ / 解释器全局 os.environ）。 */
    envdict = PyDict_New();
    if (envdict == NULL)
        goto done;
    py_env_put(envdict, "REQUEST_METHOD", method != NULL ? method : "GET");
    py_env_put(envdict, "PATH_INFO", path != NULL ? path : "/");
    py_env_put(envdict, "QUERY_STRING", query != NULL ? query : "");
    py_env_put(envdict, "REMOTE_ADDR", remote != NULL ? remote : "");
    py_env_put(envdict, "SCRIPT_FILENAME", script);
    if (content_type != NULL && content_type[0] != '\0')
        py_env_put(envdict, "CONTENT_TYPE", content_type);
    snprintf(lenbuf, sizeof(lenbuf), "%lu", (unsigned long)body_len);
    py_env_put(envdict, "CONTENT_LENGTH", lenbuf);
    /* 请求头 → HTTP_*（CGI 语义）。envdict 每请求新建，无陈旧头问题。 */
    {
        struct py_env_hdr_ctx hctx;

        hctx.env = envdict;
        (void)appengine_headers_foreach(headers, py_env_put_http_cb, &hctx);
    }
    /* 本请求 .env（extra JSON 的 "env"）→ 同一张 TLS 覆盖表。
     * 放在 CGI/HTTP_* 之后：与 cgi 引擎的 envp 顺序一致（.env 同名键优先）。 */
    {
        struct py_extra_env_ctx ectx;

        ectx.env = envdict;
        (void)appengine_extra_env_foreach(extra, py_extra_env_cb, &ectx);
    }

    /* 挂 TLS 捕获（第三次失败也不致命：脚本仍能跑，只是没有请求上下文）。 */
    result = PyObject_CallFunctionObjArgs(g_shim_set, buf, stdin_obj, envdict, NULL);
    if (result == NULL) {
        fprintf(stderr, "scriptffi: 挂载请求隔离上下文失败\n");
        PyErr_Print();
        goto done;
    }
    Py_CLEAR(result);
    shim_active = 1;

    /* sys.path 前置脚本目录：应用 import 同目录模块时必需。逐请求插入要**去重**，
     * 否则 sys.path 会随请求数无界增长（旧实现的全局残留）。 */
    sys_mod = PyImport_ImportModule("sys");
    if (sys_mod != NULL) {
        sys_path = PyObject_GetAttrString(sys_mod, "path");
        if (sys_path != NULL) {
            dir = script_dirname(script, dirbuf, sizeof(dirbuf));
            if (dir != NULL) {
                PyObject *d = PyUnicode_FromString(dir);
                if (d != NULL) {
                    int has = PySequence_Contains(sys_path, d);
                    if (has == 0)
                        (void)PyList_Insert(sys_path, 0, d);
                    Py_DECREF(d);
                }
            }
        }
    }
    PyErr_Clear();

    /* 每请求独立命名空间：不共享 __main__ 的模块级变量/函数（F1）。 */
    globals = PyDict_New();
    if (globals == NULL)
        goto done;
    {
        PyObject *v = PyUnicode_FromString("__main__");
        if (v != NULL) {
            (void)PyDict_SetItemString(globals, "__name__", v);
            Py_DECREF(v);
        }
        v = PyUnicode_FromString(script);
        if (v != NULL) {
            (void)PyDict_SetItemString(globals, "__file__", v);
            Py_DECREF(v);
        }
        {
            PyObject *bi = PyImport_ImportModule("builtins");
            if (bi != NULL) {
                PyObject *bd = PyModule_GetDict(bi); /* 借用 */
                if (bd != NULL)
                    (void)PyDict_SetItemString(globals, "__builtins__", bd);
                Py_DECREF(bi);
            }
        }
    }

    fp = fopen(script, "r");
    if (fp == NULL)
        goto done;
    /* 返回值必须检查：脚本抛异常时旧实现继续读空 StringIO → 200 + 空 body
     * （静默失败）。这里 NULL ⇒ rc = -2，调用方给出准确错误文本；
     * PyRun_FileExFlags 未打印的 traceback 由我们补打到服务端日志。 */
    result = PyRun_FileExFlags(fp, script, Py_file_input, globals, globals, 1, NULL);
    fp = NULL; /* 已由 CPython 关闭 */
    if (result == NULL) {
        if (PyErr_Occurred())
            PyErr_Print();
        PyErr_Clear();
        rc = -2;
        goto done;
    }
    Py_CLEAR(result);

    getvalue = PyObject_GetAttrString(buf, "getvalue");
    result = getvalue != NULL ? PyObject_CallObject(getvalue, NULL) : NULL;
    if (result != NULL && PyUnicode_Check(result)) {
        Py_ssize_t sz = 0;
        const char *s = PyUnicode_AsUTF8AndSize(result, &sz);
        if (s != NULL) {
            if (sz < 0 || (size_t)sz > CRUCIBLE_SCRIPT_OUT_CAP) {
                fprintf(stderr, "scriptffi: python 脚本输出超过 %u 字节上限\n",
                        CRUCIBLE_SCRIPT_OUT_CAP);
                rc = -2;
                goto done;
            }
            {
                char *b = (char *)malloc((size_t)sz + 1);
                if (b != NULL) {
                    memcpy(b, s, (size_t)sz);
                    b[sz] = '\0';
                    *out_body = b;
                    *out_len = (size_t)sz;
                    rc = 0;
                }
            }
        }
    }

done:
    if (fp != NULL)
        fclose(fp);
    if (shim_active && g_shim_clear != NULL) {
        PyObject *r = PyObject_CallObject(g_shim_clear, NULL);
        if (r != NULL)
            Py_DECREF(r);
    }
    Py_XDECREF(globals);
    Py_XDECREF(sys_path);
    Py_XDECREF(sys_mod);
    Py_XDECREF(result);
    Py_XDECREF(getvalue);
    Py_XDECREF(envdict);
    Py_XDECREF(stdin_obj);
    Py_XDECREF(buf);
    Py_XDECREF(io_mod);
    PyErr_Clear(); /* 不留悬挂异常给下一次调用 */
    PyGILState_Release(gil);
    return rc;
}
#endif /* CRUCIBLE_HAVE_PYTHON */

/* ---------- in-process Ruby ---------- */
#if defined(CRUCIBLE_HAVE_RUBY)
#include <ruby.h>

struct ruby_job {
    const char *script;
    const char *method;
    const char *path;
    const char *query;
    const char *content_type;
    const char *body;
    size_t body_len;
    const char *remote;
    const char *headers;
    char *out_body;
    size_t out_len;
    int rc;
};

#ifndef _WIN32
/* MRI 不是「加锁就能多线程用」的库：`ruby_init()` 建立 VM/GVL 时绑定的是**调用它的
 * 那个线程**，之后从别的线程直接调 rb_*（哪怕持锁）会踩空 GVL/线程本地状态 —— 实测
 * 表现是 libapp_ruby.so 里 `rb_bug_for_fatal_signal` → SIGSEGV 整个进程（core 里
 * 栈是 sigsegv → rb_bug_for_fatal_signal → ruby_default_signal）。
 *
 * 所以这里不「谁拿到锁谁执行」，而是**常驻一个专用 MRI 线程**：它自己完成
 * RUBY_INIT_STACK / ruby_init / ruby_options，之后只由它执行脚本；请求线程把 job
 * 放进深度 1 的队列并阻塞等结果（g_ruby_call_mtx 串行化调用者，等价于原来的全局锁）。
 * rack 引擎里同样的坑（libs/app-engines/rack）也是靠这套纪律才稳。 */
#include <pthread.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/file.h>

/* 进程级「谁拥有 MRI VM」选举标记。MRI 的 VM/GVL 是**进程全局且线程亲和**的：
 * ruby_init() 只能在同一个原生线程里调用一次；第二个嵌入式 Ruby 引擎（本引擎与
 * libapp_rack）再调 ruby_init_loadpath() 会直接 SIGSEGV（core 栈
 * rb_wb_protected_newobj_of ← ruby_init_loadpath ← ruby_thread_main）。
 * 两个 .so 之间唯一的共享面是 libc/文件系统，故用 flock + env 标记做跨 .so 选举：
 * 先启动者在持锁期间完成 boot 并 setenv 标记；后来者看到标记就**显式失败**（502），
 * 而不是把整个 webserver 打崩。默认构建里 ruby embed 关、rack embed 开，不会走到这里。 */
#define RUBY_BOOT_MARKER "CRUCIBLE_EMBED_RUBY_BOOTED"

static int ruby_boot_lock_acquire(void)
{
    const char *tmp = getenv("TMPDIR");
    char path[PATH_MAX];
    int fd;

    if (tmp == NULL || tmp[0] == '\0')
        tmp = "/tmp";
    if (snprintf(path, sizeof(path), "%s/crucible-embed-ruby.lock", tmp) >=
        (int)sizeof(path))
        return -1;
    fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0)
        return -1;
    while (flock(fd, LOCK_EX) != 0) {
        if (errno != EINTR) {
            close(fd);
            return -1;
        }
    }
    return fd;
}

static void ruby_boot_lock_release(int fd)
{
    if (fd < 0)
        return;
    (void)flock(fd, LOCK_UN);
    close(fd);
}

/* 钉住 libruby（RTLD_NODELETE）：app_ffi 热卸载会 dlclose(libapp_ruby.so)，libruby
 * 是其 DT_NEEDED；若引用计数归零会被解除映射，而 MRI 的定时器线程仍在里面跑 →
 * 之后必 SIGSEGV。rack 引擎有同样的保护（rack_pin_libruby）。 */
static void ruby_pin_libruby(void)
{
#ifdef RTLD_NODELETE
    char soname[128];
    const char *cands[6];
    int n = 0;
    int state = 0;
    int i;
    VALUE v;

    v = rb_eval_string_protect(
        "(defined?(RbConfig) ? RbConfig::CONFIG['LIBRUBY_SO'] : nil).to_s", &state);
    if (state == 0 && RB_TYPE_P(v, T_STRING)) {
        long len = RSTRING_LEN(v);

        if (len > 0 && (size_t)len < sizeof(soname)) {
            memcpy(soname, RSTRING_PTR(v), (size_t)len);
            soname[len] = '\0';
            cands[n++] = soname;
        }
    } else if (state != 0) {
        rb_set_errinfo(Qnil);
    }
    cands[n++] = "libruby-3.3.so.3.3";
    cands[n++] = "libruby.so.3.3";
    cands[n++] = "libruby34.so.0.0";
    cands[n++] = "libruby.so";
    for (i = 0; i < n; i++) {
        void *h = dlopen(cands[i], RTLD_NOW | RTLD_GLOBAL | RTLD_NODELETE);

        if (h != NULL)
            return; /* 句柄故意不关：常驻映射，直到进程退出 */
    }
#endif
}

static pthread_mutex_t g_ruby_call_mtx = PTHREAD_MUTEX_INITIALIZER; /* 串行化调用者 */
static pthread_mutex_t g_ruby_q_mtx = PTHREAD_MUTEX_INITIALIZER;    /* job 交接 */
static pthread_cond_t g_ruby_q_cond = PTHREAD_COND_INITIALIZER;     /* 工作线程等 job */
static pthread_cond_t g_ruby_done_cond = PTHREAD_COND_INITIALIZER;  /* 调用者等完成 */
static pthread_cond_t g_ruby_boot_cond = PTHREAD_COND_INITIALIZER;  /* 调用者等 boot */
static struct ruby_job *g_ruby_pending;
static int g_ruby_job_done;
static int g_ruby_boot_state;   /* 0=booting 1=ready -2=VM 已被别的 .so 拥有 */
static int g_ruby_thread_state; /* 0=未建 1=已建 -1=建线程/boot 失败 */
#define RUBY_LOCK()   pthread_mutex_lock(&g_ruby_call_mtx)
#define RUBY_UNLOCK() pthread_mutex_unlock(&g_ruby_call_mtx)
#else
#define RUBY_LOCK()   ((void)0)
#define RUBY_UNLOCK() ((void)0)
#endif

/* ENV 的写入**不能**用 rb_hash_aset()。
 *
 * MRI 的 ENV 不是 T_HASH：它是一个 T_DATA（`ruby -e 'p ENV.class'` → Object；
 * rb_type(ENV)==T_DATA）。rb_hash_aset() 先 rb_hash_modify() 再把参数当
 * `struct RHash *` 直接访问 st_table 指针，等于按 RHash 布局改写 RData 的内存 ⇒
 * 堆损坏。损坏不会立刻报错（本请求仍返回 200），而是在**下一次 GC 标记**时爆炸：
 *
 *   [BUG] try to mark T_NONE object        （webserver，request 13）
 *   [BUG] rb_gc_mark(): unknown data type 0x18 ... corrupted object
 *                                          （C harness，request 11）
 *   C 栈：rb_bug ← gc_mark ← rb_imemo_new/新对象分配 ← rb_parser_compile_string_path
 *
 * 复现（本机，Ruby 3.3.8，见 .agents/1009/reports/rubyembed-wave19.md）：
 *   顺序 /ruby/ ×13 → SIGABRT（core 496MB）；
 *   同一脚本把 rb_hash_aset 换成 ENV[key]=value（rb_funcall）→ 1000 请求 0 崩。
 * rack 引擎一直稳定也印证：它只对**普通 Hash**（$crucible_req）调 rb_hash_aset，
 * 从不碰 ENV。
 *
 * 用 rb_funcall 走 ENV 自己的 `[]=` 实现：既更新内部 env 表也做 libc setenv，
 * 与 Ruby 侧 `ENV[k]=v` 完全同义。 */
static void ruby_env_set(VALUE env, const char *key, VALUE val)
{
    rb_funcall(env, rb_intern("[]="), 2, rb_str_new_cstr(key), val);
}

static void ruby_env_set_cstr(VALUE env, const char *key, const char *val)
{
    ruby_env_set(env, key, rb_str_new_cstr(val != NULL ? val : ""));
}

/* ENV 是解释器级全局：清掉上一请求残留的 HTTP_*，避免请求 A 的 Cookie/Authorization
 * 在请求 B（未带该头）里仍然可见。 */
static void ruby_env_clear_http(VALUE env)
{
    int state = 0;

    (void)rb_eval_string_protect(
        "ENV.delete_if { |k, _| k.to_s.start_with?('HTTP_') }", &state);
    if (state != 0)
        rb_set_errinfo(Qnil);
    (void)env;
}

struct ruby_env_hdr_ctx {
    VALUE env;
};

static int ruby_env_put_http_cb(void *ctx, const char *name, size_t name_len,
                                const char *value, size_t value_len)
{
    struct ruby_env_hdr_ctx *c = (struct ruby_env_hdr_ctx *)ctx;
    char key[262];

    if (c == NULL)
        return 1;
    if (appengine_cgi_http_key(key, sizeof(key), name, name_len) == 0)
        return 0;
    ruby_env_set(c->env, key, rb_str_new(value, (long)value_len));
    return 0;
}

/* 一个 job 的实际执行：**只能在 MRI 专用线程上调用**（VM 已就绪，无需加锁）。 */
static int ruby_exec_job(struct ruby_job *job)
{
    int state = 0;
    VALUE out;
    char lenbuf[32];
    int rc = -1;
    const char *script = job->script;
    const char *method = job->method;
    const char *path = job->path;
    const char *query = job->query;
    const char *content_type = job->content_type;
    const char *body = job->body;
    size_t body_len = job->body_len;
    const char *remote = job->remote;
    const char *headers = job->headers;

    ruby_script(script);
    /* ENV inject（含请求体长度/类型；P2 body 丢失修复）。 */
    {
        VALUE env = rb_const_get(rb_cObject, rb_intern("ENV"));
        ruby_env_set_cstr(env, "REQUEST_METHOD", method ? method : "GET");
        ruby_env_set_cstr(env, "PATH_INFO", path ? path : "/");
        ruby_env_set_cstr(env, "QUERY_STRING", query ? query : "");
        ruby_env_set_cstr(env, "REMOTE_ADDR", remote ? remote : "");
        ruby_env_set_cstr(env, "SCRIPT_FILENAME", script);
        snprintf(lenbuf, sizeof(lenbuf), "%lu", (unsigned long)body_len);
        ruby_env_set_cstr(env, "CONTENT_LENGTH", lenbuf);
        if (content_type != NULL && content_type[0] != '\0')
            ruby_env_set_cstr(env, "CONTENT_TYPE", content_type);
        /* 请求头 → HTTP_*（CGI 语义）。 */
        ruby_env_clear_http(env);
        {
            struct ruby_env_hdr_ctx hctx;

            hctx.env = env;
            (void)appengine_headers_foreach(headers, ruby_env_put_http_cb, &hctx);
        }
    }
    /* 请求体 → $__crucible_body（rb_str_new 显式长度，NUL 不截断）→ $stdin。
     * 注意 rb_gv_set 的形参是 **const char***（不是 ID）：旧代码传 rb_intern(...)
     * 在 Ruby 3.3 头文件 + GCC 14+（int-conversion 默认报错）下直接编译失败，
     * 导致 CRUCIBLE_ENABLE_RUBY_EMBED=1 永远只能降级 embed-missing。 */
    rb_gv_set("$__crucible_body",
              rb_str_new(body != NULL ? body : "", (long)body_len));
    /* Capture $stdout with StringIO when available; else eval and stringify.
     * 请求结束（eval 的 ensure）恢复 $stdout/$stdin，不把捕获缓冲留在全局。 */
    rb_eval_string_protect(
        "begin; require 'stringio'; "
        "$__crucible_out = StringIO.new; "
        "$__crucible_old_stdout = $stdout; $stdout = $__crucible_out; "
        "$__crucible_old_stdin = $stdin; $stdin = StringIO.new($__crucible_body.to_s); "
        "rescue LoadError; $__crucible_out = nil; end",
        &state);
    rb_load_protect(rb_str_new_cstr(script), 0, &state);
    if (state != 0)
        rb_set_errinfo(Qnil); /* 不把上一请求的异常对象挂到下一请求 */
    out = rb_eval_string_protect(
        "begin; r = $__crucible_out ? $__crucible_out.string : ''; "
        "ensure; $stdout = $__crucible_old_stdout if $__crucible_old_stdout; "
        "$stdin = $__crucible_old_stdin if $__crucible_old_stdin; end; r",
        &state);
    if (state == 0 && TYPE(out) == T_STRING) {
        long n = RSTRING_LEN(out);
        if (n < 0 || (unsigned long)n > CRUCIBLE_SCRIPT_OUT_CAP) {
            fprintf(stderr, "scriptffi: ruby 脚本输出超过 %u 字节上限\n",
                    CRUCIBLE_SCRIPT_OUT_CAP);
        } else {
            char *b = (char *)malloc((size_t)n + 1);
            if (b != NULL) {
                memcpy(b, RSTRING_PTR(out), (size_t)n);
                b[n] = '\0';
                job->out_body = b;
                job->out_len = (size_t)n;
                rc = n > 0 ? 0 : -1; /* 保持原语义：空输出视为执行失败 */
            }
        }
    }
    return rc;
}

#ifndef _WIN32
/* ruby_exec_job 的 rb_protect 包装：ENV[]=（rb_funcall）在值编码非法时可能抛异常，
 * 脚本里的非本地跳转也只有 protect 能兜住。任何逃逸的 Ruby 异常都不允许把专用
 * MRI 线程的 root tag 打穿（那会让后续请求全挂）。 */
static VALUE ruby_exec_job_protected(VALUE arg)
{
    return (VALUE)ruby_exec_job((struct ruby_job *)arg);
}

/* MRI 专用线程：初始化 VM（只此线程碰 rb_*），然后循环取 job 执行。 */
static void *ruby_thread_main(void *arg)
{
    int lockfd;

    (void)arg;
    /* 跨 .so 选举：libapp_rack 可能已经初始化并独占了这个进程的 MRI VM。 */
    lockfd = ruby_boot_lock_acquire();
    if (getenv(RUBY_BOOT_MARKER) != NULL) {
        fprintf(stderr,
                "scriptffi: ruby 嵌入式 MRI 未启动：本进程已由另一个嵌入式 Ruby 引擎"
                "（通常是 libapp_rack）初始化了 MRI VM（%s=1）。MRI 的 VM/GVL 是进程全局且"
                "线程亲和的，二次 ruby_init 会 SIGSEGV 整个 webserver；本引擎改为显式失败"
                "（502）。默认配置用常驻 sidecar 提供 /ruby/（CRUCIBLE_ENABLE_RUBY_EMBED=0）；"
                "若要嵌入式 ruby，请在同一构建里关闭 rack embed。\n",
                RUBY_BOOT_MARKER);
        pthread_mutex_lock(&g_ruby_q_mtx);
        g_ruby_boot_state = -2;
        pthread_cond_broadcast(&g_ruby_boot_cond);
        pthread_mutex_unlock(&g_ruby_q_mtx);
        ruby_boot_lock_release(lockfd);
        return NULL;
    }
    /* RUBY_INIT_STACK 必须落在本线程的栈帧里：MRI 的保守 GC/栈深检查用它定栈底，
     * 缺了它（从池线程直接 ruby_init）GC 会拿到错误边界 → SIGSEGV。 */
#ifdef RUBY_INIT_STACK
    RUBY_INIT_STACK;
#endif
    ruby_init();
    ruby_init_loadpath();
    /* Ruby 3.4（Prism）：只 ruby_init 的半启动 VM 方法查找不完整（rack 引擎同结论），
     * 走一次 ruby_options 载入 prelude；env 标记避免 .so 重开后再 boot（会 SIGSEGV）。 */
    rb_gv_set("$VERBOSE", Qnil);
    /* 只 boot 到「能 rb_load_protect 跑脚本」为止：
     * did_you_mean / syntax_suggest / error_highlight 这些 prelude 在嵌入场景
     * 实测会让 MRI 在启动阶段自己 rb_bug → SIGSEGV（OpenBSD + Ruby 3.4，core 栈
     * sigsegv → rb_bug_for_fatal_signal → ruby_default_signal）；它们对执行脚本
     * 毫无必要（只是 REPL 的报错美化）。gems 一并关掉：本引擎按契约只跑脚本文件，
     * 需要 gem 的场景应走 rack 引擎。 */
    {
        static char *embedding[] = {"libapp_ruby",
                                    "--disable=gems,did_you_mean,syntax_suggest,error_highlight",
                                    "-e", "0"};
        char *rubyopt = getenv("RUBYOPT");
        char *saved = rubyopt != NULL ? appengine_strdup(rubyopt) : NULL;

        unsetenv("RUBYOPT");
        (void)ruby_options(4, embedding);
        if (saved != NULL) {
            setenv("RUBYOPT", saved, 1);
            free(saved);
        }
    }
    /* .so 常驻（RTLD_NODELETE）后再宣告「本进程的 VM 归我」，后来者据此显式失败。 */
    ruby_pin_libruby();
    setenv(RUBY_BOOT_MARKER, "1", 1);
    ruby_boot_lock_release(lockfd);
    pthread_mutex_lock(&g_ruby_q_mtx);
    g_ruby_boot_state = 1;
    pthread_cond_broadcast(&g_ruby_boot_cond);
    pthread_mutex_unlock(&g_ruby_q_mtx);
    for (;;) {
        struct ruby_job *job;

        pthread_mutex_lock(&g_ruby_q_mtx);
        while (g_ruby_pending == NULL)
            pthread_cond_wait(&g_ruby_q_cond, &g_ruby_q_mtx);
        job = g_ruby_pending;
        g_ruby_pending = NULL;
        pthread_mutex_unlock(&g_ruby_q_mtx);

        {
            int state = 0;
            int rc = (int)rb_protect(ruby_exec_job_protected, (VALUE)job, &state);

            if (state != 0) {
                rb_set_errinfo(Qnil);
                rc = -1;
            }
            job->rc = rc;
        }

        pthread_mutex_lock(&g_ruby_q_mtx);
        g_ruby_job_done = 1;
        pthread_cond_signal(&g_ruby_done_cond);
        pthread_mutex_unlock(&g_ruby_q_mtx);
    }
    return NULL;
}
#endif

static int run_ruby_inprocess(const char *script, const char *method, const char *path,
                              const char *query, const char *content_type, const char *body,
                              size_t body_len, const char *remote, const char *headers,
                              char **out_body, size_t *out_len)
{
    struct ruby_job job;

    memset(&job, 0, sizeof(job));
    job.script = script;
    job.method = method;
    job.path = path;
    job.query = query;
    job.content_type = content_type;
    job.body = body;
    job.body_len = body_len;
    job.remote = remote;
    job.headers = headers;
    job.rc = -1;

#ifndef _WIN32
    RUBY_LOCK();
    if (g_ruby_thread_state == 0) {
        pthread_t th;
        pthread_attr_t attr;

        pthread_attr_init(&attr);
        /* MRI 的 GC 扫栈：给足 8MB（OpenBSD 默认 512KB 会偏紧）。 */
        pthread_attr_setstacksize(&attr, 8UL * 1024 * 1024);
        if (pthread_create(&th, &attr, ruby_thread_main, NULL) == 0) {
            (void)pthread_detach(th);
            /* 等 boot 结果：失败（VM 已被别家 .so 拥有 / ruby_init 失败）时不要把
             * job 挂进去——否则没有消费者，请求线程会永久等 g_ruby_job_done。 */
            pthread_mutex_lock(&g_ruby_q_mtx);
            while (g_ruby_boot_state == 0)
                pthread_cond_wait(&g_ruby_boot_cond, &g_ruby_q_mtx);
            g_ruby_thread_state = (g_ruby_boot_state == 1) ? 1 : -1;
            pthread_mutex_unlock(&g_ruby_q_mtx);
        } else {
            g_ruby_thread_state = -1;
        }
        pthread_attr_destroy(&attr);
    }
    if (g_ruby_thread_state != 1) {
        RUBY_UNLOCK();
        fprintf(stderr, "scriptffi: ruby 嵌入式引擎不可用（专用 MRI 线程创建或 VM boot 失败）；"
                        "见上一条日志。\n");
        return -1;
    }
    pthread_mutex_lock(&g_ruby_q_mtx);
    g_ruby_job_done = 0;
    g_ruby_pending = &job;
    pthread_cond_signal(&g_ruby_q_cond);
    while (!g_ruby_job_done)
        pthread_cond_wait(&g_ruby_done_cond, &g_ruby_q_mtx);
    pthread_mutex_unlock(&g_ruby_q_mtx);
    RUBY_UNLOCK();
#else
    {
        static int ruby_started;

        RUBY_LOCK();
        if (!ruby_started) {
            ruby_init();
            ruby_init_loadpath();
            ruby_started = 1;
        }
        job.rc = ruby_exec_job(&job);
        RUBY_UNLOCK();
    }
#endif
    if (job.rc == 0) {
        *out_body = job.out_body;
        *out_len = job.out_len;
    }
    return job.rc;
}
#endif /* CRUCIBLE_HAVE_RUBY */

/* ---------- in-process Perl ---------- */
#if defined(CRUCIBLE_HAVE_PERL)
#include <EXTERN.h>
#include <perl.h>

static PerlInterpreter *my_perl;

#ifndef _WIN32
/* 单解释器被 4..8 个池线程并发调用（perl_parse/perl_run/eval_pv）无任何同步（F1）。 */
static pthread_mutex_t g_perl_mtx = PTHREAD_MUTEX_INITIALIZER;
#define PERL_LOCK()   pthread_mutex_lock(&g_perl_mtx)
#define PERL_UNLOCK() pthread_mutex_unlock(&g_perl_mtx)
#else
#define PERL_LOCK()   ((void)0)
#define PERL_UNLOCK() ((void)0)
#endif

/* ENV 是解释器级全局：清掉上一请求残留的 HTTP_*（先收集再删除，避免边遍历边删）。 */
static void perl_env_clear_http(HV *envhv)
{
    struct {
        char *k;
        I32 len;
    } keys[256];
    size_t n = 0, i;
    HE *he;

    if (envhv == NULL)
        return;
    hv_iterinit(envhv);
    while (n < sizeof(keys) / sizeof(keys[0]) && (he = hv_iternext(envhv)) != NULL) {
        I32 klen = 0;
        char *k = hv_iterkey(he, &klen);

        if (k != NULL && klen > 5 && memcmp(k, "HTTP_", 5) == 0) {
            keys[n].k = (char *)malloc((size_t)klen + 1);
            if (keys[n].k == NULL)
                continue;
            memcpy(keys[n].k, k, (size_t)klen);
            keys[n].k[klen] = '\0';
            keys[n].len = klen;
            n++;
        }
    }
    for (i = 0; i < n; i++) {
        (void)hv_delete(envhv, keys[i].k, keys[i].len, G_DISCARD);
        free(keys[i].k);
    }
}

struct perl_env_hdr_ctx {
    HV *env;
};

static int perl_env_put_http_cb(void *ctx, const char *name, size_t name_len,
                                const char *value, size_t value_len)
{
    struct perl_env_hdr_ctx *c = (struct perl_env_hdr_ctx *)ctx;
    char key[262];
    size_t klen;

    if (c == NULL || c->env == NULL)
        return 1;
    klen = appengine_cgi_http_key(key, sizeof(key), name, name_len);
    if (klen == 0)
        return 0;
    (void)hv_store(c->env, key, (I32)klen, newSVpvn(value, value_len), 0);
    return 0;
}

static int run_perl_inprocess(const char *script, const char *method, const char *path,
                              const char *query, const char *content_type, const char *body,
                              size_t body_len, const char *remote, const char *headers,
                              char **out_body, size_t *out_len)
{
    char *embedding[] = {"", (char *)script};
    int argc = 2;
    char **argv = embedding;
    char **env = NULL;
    char lenbuf[32];
    SV *out_sv;
    STRLEN n;
    char *s;
    int rc = -1;

    PERL_LOCK();
    if (!my_perl) {
        PERL_SYS_INIT3(&argc, &argv, &env);
        my_perl = perl_alloc();
        perl_construct(my_perl);
    }
    /* Debian/Ubuntu 的 perl 是 **ithreads** 构建：解释器指针/PL_* 是**每线程**的
     * TLS（`PL_curinterp`）。app_ffi 的通用池有 4..8 个线程，第一次请求在哪个
     * 线程建解释器、后续请求很可能落到别的线程 —— 只加互斥锁**不够**：没有
     * PERL_SET_CONTEXT 的线程 `PL_curinterp == NULL`，下一次 PL_* 访问就在
     * libperl 里 SIGSEGV（真机 2026-10-23：h1 第一次 200，随后 h2c 请求
     * `segfault at 0x40 in libperl.so.5.40`，整个 webserver 被打死）。
     * 每次进入锁后都显式 set：线程无关、幂等（非 ithreads 构建上是 no-op）。 */
    PERL_SET_CONTEXT(my_perl);
    {
        char *args[] = {"", (char *)script};
        perl_parse(my_perl, NULL, 2, args, NULL);
    }
    /* ENV（含 CONTENT_LENGTH/CONTENT_TYPE；P2 body 丢失修复）。 */
    {
        HV *envhv = get_hv("ENV", GV_ADD);
        hv_store(envhv, "REQUEST_METHOD", 14,
                 newSVpv(method ? method : "GET", 0), 0);
        hv_store(envhv, "PATH_INFO", 9, newSVpv(path ? path : "/", 0), 0);
        hv_store(envhv, "QUERY_STRING", 12, newSVpv(query ? query : "", 0), 0);
        hv_store(envhv, "REMOTE_ADDR", 11, newSVpv(remote ? remote : "", 0), 0);
        hv_store(envhv, "SCRIPT_FILENAME", 15, newSVpv(script, 0), 0);
        snprintf(lenbuf, sizeof(lenbuf), "%lu", (unsigned long)body_len);
        hv_store(envhv, "CONTENT_LENGTH", 14, newSVpv(lenbuf, 0), 0);
        if (content_type != NULL && content_type[0] != '\0')
            hv_store(envhv, "CONTENT_TYPE", 12, newSVpv(content_type, 0), 0);
        /* 请求头 → HTTP_*（CGI 语义）。 */
        perl_env_clear_http(envhv);
        {
            struct perl_env_hdr_ctx hctx;

            hctx.env = envhv;
            (void)appengine_headers_foreach(headers, perl_env_put_http_cb, &hctx);
        }
    }
    /* 请求体 → $Crucible::body（newSVpvn 显式长度，NUL 不截断）；脚本里
     * local *STDIN 绑定到该标量，`<>`/STDIN 读到完整 body。 */
    {
        SV *bsv = newSVpvn(body != NULL ? body : "", body_len);
        SV *gv = get_sv("Crucible::body", GV_ADD);
        sv_setsv(gv, bsv);
        SvREFCNT_dec(bsv);
    }
    perl_run(my_perl);
    /* Best-effort: scripts that print go to real stdout; capture via tie is heavy.
     * Read script and eval into scalar when file is small CGI-style. */
    out_sv = eval_pv("do { local $/; open my $fh, '<', $ENV{SCRIPT_FILENAME} or die $!; "
                     "my $c = <$fh>; close $fh; "
                     "my $buf = ''; open my $o, '>', \\$buf; "
                     "my $old = select $o; "
                     "{ local *STDIN; open STDIN, '<', \\$Crucible::body or die $!; "
                     "  eval $c; } "
                     "select $old; $buf }",
                     0);
    if (!out_sv || !SvOK(out_sv)) {
        PERL_UNLOCK();
        return -1;
    }
    s = SvPV(out_sv, n);
    if (!s || n == 0) {
        PERL_UNLOCK();
        return -1;
    }
    if ((unsigned long)n > CRUCIBLE_SCRIPT_OUT_CAP) {
        fprintf(stderr, "scriptffi: perl 脚本输出超过 %u 字节上限\n",
                CRUCIBLE_SCRIPT_OUT_CAP);
        PERL_UNLOCK();
        return -1;
    }
    {
        char *b = (char *)malloc(n + 1);
        if (b != NULL) {
            memcpy(b, s, n);
            b[n] = '\0';
            *out_body = b;
            *out_len = n;
            rc = 0;
        }
    }
    PERL_UNLOCK();
    return rc;
}
#endif /* CRUCIBLE_HAVE_PERL */

/*
 * 执行分派。返回 0 = 成功；-1 = 嵌入不可用 / 语言未知（调用方写错误文本，
 * 不再有 popen 回退，也不再返回假 hello）；-2 = 脚本自身抛异常（仅 python 目前会返回）。
 */
static int run_lang(const char *lang, const char *script, const char *method, const char *path,
                    const char *query, const char *content_type, const char *body,
                    size_t body_len, const char *remote, const char *headers,
                    const char *extra, char **out_body, size_t *out_len,
                    const char **mode_out)
{
    if (strcmp(lang, "python") == 0) {
#if defined(CRUCIBLE_HAVE_PYTHON)
        *mode_out = "inprocess-python";
        return run_python_inprocess(script, method, path, query, content_type, body, body_len,
                                    remote, headers, extra, out_body, out_len);
#else
        *mode_out = "embed-missing";
        fprintf(stderr,
                "scriptffi: python embed not built; rebuild with -DCRUCIBLE_HAVE_PYTHON "
                "(popen fallback removed)\n");
        return -1;
#endif
    }
    if (strcmp(lang, "ruby") == 0) {
#if defined(CRUCIBLE_HAVE_RUBY)
        *mode_out = "inprocess-ruby";
        return run_ruby_inprocess(script, method, path, query, content_type, body, body_len,
                                  remote, headers, out_body, out_len);
#else
        *mode_out = "embed-missing";
        fprintf(stderr,
                "scriptffi: ruby embed not built. 默认关闭：OpenBSD + Ruby 3.4 下嵌入式 MRI "
                "在 boot 阶段就会 rb_bug → SIGSEGV（整个进程，已复现多次 core）。"
                "需要时用 CRUCIBLE_ENABLE_RUBY_EMBED=1 重新执行 scripts/build_script_ffi.sh；"
                "稳定的替代路径是常驻 Ruby sidecar（www-apps/ruby/deps/bin/index）。\n");
        return -1;
#endif
    }
    if (strcmp(lang, "perl") == 0) {
#if defined(CRUCIBLE_HAVE_PERL)
        *mode_out = "inprocess-perl";
        return run_perl_inprocess(script, method, path, query, content_type, body, body_len,
                                  remote, headers, out_body, out_len);
#else
        *mode_out = "embed-missing";
        fprintf(stderr,
                "scriptffi: perl embed not built; rebuild with -DCRUCIBLE_HAVE_PERL "
                "(popen fallback removed)\n");
        return -1;
#endif
    }
    *mode_out = "unsupported";
    fprintf(stderr, "scriptffi: unsupported language `%s`\n", lang != NULL ? lang : "(null)");
    return -1;
}

int appengine_init(const char *engine, const char *lib_hint)
{
    (void)engine;
    /* 记下本 .so 的路径：Python 初始化要据此定位同目录的共享协调库
     * libscriptffi.so（跨 .so 进程级初始化锁，见 crucible_pyinit.h）。 */
    crucible_pyinit_set_hint(lib_hint);
    g_ready = 1;
    return 0;
}

int appengine_execute(
    const char *script,
    const char *docroot,
    const char *method,
    const char *path,
    const char *query,
    const char *content_type,
    const char *body,
    size_t body_len,
    const char *remote,
    const char *server_name,
    int server_port,
    const char *extra,
    const char *headers,
    AppEngineResult *out)
{
    const char *lang;
    char *result = NULL;
    size_t result_len = 0;
    char resolved[1024];
    char hdr[320];
    const char *mode = "none";

    /* content_type/body/body_len 已转发给 run_lang（此前被 (void) 丢弃 ⇒
     * python/ruby/perl 三个嵌入引擎都看不到 POST body 与 Content-Type）。
     * headers 同样透传 → run_*_inprocess 落地 HTTP_*（CGI 语义）。
     * extra 里的 .env 也透传：python 的 os.environ 是 import 期缓存，看不到 Rust
     * 侧 setenv，必须按请求落进 TLS 覆盖表（见 py_extra_env_cb）。 */
    (void)server_name;
    (void)server_port;

    if (!g_ready || !out)
        return -1;

    lang = lang_name(script);

    if (resolve_script(script, docroot, lang, resolved, sizeof(resolved)) != 0) {
        /* 旧实现这里返回 appengine_fill_hello——坏引擎看起来像服务了页面。 */
        return script_fail(out,
                           "%s: 未找到脚本（script=%s docroot=%s；按语言回落到 index.%s）",
                           lang, script != NULL ? script : "(null)",
                           docroot != NULL ? docroot : "(null)",
                           strcmp(lang, "ruby") == 0 ? "rb"
                                                     : (strcmp(lang, "perl") == 0 ? "pl"
                                                                                 : "py"));
    }

    {
        int rc = run_lang(lang, resolved, method, path, query, content_type, body, body_len,
                          remote, headers, extra, &result, &result_len, &mode);
        if (rc != 0) {
            free(result);
            /* -2 = 脚本**跑起来了但抛了异常**（python 侧约定，见 run_python_inprocess）。
             * 与 -1「嵌入解释器不可用」区分开：否则日志会把「应用代码有 bug」误报成
             * 「引擎没编好」，排障方向直接跑偏。traceback 已由解释器写进服务端日志。 */
            if (rc == -2)
                return script_fail(out,
                                   "%s: 脚本执行失败（script=%s）；详细 traceback 见服务端日志",
                                   lang, resolved);
            return script_fail(out,
                               "%s: 进程内解释器不可用（mode=%s，script=%s）。"
                               "本引擎不做 popen 回退，也不返回假响应；"
                               "请用 CRUCIBLE_HAVE_%s 重建 libapp_%s.so",
                               lang, mode, resolved,
                               strcmp(lang, "ruby") == 0 ? "RUBY"
                                                         : (strcmp(lang, "perl") == 0
                                                                ? "PERL"
                                                                : "PYTHON"),
                               lang);
        }
    }

    appengine_result_alloc(out);
    out->status = 200;
    snprintf(hdr, sizeof(hdr),
             "Content-Type: text/plain; charset=utf-8\r\n"
             "X-Crucible-Engine: %s\r\n"
             "X-Crucible-Script-Mode: %s\r\n",
             lang, mode);
    appengine_result_set_headers(out, hdr);
    appengine_result_set_body(out, result, result_len);
    free(result);
    return 0;
}

/*
 * `.env` 隔离自报（可选符号，见 appengine.h）。
 *
 * 只有 **python** 构建可以回答 1：它把每请求 `.env` 从 `extra` JSON 直接落进
 * 线程本地覆盖表（`_CrucibleEnv`），并把解释器全局 `os.environ` 视图对齐到
 * 启动期基底（`py_env_reconcile_to_base`）—— 请求数据从不经进程 env，故无需
 * 宿主的全局 env 锁，慢的「无 .env」请求也不会再挡住随后带 `.env` 的 python 请求。
 *
 * ruby/perl 构建仍以进程 ENV 为唯一 `.env` 通道（`run_*_inprocess` 不解析 extra），
 * 必须留在 env 锁内。没有编译期语言（按扩展名推断的通用 .so）同样保守地回答 0。
 *
 * 诚实边界：它声明的是**引擎自身**不读写 environ 承载请求数据；应用代码自己调
 * `os.putenv`/`ctypes` 直接改 C environ 属应用自伤（与 cgi 的 env_isolation 同类）。
 */
int appengine_env_isolation(void)
{
#if defined(CRUCIBLE_HAVE_PYTHON) && defined(CRUCIBLE_SCRIPT_LANG)
    return strcmp(CRUCIBLE_SCRIPT_LANG, "python") == 0 ? 1 : 0;
#else
    return 0;
#endif
}

void appengine_shutdown(void) { g_ready = 0; }
