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
    "    def __init__(self, real):\n"
    "        self._real = real\n"
    "    def _ov(self):\n"
    "        return getattr(_c_tls, 'env', None)\n"
    "    def __getitem__(self, k):\n"
    "        ov = self._ov()\n"
    "        if ov is not None and k in ov:\n"
    "            return ov[k]\n"
    "        return self._real[k]\n"
    "    def __setitem__(self, k, v):\n"
    "        ov = self._ov()\n"
    "        if ov is not None:\n"
    "            ov[k] = v\n"
    "        else:\n"
    "            self._real[k] = v\n"
    "    def __delitem__(self, k):\n"
    "        ov = self._ov()\n"
    "        if ov is not None and k in ov:\n"
    "            del ov[k]\n"
    "            return\n"
    "        del self._real[k]\n"
    "    def __iter__(self):\n"
    "        ov = self._ov()\n"
    "        seen = set()\n"
    "        if ov is not None:\n"
    "            for k in ov:\n"
    "                seen.add(k)\n"
    "                yield k\n"
    "        for k in self._real:\n"
    "            if k not in seen:\n"
    "                yield k\n"
    "    def __len__(self):\n"
    "        ov = self._ov()\n"
    "        if ov is None:\n"
    "            return len(self._real)\n"
    "        return len(set(ov) | set(self._real))\n"
    "    def copy(self):\n"
    "        d = dict(self._real)\n"
    "        ov = self._ov()\n"
    "        if ov is not None:\n"
    "            d.update(ov)\n"
    "        return d\n"
    "_cos.environ = _CrucibleEnv(_cos.environ)\n"
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

/* 安装 shim；失败返回 -1（已经带着异常，调用方清掉并显式报错）。 */
static int python_shim_install(void)
{
    PyObject *ns, *r;

    if (g_shim_set != NULL)
        return 0;
    ns = PyDict_New();
    if (ns == NULL)
        return -1;
    r = PyRun_StringFlags(g_shim_src, Py_file_input, ns, ns, NULL);
    if (r == NULL) {
        PyErr_Print();
        Py_DECREF(ns);
        return -1;
    }
    Py_DECREF(r);
    g_shim_set = PyDict_GetItemString(ns, "_cr_set");     /* 借用 */
    g_shim_clear = PyDict_GetItemString(ns, "_cr_clear"); /* 借用 */
    if (g_shim_set == NULL || g_shim_clear == NULL) {
        Py_DECREF(ns);
        fprintf(stderr, "scriptffi: python 隔离 shim 缺少入口函数\n");
        return -1;
    }
    Py_INCREF(g_shim_set);
    Py_INCREF(g_shim_clear);
    Py_DECREF(ns); /* 函数对象经 __globals__ 自持 shim 命名空间 */
    return 0;
}

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

static int run_python_inprocess(const char *script, const char *method, const char *path,
                                const char *query, const char *content_type,
                                const char *body, size_t body_len, const char *remote,
                                const char *headers, char **out_body, size_t *out_len)
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

    /* 跨 .so 共享初始化锁：并发冷启动只有一个线程真正 Py_Initialize。 */
    if (crucible_pyinit_ensure(Py_IsInitialized, Py_Initialize, PyEval_SaveThread, errbuf,
                               sizeof(errbuf)) != 0) {
        fprintf(stderr, "scriptffi: CPython 初始化失败: %s\n", errbuf);
        return -1;
    }
    gil = PyGILState_Ensure(); /* 每请求拿 GIL；与 wsgi/asgi/uwsgi 共用同一解释器 */

    if (python_shim_install() != 0)
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

static pthread_mutex_t g_ruby_call_mtx = PTHREAD_MUTEX_INITIALIZER; /* 串行化调用者 */
static pthread_mutex_t g_ruby_q_mtx = PTHREAD_MUTEX_INITIALIZER;    /* job 交接 */
static pthread_cond_t g_ruby_q_cond = PTHREAD_COND_INITIALIZER;     /* 工作线程等 job */
static pthread_cond_t g_ruby_done_cond = PTHREAD_COND_INITIALIZER;  /* 调用者等完成 */
static struct ruby_job *g_ruby_pending;
static int g_ruby_job_done;
static int g_ruby_thread_state; /* 0=未建 1=已建 -1=建线程失败 */
#define RUBY_LOCK()   pthread_mutex_lock(&g_ruby_call_mtx)
#define RUBY_UNLOCK() pthread_mutex_unlock(&g_ruby_call_mtx)
#else
#define RUBY_LOCK()   ((void)0)
#define RUBY_UNLOCK() ((void)0)
#endif

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
    rb_hash_aset(c->env, rb_str_new_cstr(key), rb_str_new(value, (long)value_len));
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
        rb_hash_aset(env, rb_str_new_cstr("REQUEST_METHOD"),
                     rb_str_new_cstr(method ? method : "GET"));
        rb_hash_aset(env, rb_str_new_cstr("PATH_INFO"),
                     rb_str_new_cstr(path ? path : "/"));
        rb_hash_aset(env, rb_str_new_cstr("QUERY_STRING"),
                     rb_str_new_cstr(query ? query : ""));
        rb_hash_aset(env, rb_str_new_cstr("REMOTE_ADDR"),
                     rb_str_new_cstr(remote ? remote : ""));
        rb_hash_aset(env, rb_str_new_cstr("SCRIPT_FILENAME"), rb_str_new_cstr(script));
        snprintf(lenbuf, sizeof(lenbuf), "%lu", (unsigned long)body_len);
        rb_hash_aset(env, rb_str_new_cstr("CONTENT_LENGTH"), rb_str_new_cstr(lenbuf));
        if (content_type != NULL && content_type[0] != '\0')
            rb_hash_aset(env, rb_str_new_cstr("CONTENT_TYPE"),
                         rb_str_new_cstr(content_type));
        /* 请求头 → HTTP_*（CGI 语义）。 */
        ruby_env_clear_http(env);
        {
            struct ruby_env_hdr_ctx hctx;

            hctx.env = env;
            (void)appengine_headers_foreach(headers, ruby_env_put_http_cb, &hctx);
        }
    }
    /* 请求体 → $__crucible_body（rb_str_new 显式长度，NUL 不截断）→ $stdin。 */
    rb_gv_set(rb_intern("$__crucible_body"),
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
/* MRI 专用线程：初始化 VM（只此线程碰 rb_*），然后循环取 job 执行。 */
static void *ruby_thread_main(void *arg)
{
    (void)arg;
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
    if (getenv("CRUCIBLE_EMBED_RUBY_BOOTED") == NULL) {
        /* 只 boot 到「能 rb_load_protect 跑脚本」为止：
         * did_you_mean / syntax_suggest / error_highlight 这些 prelude 在嵌入场景
         * 实测会让 MRI 在启动阶段自己 rb_bug → SIGSEGV（OpenBSD + Ruby 3.4，core 栈
         * sigsegv → rb_bug_for_fatal_signal → ruby_default_signal）；它们对执行脚本
         * 毫无必要（只是 REPL 的报错美化）。gems 一并关掉：本引擎按契约只跑脚本文件，
         * 需要 gem 的场景应走 rack 引擎。 */
        static char *embedding[] = {"libapp_ruby",
                                    "--disable=gems,did_you_mean,syntax_suggest,error_highlight",
                                    "-e", "0"};
        char *rubyopt = getenv("RUBYOPT");
        char *saved = rubyopt != NULL ? appengine_strdup(rubyopt) : NULL;

        unsetenv("RUBYOPT");
        (void)ruby_options(4, embedding);
        setenv("CRUCIBLE_EMBED_RUBY_BOOTED", "1", 1);
        if (saved != NULL) {
            setenv("RUBYOPT", saved, 1);
            free(saved);
        }
    }
    for (;;) {
        struct ruby_job *job;

        pthread_mutex_lock(&g_ruby_q_mtx);
        while (g_ruby_pending == NULL)
            pthread_cond_wait(&g_ruby_q_cond, &g_ruby_q_mtx);
        job = g_ruby_pending;
        g_ruby_pending = NULL;
        pthread_mutex_unlock(&g_ruby_q_mtx);

        job->rc = ruby_exec_job(job);

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
            g_ruby_thread_state = 1;
        } else {
            g_ruby_thread_state = -1;
        }
        pthread_attr_destroy(&attr);
    }
    if (g_ruby_thread_state != 1) {
        RUBY_UNLOCK();
        fprintf(stderr, "scriptffi: ruby 专用线程创建失败\n");
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
                    char **out_body, size_t *out_len, const char **mode_out)
{
    if (strcmp(lang, "python") == 0) {
#if defined(CRUCIBLE_HAVE_PYTHON)
        *mode_out = "inprocess-python";
        return run_python_inprocess(script, method, path, query, content_type, body, body_len,
                                    remote, headers, out_body, out_len);
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
     * headers 同样透传 → run_*_inprocess 落地 HTTP_*（CGI 语义）。 */
    (void)server_name;
    (void)server_port;
    (void)extra; /* .env 变量：Rust 侧已注入进程环境；嵌入解释器共用进程环境 */

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
                          remote, headers, &result, &result_len, &mode);
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

void appengine_shutdown(void) { g_ready = 0; }
