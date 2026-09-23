/*
 * 进程内 CPython 嵌入运行时（WSGI / ASGI / uWSGI 三个引擎共用）。
 *
 * spec：解释器必须静态嵌入引擎进程内，禁止每请求 spawn（"能 FFI 就不 spawn"）。
 * 本文件实现的正是"每请求 spawn python3"的替代路径：一次 Py_Initialize，之后每请求
 * 只在同进程内构造 environ、调用应用可调用对象、迭代响应。
 *
 * 为什么用 dlopen+dlsym 而不是 #include <Python.h>：
 *   1) build_app_engines.sh（不在本目录的改动范围内）不探测 python 头文件/库，
 *      没有 -I/usr/local/include/python3.13，也没有 -lpython3.13；
 *   2) app_ffi 用 dlopen(RTLD_NOW|RTLD_GLOBAL) 加载引擎 .so——只要引擎里存在
 *      未定义的 Py_* 符号，加载期就直接失败（该引擎整体 502，比"不工作"更糟）。
 *   所以：本文件不引用任何链接期符号，全部符号在首次使用时从
 *   libpython3.13.so.0[.0] 等 soname 上 dlsym 解析；宿主没有 libpython 时，
 *   引擎返回显式错误（rc != 0 + error 文本），绝不返回假的 hello 页面。
 *   解析所用的名字全部是 CPython 公开 C API（见 CRUCIBLE_PY_LOAD 列表）。
 *
 * 线程/GIL（跨 .so 契约，见 crucible_embed.h 文件头）：
 *   - 初始化一次（Py_IsInitialized 守卫 + pthread 互斥），初始化线程立刻
 *     PyEval_SaveThread 释放 GIL；请求线程各自 PyGILState_Ensure/Release。
 *   - 谁都不调用 Py_FinalizeEx：解释器随进程常驻，否则另一个 .so 的线程会在
 *     等 GIL 上永久阻塞。
 *   - 进程级互斥 g_py_lock 只串行化"初始化 / 应用缓存读写 / shutdown"，不覆盖应用
 *     执行（应用在锁外跑，避免应用回调本服务器时自锁）；锁序固定为 GIL → 锁，
 *     初始化路径只持锁不碰 GIL，故无 ABBA 死锁。
 *   - 所有 Py* 调用（含 Py_DecRef）必须在持 GIL 期间完成，本文件按该顺序收尾。
 *
 * Py_ssize_t 假定为 long：目标平台是 LP64（openbsd/amd64、linux/amd64）。
 */
#ifndef CRUCIBLE_PYEMBED_H
#define CRUCIBLE_PYEMBED_H

#include "appengine.h"
#include "appengine_common.h"
#include "crucible_embed.h"

#include <pthread.h>
#include <stdarg.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifdef CRUCIBLE_HAVE_PYTHON

/* ------------------------------------------------- CPython C API 符号表 ---
 * 每个成员就是 CPython 导出的 C API 函数（名字见 CRUCIBLE_PY_LOAD 列表）。
 * 全部用 void* 承接 PyObject*，避免在无 Python.h 时声明 PyObject。 */
typedef struct {
    /* 解释器生命周期 */
    void (*init)(void);                                     /* Py_Initialize */
    int (*is_initialized)(void);                             /* Py_IsInitialized */
    int (*finalize_ex)(void);                                /* Py_FinalizeEx */
    const char *(*get_version)(void);                         /* Py_GetVersion */
    void *(*save_thread)(void);                               /* PyEval_SaveThread */
    void (*restore_thread)(void *);                           /* PyEval_RestoreThread */
    int (*gil_ensure)(void);                                  /* PyGILState_Ensure */
    void (*gil_release)(int);                                 /* PyGILState_Release */
    /* 模块 / 对象 */
    void *(*import_module)(const char *);                     /* PyImport_ImportModule */
    void *(*object_get_attr_string)(void *, const char *);     /* PyObject_GetAttrString */
    void *(*dict_new)(void);                                  /* PyDict_New */
    int (*dict_set_item_string)(void *, const char *, void *); /* PyDict_SetItemString */
    void *(*dict_get_item_string)(void *, const char *);       /* PyDict_GetItemString */
    void *(*bytes_from_string_and_size)(const char *, long);   /* PyBytes_FromStringAndSize */
    int (*bytes_as_string_and_size)(void *, char **, long *);  /* PyBytes_AsStringAndSize */
    void *(*unicode_from_string_and_size)(const char *, long); /* PyUnicode_FromStringAndSize */
    const char *(*unicode_as_utf8_and_size)(void *, long *);   /* PyUnicode_AsUTF8AndSize */
    void *(*object_call)(void *, void *, void *);              /* PyObject_Call */
    void *(*object_call_object)(void *, void *);               /* PyObject_CallObject */
    void *(*object_call_method)(void *, const char *, const char *, ...); /* PyObject_CallMethod */
    void *(*object_get_iter)(void *);                          /* PyObject_GetIter */
    void *(*iter_next)(void *);                                /* PyIter_Next */
    void *(*object_str)(void *);                               /* PyObject_Str */
    long (*sequence_size)(void *);                             /* PySequence_Size */
    void *(*sequence_get_item)(void *, long);                  /* PySequence_GetItem */
    void *(*tuple_new)(long);                                  /* PyTuple_New */
    int (*tuple_set_item)(void *, long, void *);               /* PyTuple_SetItem（成功偷引用） */
    void *(*list_new)(long);                                   /* PyList_New */
    int (*list_append)(void *, void *);                        /* PyList_Append */
    void *(*long_from_long)(long);                             /* PyLong_FromLong */
    void *(*cfunction_new_ex)(void *, void *, void *);         /* PyCFunction_NewEx */
    void (*inc_ref)(void *);                                   /* Py_IncRef */
    void (*dec_ref)(void *);                                   /* Py_DecRef */
    /* 异常 */
    void *(*err_occurred)(void);                               /* PyErr_Occurred */
    void (*err_clear)(void);                                   /* PyErr_Clear */
    void (*err_fetch)(void **, void **, void **);               /* PyErr_Fetch */
    void (*err_normalize_exception)(void **, void **, void **); /* PyErr_NormalizeException */
} crucible_py_api;

/* PyMethodDef 的内存布局（const char *ml_name; PyCFunction ml_meth;
 * int ml_flags; const char *ml_doc;）。ml_meth 用 void(*)(void) 承接，宽度一致，
 * 避免"函数指针 → 对象指针"的约束违规。 */
typedef struct {
    const char *ml_name;
    void (*ml_meth)(void);
    int ml_flags;
    const char *ml_doc;
} crucible_py_methoddef;

#define CRUCIBLE_PY_METH_VARARGS  0x0001
#define CRUCIBLE_PY_METH_KEYWORDS 0x0002

static crucible_py_api g_py;
static void *g_py_lib;
static int g_py_state;            /* 0=未尝试 1=就绪 -1=失败 */
static char g_py_init_err[256];
static char g_py_version[96];
static void *g_py_tstate;         /* PyEval_SaveThread 保存的初始化线程状态 */
static void *g_py_none;           /* 缓存的 None 对象（故意不释放） */
static pthread_mutex_t g_py_lock = PTHREAD_MUTEX_INITIALIZER;

static const char *const g_py_libnames[] = {
    /* 绝对路径优先（OpenBSD 的 ld.so 默认搜索路径含 /usr/local/lib，但显式更稳）：
     * 本机（OpenBSD）为 /usr/local/lib/libpython3.13.so.0.0。 */
    "/usr/local/lib/libpython3.13.so.0.0",
    "/usr/local/lib/libpython3.13.so",
    "/usr/local/lib/libpython3.12.so.0.0",
    "/usr/local/lib/libpython3.11.so.0.0",
    "/usr/lib/libpython3.13.so.0.0",
    "/usr/lib/libpython3.12.so.0.0",
    "libpython3.13.so.0.0", "libpython3.13.so.0", "libpython3.13.so",
    "libpython3.12.so.0.0", "libpython3.12.so.0", "libpython3.12.so",
    "libpython3.11.so.0.0", "libpython3.11.so.0", "libpython3.11.so",
    "libpython3.10.so.0.0", "libpython3.10.so.0", "libpython3.10.so",
    "libpython3.9.so.0.0", "libpython3.9.so.0", "libpython3.9.so",
    "libpython3.so",
    NULL
};

/* ------------------------------------------------------------------ 工具 --- */

static void crucible_py_xdecref(void *o)
{
    if (o != NULL && g_py_state == 1 && g_py.dec_ref != NULL)
        g_py.dec_ref(o);
}

static int crucible_py_has_error(void)
{
    return g_py_state == 1 && g_py.err_occurred != NULL && g_py.err_occurred() != NULL;
}

static void crucible_py_clear_error(void)
{
    if (crucible_py_has_error())
        g_py.err_clear();
}

/* 对象 → C 文本（str 走 UTF-8；否则按 bytes 处理并拷贝到 *tmp）。
 * 返回 NULL 表示无法取文本。*tmp 非 NULL 时由调用方 free；bytes 分支要求 tmp 非 NULL
 * （否则不返回借用指针，避免泄漏拷贝）。 */
static const char *crucible_py_text(void *o, long *len, char **tmp)
{
    const char *s;
    long n = 0;
    char *bs = NULL;
    long bn = 0;

    if (tmp != NULL)
        *tmp = NULL;
    if (o == NULL || g_py_state != 1)
        return NULL;
    s = g_py.unicode_as_utf8_and_size(o, &n);
    if (s != NULL) {
        if (len != NULL)
            *len = n;
        return s;
    }
    crucible_py_clear_error();
    if (tmp == NULL)
        return NULL;
    if (g_py.bytes_as_string_and_size(o, &bs, &bn) == 0) {
        char *cp = (char *)malloc((size_t)bn + 1);
        if (cp == NULL)
            return NULL;
        memcpy(cp, bs, (size_t)bn);
        cp[bn] = '\0';
        *tmp = cp;
        if (len != NULL)
            *len = bn;
        return cp;
    }
    crucible_py_clear_error();
    return NULL;
}

/* 取当前异常 → malloc 文本（含 traceback 模块格式化结果）。无异常返回 NULL。 */
static char *crucible_py_take_error(void)
{
    void *t = NULL, *v = NULL, *tb = NULL, *obj = NULL;
    crucible_buf b;

    memset(&b, 0, sizeof(b));
    if (!crucible_py_has_error())
        return NULL;
    g_py.err_fetch(&t, &v, &tb);
    if (g_py.err_normalize_exception != NULL)
        g_py.err_normalize_exception(&t, &v, &tb);
    obj = v != NULL ? v : t;
    if (v != NULL) {
        void *tbm = g_py.import_module("traceback");
        if (tbm != NULL) {
            /* Python 3.10+：traceback.format_exception(exc) 直接接受异常实例 */
            void *lines = g_py.object_call_method(tbm, "format_exception", "O", v);
            if (lines != NULL) {
                long n = g_py.sequence_size(lines), i;
                if (n > 0) {
                    for (i = 0; i < n; i++) {
                        void *ln = g_py.sequence_get_item(lines, i);
                        if (ln != NULL) {
                            const char *s = g_py.unicode_as_utf8_and_size(ln, NULL);
                            if (s != NULL)
                                (void)crucible_buf_puts(&b, s);
                            g_py.dec_ref(ln);
                        }
                    }
                }
                g_py.dec_ref(lines);
            }
            crucible_py_clear_error();
            g_py.dec_ref(tbm);
        } else {
            crucible_py_clear_error();
        }
    }
    if (b.len == 0 && obj != NULL) { /* 兜底：str(value) / str(type) */
        void *s = g_py.object_str(obj);
        if (s != NULL) {
            const char *cs = g_py.unicode_as_utf8_and_size(s, NULL);
            if (cs != NULL)
                (void)crucible_buf_puts(&b, cs);
            g_py.dec_ref(s);
        }
        crucible_py_clear_error();
    }
    crucible_py_xdecref(t);
    crucible_py_xdecref(v);
    crucible_py_xdecref(tb);
    if (b.len == 0) {
        crucible_buf_free(&b);
        return NULL;
    }
    return b.p;
}

/* 异常 → err 缓冲（带前缀）。 */
static void crucible_py_err_text(char *err, size_t errsz, const char *prefix)
{
    char *t = crucible_py_take_error();

    if (t != NULL) {
        snprintf(err, errsz, "%s: %s", prefix, t);
        free(t);
    } else {
        snprintf(err, errsz, "%s", prefix);
    }
}

/* Py_None。刻意不引用 Py_None/_Py_NoneStruct 数据符号：dict.clear() 必然返回 None。 */
static void *crucible_py_none_obj(void)
{
    void *d;

    if (g_py_none != NULL)
        return g_py_none;
    if (g_py_state != 1 || g_py.dict_new == NULL || g_py.object_call_method == NULL)
        return NULL;
    d = g_py.dict_new();
    if (d == NULL) {
        crucible_py_clear_error();
        return NULL;
    }
    g_py_none = g_py.object_call_method(d, "clear", NULL);
    g_py.dec_ref(d);
    if (g_py_none == NULL)
        crucible_py_clear_error();
    return g_py_none;
}

static int crucible_py_dict_set_str(void *d, const char *k, const char *v)
{
    void *o;
    int rc;

    if (d == NULL || k == NULL || g_py_state != 1)
        return -1;
    o = g_py.unicode_from_string_and_size(v != NULL ? v : "",
                                          v != NULL ? (long)strlen(v) : 0);
    if (o == NULL)
        return -1;
    rc = g_py.dict_set_item_string(d, k, o);
    g_py.dec_ref(o);
    return rc;
}

/* 建一个 (a, b) 整数元组，如 wsgi.version = (1, 0)。 */
static void *crucible_py_int_tuple(long a, long b)
{
    void *t, *x, *y;

    if (g_py_state != 1)
        return NULL;
    t = g_py.tuple_new(2);
    if (t == NULL)
        return NULL;
    x = g_py.long_from_long(a);
    if (x == NULL) {
        g_py.dec_ref(t);
        return NULL;
    }
    if (g_py.tuple_set_item(t, 0, x) != 0) { /* 失败时 SetItem 已 DECREF x */
        g_py.dec_ref(t);
        return NULL;
    }
    y = g_py.long_from_long(b);
    if (y == NULL) {
        g_py.dec_ref(t);
        return NULL;
    }
    if (g_py.tuple_set_item(t, 1, y) != 0) {
        g_py.dec_ref(t);
        return NULL;
    }
    return t;
}

/* 调用 bool(v)（用真 bool，不引用 Py_True/Py_False 数据符号）。 */
static void *crucible_py_bool_obj(void *bool_type, long v)
{
    void *args, *x, *r;

    if (bool_type == NULL || g_py_state != 1)
        return NULL;
    args = g_py.tuple_new(1);
    if (args == NULL)
        return NULL;
    x = g_py.long_from_long(v);
    if (x == NULL) {
        g_py.dec_ref(args);
        return NULL;
    }
    if (g_py.tuple_set_item(args, 0, x) != 0) { /* 失败时已 DECREF x */
        g_py.dec_ref(args);
        return NULL;
    }
    r = g_py.object_call_object(bool_type, args);
    g_py.dec_ref(args);
    return r;
}

/* "200 OK" → 200；无法解析返回 -1。 */
static int crucible_py_status_code(const char *s)
{
    int code = 0;

    if (s == NULL)
        return -1;
    while (*s == ' ')
        s++;
    if (*s < '0' || *s > '9')
        return -1;
    while (*s >= '0' && *s <= '9') {
        code = code * 10 + (*s - '0');
        if (code > 999)
            return -1;
        s++;
    }
    return code;
}

/* 响应头列表 [(name, value), ...] → "Name: value\r\n" 块（跳过伪头 Status）。 */
static void crucible_py_emit_headers(crucible_buf *hb, void *headers)
{
    long n, i;

    if (hb == NULL || headers == NULL || g_py_state != 1)
        return;
    n = g_py.sequence_size(headers);
    if (n <= 0) {
        crucible_py_clear_error();
        return;
    }
    for (i = 0; i < n; i++) {
        void *pair = g_py.sequence_get_item(headers, i);
        void *k = NULL, *v = NULL;
        char *ktmp = NULL, *vtmp = NULL;
        const char *ks, *vs;
        long kl = 0, vl = 0;

        if (pair == NULL)
            break;
        k = g_py.sequence_get_item(pair, 0);
        v = g_py.sequence_get_item(pair, 1);
        ks = crucible_py_text(k, &kl, &ktmp);
        vs = crucible_py_text(v, &vl, &vtmp);
        if (ks != NULL && vs != NULL && kl > 0) {
            if (!(kl == 6 && strncasecmp(ks, "Status", 6) == 0)) {
                (void)crucible_buf_append(hb, ks, (size_t)kl);
                (void)crucible_buf_puts(hb, ": ");
                (void)crucible_buf_append(hb, vs, (size_t)vl);
                (void)crucible_buf_puts(hb, "\r\n");
            }
        }
        free(ktmp);
        free(vtmp);
        crucible_py_xdecref(k);
        crucible_py_xdecref(v);
        crucible_py_xdecref(pair);
    }
}

/* 一个响应块（bytes 原样；其他类型 str() 后按 UTF-8）追加到缓冲。 */
static int crucible_py_append_obj(crucible_buf *bb, void *o)
{
    char *bs = NULL;
    long bn = 0;
    void *s;
    const char *cs;
    long n = 0;
    int rc;

    if (bb == NULL || o == NULL || g_py_state != 1)
        return -1;
    if (g_py.bytes_as_string_and_size(o, &bs, &bn) == 0)
        return crucible_buf_append(bb, bs, (size_t)bn);
    crucible_py_clear_error();
    s = g_py.object_str(o);
    if (s == NULL) {
        crucible_py_clear_error();
        return -1;
    }
    cs = g_py.unicode_as_utf8_and_size(s, &n);
    rc = cs != NULL ? crucible_buf_append(bb, cs, (size_t)n) : -1;
    g_py.dec_ref(s);
    if (rc != 0)
        crucible_py_clear_error();
    return rc;
}

/* 序列（WSGI 的 write() 缓冲 / 已拼接好的文本行列表）逐项追加。 */
static void crucible_py_append_seq(crucible_buf *bb, void *seq)
{
    long n, i;

    if (bb == NULL || seq == NULL || g_py_state != 1)
        return;
    n = g_py.sequence_size(seq);
    if (n <= 0) {
        crucible_py_clear_error();
        return;
    }
    for (i = 0; i < n; i++) {
        void *it = g_py.sequence_get_item(seq, i);
        if (it == NULL)
            break;
        (void)crucible_py_append_obj(bb, it);
        g_py.dec_ref(it);
    }
}

/* 把 C 层 environ 同步进 Python 的 os.environ。
 *
 * 场景：Rust 侧把 .env / deps 变量经 env_lock::with_temp_env_named（setenv）注入
 * C environ，但 Python 的 os.environ 是 posix 模块 import 时构建的缓存映射，
 * 看不到之后的 setenv（旧实现每请求 spawn python3，子进程天然继承 env；嵌入后
 * 必须显式同步，否则 .env 变量对 WSGI 应用不可见）。
 *
 * 只做 update 不做 clear：clear+update 之间会有"进程级 env 为空"的窗口，同进程
 * 其他引擎线程可能读到空环境。代价是 C 环境里已删除的键会在 os.environ 残留，
 * 记为已知限制（下一请求的 update 会覆盖仍在的键）。 */
extern char **environ;

static void crucible_py_sync_environ_locked(void)
{
    void *d, *os_mod, *envmap;
    char **e;

    if (g_py_state != 1)
        return;
    d = g_py.dict_new();
    if (d == NULL) {
        crucible_py_clear_error();
        return;
    }
    for (e = environ; e != NULL && *e != NULL; e++) {
        const char *eq = strchr(*e, '=');
        char kbuf[128];
        size_t klen;
        void *v;

        if (eq == NULL || eq == *e)
            continue;
        klen = (size_t)(eq - *e);
        if (klen >= sizeof(kbuf))
            continue;
        memcpy(kbuf, *e, klen);
        kbuf[klen] = '\0';
        v = g_py.unicode_from_string_and_size(eq + 1, (long)strlen(eq + 1));
        if (v == NULL) {
            crucible_py_clear_error();
            continue;
        }
        (void)g_py.dict_set_item_string(d, kbuf, v);
        g_py.dec_ref(v);
    }
    os_mod = g_py.import_module("os");
    if (os_mod != NULL) {
        envmap = g_py.object_get_attr_string(os_mod, "environ"); /* 借用 */
        if (envmap != NULL)
            (void)g_py.object_call_method(envmap, "update", "O", d);
        g_py.dec_ref(os_mod);
    }
    crucible_py_clear_error();
    g_py.dec_ref(d);
}

/* 引擎级失败：填 out->error 并返回 -1（app_ffi 把它变成 502 文本，不会假装成功）。 */
static int crucible_py_fail(AppEngineResult *out, const char *fmt, ...)
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

/* ------------------------------------------------------- start_response --- */

static void *crucible_py_sr_impl(void *self, void *args, void *kwds)
{
    void *status, *headers, *wr;

    (void)kwds; /* exc_info：本实现不复用旧响应，忽略 */
    status = args != NULL ? g_py.sequence_get_item(args, 0) : NULL;
    headers = args != NULL ? g_py.sequence_get_item(args, 1) : NULL;
    if (status != NULL && headers != NULL && self != NULL) {
        (void)g_py.dict_set_item_string(self, "status", status);
        (void)g_py.dict_set_item_string(self, "headers", headers);
    } else {
        crucible_py_clear_error(); /* 返回非 NULL 前不能带着异常 */
    }
    crucible_py_xdecref(status);
    crucible_py_xdecref(headers);
    wr = self != NULL ? g_py.dict_get_item_string(self, "write_callable") : NULL;
    if (wr != NULL) {
        g_py.inc_ref(wr);
        return wr;
    }
    return crucible_py_none_obj();
}

static void *crucible_py_write_impl(void *self, void *args)
{
    void *chunk, *wr, *none;

    chunk = args != NULL ? g_py.sequence_get_item(args, 0) : NULL;
    if (chunk != NULL && self != NULL) {
        wr = g_py.dict_get_item_string(self, "written");
        if (wr != NULL) {
            if (g_py.list_append(wr, chunk) != 0)
                crucible_py_clear_error();
        }
    }
    crucible_py_xdecref(chunk);
    crucible_py_clear_error();
    none = crucible_py_none_obj();
    if (none == NULL && self != NULL) { /* 极端兜底：绝不返回 NULL 且无异常 */
        g_py.inc_ref(self);
        return self;
    }
    return none;
}

/* 非 const：PyCFunction_NewEx 收 PyMethodDef*，CPython 只读不写，
 * 但去掉 const 以免"丢弃限定符"的转换告警。 */
static crucible_py_methoddef g_py_sr_def = {
    "start_response",
    (void (*)(void))crucible_py_sr_impl,
    CRUCIBLE_PY_METH_VARARGS | CRUCIBLE_PY_METH_KEYWORDS,
    "WSGI start_response(status, response_headers, exc_info=None)"
};

static crucible_py_methoddef g_py_write_def = {
    "write",
    (void (*)(void))crucible_py_write_impl,
    CRUCIBLE_PY_METH_VARARGS,
    "WSGI write(data)"
};

/* ------------------------------------------------------------ 初始化 --- */

#define CRUCIBLE_PY_LOAD(field, symname)                                     \
    do {                                                                     \
        *(void **)(&g_py.field) = dlsym(h, symname);                          \
        if (g_py.field == NULL) {                                             \
            missing = symname;                                                \
            goto fail;                                                        \
        }                                                                     \
    } while (0)

/* 首次调用：dlopen libpython + 解析符号 + Py_Initialize（一次）+ 释放 GIL。
 * 调用方必须持有 g_py_lock。 */
static int crucible_py_init_locked(char *err, size_t errsz)
{
    void *h;
    const char *missing = NULL;
    char dlerrbuf[200];
    int we_initialized = 0;

    if (g_py_state == 1)
        return 0;
    if (g_py_state == -1) {
        snprintf(err, errsz, "%s", g_py_init_err);
        return -1;
    }
    dlerrbuf[0] = '\0';
    h = crucible_dynopen(g_py_libnames,
                         sizeof(g_py_libnames) / sizeof(g_py_libnames[0]) - 1,
                         dlerrbuf, sizeof(dlerrbuf));
    if (h == NULL) {
        snprintf(g_py_init_err, sizeof(g_py_init_err), "找不到 libpython（%s）", dlerrbuf);
        g_py_state = -1;
        snprintf(err, errsz, "%s", g_py_init_err);
        return -1;
    }
    CRUCIBLE_PY_LOAD(init, "Py_Initialize");
    CRUCIBLE_PY_LOAD(is_initialized, "Py_IsInitialized");
    CRUCIBLE_PY_LOAD(finalize_ex, "Py_FinalizeEx");
    CRUCIBLE_PY_LOAD(get_version, "Py_GetVersion");
    CRUCIBLE_PY_LOAD(save_thread, "PyEval_SaveThread");
    CRUCIBLE_PY_LOAD(restore_thread, "PyEval_RestoreThread");
    CRUCIBLE_PY_LOAD(gil_ensure, "PyGILState_Ensure");
    CRUCIBLE_PY_LOAD(gil_release, "PyGILState_Release");
    CRUCIBLE_PY_LOAD(import_module, "PyImport_ImportModule");
    CRUCIBLE_PY_LOAD(object_get_attr_string, "PyObject_GetAttrString");
    CRUCIBLE_PY_LOAD(dict_new, "PyDict_New");
    CRUCIBLE_PY_LOAD(dict_set_item_string, "PyDict_SetItemString");
    CRUCIBLE_PY_LOAD(dict_get_item_string, "PyDict_GetItemString");
    CRUCIBLE_PY_LOAD(bytes_from_string_and_size, "PyBytes_FromStringAndSize");
    CRUCIBLE_PY_LOAD(bytes_as_string_and_size, "PyBytes_AsStringAndSize");
    CRUCIBLE_PY_LOAD(unicode_from_string_and_size, "PyUnicode_FromStringAndSize");
    CRUCIBLE_PY_LOAD(unicode_as_utf8_and_size, "PyUnicode_AsUTF8AndSize");
    CRUCIBLE_PY_LOAD(object_call, "PyObject_Call");
    CRUCIBLE_PY_LOAD(object_call_object, "PyObject_CallObject");
    CRUCIBLE_PY_LOAD(object_call_method, "PyObject_CallMethod");
    CRUCIBLE_PY_LOAD(object_get_iter, "PyObject_GetIter");
    CRUCIBLE_PY_LOAD(iter_next, "PyIter_Next");
    CRUCIBLE_PY_LOAD(object_str, "PyObject_Str");
    CRUCIBLE_PY_LOAD(sequence_size, "PySequence_Size");
    CRUCIBLE_PY_LOAD(sequence_get_item, "PySequence_GetItem");
    CRUCIBLE_PY_LOAD(tuple_new, "PyTuple_New");
    CRUCIBLE_PY_LOAD(tuple_set_item, "PyTuple_SetItem");
    CRUCIBLE_PY_LOAD(list_new, "PyList_New");
    CRUCIBLE_PY_LOAD(list_append, "PyList_Append");
    CRUCIBLE_PY_LOAD(long_from_long, "PyLong_FromLong");
    CRUCIBLE_PY_LOAD(cfunction_new_ex, "PyCFunction_NewEx");
    CRUCIBLE_PY_LOAD(inc_ref, "Py_IncRef");
    CRUCIBLE_PY_LOAD(dec_ref, "Py_DecRef");
    CRUCIBLE_PY_LOAD(err_occurred, "PyErr_Occurred");
    CRUCIBLE_PY_LOAD(err_clear, "PyErr_Clear");
    CRUCIBLE_PY_LOAD(err_fetch, "PyErr_Fetch");
    CRUCIBLE_PY_LOAD(err_normalize_exception, "PyErr_NormalizeException");

    if (!g_py.is_initialized()) {
        g_py.init();
        we_initialized = 1;
    }
    if (g_py.get_version != NULL) {
        const char *v = g_py.get_version();
        if (v != NULL)
            snprintf(g_py_version, sizeof(g_py_version), "%s", v);
    }
    /* 释放初始化线程持有的 GIL；请求线程各自 PyGILState_Ensure。
     * 若解释器是本进程内另一个 .so 初始化的（它已按契约 SaveThread），这里不能再
     * SaveThread —— 当前线程并不持有 GIL。 */
    if (we_initialized)
        g_py_tstate = g_py.save_thread();
    g_py_lib = h;
    g_py_state = 1;
    return 0;

fail:
    snprintf(g_py_init_err, sizeof(g_py_init_err),
             "libpython 缺少 C API 符号 %s", missing != NULL ? missing : "?");
    snprintf(err, errsz, "%s", g_py_init_err);
    memset(&g_py, 0, sizeof(g_py));
    g_py_state = -1;
    if (h != NULL)
        dlclose(h);
    return -1;
}

/* 供引擎 appengine_init / execute 调用（内部加锁，可安全并发调用）。 */
static int crucible_py_embed_ensure(char *err, size_t errsz)
{
    int rc;

    pthread_mutex_lock(&g_py_lock);
    rc = crucible_py_init_locked(err, errsz);
    pthread_mutex_unlock(&g_py_lock);
    return rc;
}

/* libpython 版本串（Py_GetVersion 首段），未初始化时为空串。 */
static const char *crucible_py_embed_version(void)
{
    return g_py_version;
}

/* ------------------------------------------------ WSGI 应用缓存（每 .so 一份） --- */

typedef struct {
    char script[1024];
    long mtime;
    long size;
    void *ns;  /* runpy 命名空间（新引用） */
    void *app; /* WSGI 可调用对象（新引用） */
} crucible_py_app_cache;

static crucible_py_app_cache g_py_app;

/* 清缓存（须持 GIL；调用方持 g_py_lock）。 */
static void crucible_py_app_cache_clear(void)
{
    crucible_py_xdecref(g_py_app.app);
    crucible_py_xdecref(g_py_app.ns);
    g_py_app.app = NULL;
    g_py_app.ns = NULL;
    g_py_app.script[0] = '\0';
    g_py_app.mtime = 0;
    g_py_app.size = 0;
}

/* 脚本所在目录（写入 out，返回 out 或 NULL）。 */
static const char *crucible_py_dirname(const char *path, char *out, size_t outsz)
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

/* 载入（或按 mtime/size 失效重载）WSGI 应用。须持 g_py_lock 且持 GIL。 */
static int crucible_py_wsgi_app_locked(const char *script, char *err, size_t errsz)
{
    struct stat st;
    void *runpy, *ns, *app;
    void *sys_mod, *sys_path;
    char dirbuf[1024];
    const char *dir;

    if (script == NULL || script[0] == '\0') {
        snprintf(err, errsz, "未解析到脚本路径");
        return -1;
    }
    if (stat(script, &st) != 0 || !S_ISREG(st.st_mode)) {
        snprintf(err, errsz, "脚本不存在或不是普通文件: %s", script);
        return -1;
    }
    if (g_py_app.ns != NULL && strcmp(g_py_app.script, script) == 0 &&
        g_py_app.mtime == (long)st.st_mtime && g_py_app.size == (long)st.st_size)
        return 0;

    runpy = g_py.import_module("runpy");
    if (runpy == NULL) {
        crucible_py_err_text(err, errsz, "import runpy 失败");
        return -1;
    }
    ns = g_py.object_call_method(runpy, "run_path", "s", script);
    g_py.dec_ref(runpy);
    if (ns == NULL) {
        crucible_py_err_text(err, errsz, "加载脚本失败");
        return -1;
    }
    app = g_py.dict_get_item_string(ns, "application");
    if (app == NULL)
        app = g_py.dict_get_item_string(ns, "app");
    if (app == NULL) {
        g_py.dec_ref(ns);
        snprintf(err, errsz,
                 "脚本未定义 WSGI 可调用对象 application（或 app）: %s", script);
        return -1;
    }
    g_py.inc_ref(app);
    /* sys.path 前置脚本目录：应用 import 同目录模块（模板/工具）时必需。 */
    sys_mod = g_py.import_module("sys");
    if (sys_mod != NULL) {
        sys_path = g_py.object_get_attr_string(sys_mod, "path");
        if (sys_path != NULL) {
            dir = crucible_py_dirname(script, dirbuf, sizeof(dirbuf));
            if (dir != NULL)
                (void)g_py.object_call_method(sys_path, "insert", "is", 0, dir);
            g_py.dec_ref(sys_path);
        }
        g_py.dec_ref(sys_mod);
    }
    crucible_py_clear_error();

    crucible_py_xdecref(g_py_app.app);
    crucible_py_xdecref(g_py_app.ns);
    g_py_app.ns = ns;
    g_py_app.app = app;
    g_py_app.mtime = (long)st.st_mtime;
    g_py_app.size = (long)st.st_size;
    snprintf(g_py_app.script, sizeof(g_py_app.script), "%s", script);
    return 0;
}

/* ------------------------------------------------------ 应用异常 → 500 --- */

static int crucible_py_serve_app_error(AppEngineResult *out, const char *label,
                                       const char *script, const char *trace)
{
    crucible_buf b;
    char head[512];

    if (out == NULL)
        return -1;
    memset(&b, 0, sizeof(b));
    snprintf(head, sizeof(head), "%s: 应用抛出异常（script=%s）\n", label,
             script != NULL ? script : "(none)");
    (void)crucible_buf_puts(&b, head);
    (void)crucible_buf_puts(&b, trace != NULL ? trace : "no traceback available\n");
    appengine_result_alloc(out);
    out->status = 500;
    appengine_result_set_headers(out, "Content-Type: text/plain; charset=utf-8\r\n");
    appengine_result_set_body(out, b.p != NULL ? b.p : "", b.len);
    /* traceback 同时写进 error（rc==0 时 app_ffi 以 body 为准，error 供直接 ABI 调用方） */
    appengine_result_set_error(out, trace != NULL ? trace : "application error");
    crucible_buf_free(&b);
    return 0;
}

/* ---------------------------------------------------------- WSGI 执行 --- */

/*
 * 一次 WSGI 请求：构造 environ → 调用 application(environ, start_response)
 * → 迭代返回值 → 填 AppEngineResult。
 * 返回 0：out 已填（应用异常 → 500 + traceback，仍是"服务过"的响应）。
 * 返回 -1：引擎级失败（out->error 已填），调用方原样返回 -1 让上层报 502。
 */
static int crucible_py_wsgi_request(const char *label, const char *script,
                                    const char *docroot, const char *method,
                                    const char *path, const char *query,
                                    const char *content_type, const char *body,
                                    size_t body_len, const char *remote,
                                    const char *server_name, int server_port,
                                    int env_dirty, AppEngineResult *out)
{
    crucible_buf hb, bb;
    char errbuf[512];
    char portbuf[16];
    char lenbuf[32];
    char hostbuf[320];
    char *trace = NULL;
    int gil = 0, rc = -1, we_gil = 0;
    void *app = NULL;
    void *environ = NULL, *args = NULL, *sr = NULL, *result = NULL, *it = NULL;
    void *state = NULL, *write_fn = NULL, *io = NULL, *pybody = NULL, *wsgi_in = NULL;
    void *sys_mod = NULL, *sys_err = NULL, *tmp = NULL, *st = NULL, *close_fn = NULL;
    void *true_obj = NULL, *false_obj = NULL, *bools = NULL;
    const char *srv = server_name != NULL && server_name[0] != '\0' ? server_name : "crucible";
    int port = server_port > 0 ? server_port : 80;

    (void)docroot; /* 脚本解析由引擎完成（script 已是可用路径） */
    memset(&hb, 0, sizeof(hb));
    memset(&bb, 0, sizeof(bb));

    if (out == NULL)
        return -1;
    if (script == NULL || script[0] == '\0')
        return crucible_py_fail(out, "%s: 未解析到脚本路径", label);
    if (body == NULL)
        body_len = 0;

    /* 步骤 1：初始化（首次调用；不需要 GIL，Py_Initialize 由本线程创建 GIL）。 */
    pthread_mutex_lock(&g_py_lock);
    if (crucible_py_init_locked(errbuf, sizeof(errbuf)) != 0) {
        pthread_mutex_unlock(&g_py_lock);
        return crucible_py_fail(out, "%s: 嵌入式 CPython 不可用: %s", label, errbuf);
    }
    pthread_mutex_unlock(&g_py_lock);

    /* 步骤 2：先拿 GIL 再拿锁（锁内只做 env 同步 + 应用加载/缓存，随即释放）。
     * 应用本体在锁外执行：应用回调本服务器时不会自锁（GIL 在 I/O 期间会释放）。 */
    gil = g_py.gil_ensure();
    we_gil = 1;
    if (env_dirty)
        crucible_py_sync_environ_locked();
    pthread_mutex_lock(&g_py_lock);
    if (crucible_py_wsgi_app_locked(script, errbuf, sizeof(errbuf)) != 0) {
        pthread_mutex_unlock(&g_py_lock);
        rc = crucible_py_fail(out, "%s: %s", label, errbuf);
        goto done;
    }
    g_py.inc_ref(g_py_app.app);
    app = g_py_app.app; /* 本请求的强引用：缓存可被并发重载/shutdown 清空 */
    pthread_mutex_unlock(&g_py_lock);

    /* 1) 请求体 → bytes；wsgi.input = io.BytesIO(body) */
    pybody = g_py.bytes_from_string_and_size(body, (long)body_len);
    if (pybody == NULL) {
        crucible_py_err_text(errbuf, sizeof(errbuf), "构造请求体失败");
        rc = crucible_py_fail(out, "%s: %s", label, errbuf);
        goto done;
    }
    io = g_py.import_module("io");
    if (io != NULL) {
        wsgi_in = g_py.object_call_method(io, "BytesIO", "O", pybody);
        g_py.dec_ref(io);
    }
    crucible_py_clear_error();
    /* 2) wsgi.errors = sys.stderr（借用引用） */
    sys_mod = g_py.import_module("sys");
    if (sys_mod != NULL)
        sys_err = g_py.object_get_attr_string(sys_mod, "stderr");
    crucible_py_clear_error();
    /* 3) 真 bool 单例（builtins.bool(1) / bool(0)） */
    {
        void *bi_mod = g_py.import_module("builtins");
        if (bi_mod != NULL) {
            bools = g_py.object_get_attr_string(bi_mod, "__dict__");
            g_py.dec_ref(bi_mod);
        }
        if (bools != NULL) {
            void *bool_type = g_py.dict_get_item_string(bools, "bool"); /* 借用 */
            true_obj = crucible_py_bool_obj(bool_type, 1);
            false_obj = crucible_py_bool_obj(bool_type, 0);
        }
        crucible_py_clear_error();
    }
    if (wsgi_in == NULL || sys_err == NULL || true_obj == NULL || false_obj == NULL) {
        crucible_py_err_text(errbuf, sizeof(errbuf), "构造 environ 依赖对象失败");
        rc = crucible_py_fail(out, "%s: %s", label, errbuf);
        goto done;
    }

    /* 4) environ */
    environ = g_py.dict_new();
    if (environ == NULL) {
        crucible_py_err_text(errbuf, sizeof(errbuf), "构造 environ 失败");
        rc = crucible_py_fail(out, "%s: %s", label, errbuf);
        goto done;
    }
    snprintf(portbuf, sizeof(portbuf), "%d", port);
    if (port == 80)
        snprintf(hostbuf, sizeof(hostbuf), "%s", srv);
    else
        snprintf(hostbuf, sizeof(hostbuf), "%s:%d", srv, port);
    (void)crucible_py_dict_set_str(environ, "REQUEST_METHOD", method ? method : "GET");
    (void)crucible_py_dict_set_str(environ, "SCRIPT_NAME", "");
    (void)crucible_py_dict_set_str(environ, "PATH_INFO", path ? path : "/");
    (void)crucible_py_dict_set_str(environ, "QUERY_STRING", query ? query : "");
    (void)crucible_py_dict_set_str(environ, "SERVER_PROTOCOL", "HTTP/1.1");
    (void)crucible_py_dict_set_str(environ, "SERVER_NAME", srv);
    (void)crucible_py_dict_set_str(environ, "SERVER_PORT", portbuf);
    (void)crucible_py_dict_set_str(environ, "REMOTE_ADDR", remote ? remote : "");
    (void)crucible_py_dict_set_str(environ, "HTTP_HOST", hostbuf);
    if (content_type != NULL && content_type[0] != '\0')
        (void)crucible_py_dict_set_str(environ, "CONTENT_TYPE", content_type);
    if (body_len > 0) {
        snprintf(lenbuf, sizeof(lenbuf), "%lu", (unsigned long)body_len);
        (void)crucible_py_dict_set_str(environ, "CONTENT_LENGTH", lenbuf);
    }
    tmp = crucible_py_int_tuple(1, 0);
    if (tmp != NULL) {
        (void)g_py.dict_set_item_string(environ, "wsgi.version", tmp);
        g_py.dec_ref(tmp);
        tmp = NULL;
    }
    (void)crucible_py_dict_set_str(environ, "wsgi.url_scheme", "http");
    (void)g_py.dict_set_item_string(environ, "wsgi.input", wsgi_in);
    (void)g_py.dict_set_item_string(environ, "wsgi.errors", sys_err);
    (void)g_py.dict_set_item_string(environ, "wsgi.multithread", true_obj);
    (void)g_py.dict_set_item_string(environ, "wsgi.multiprocess", false_obj);
    (void)g_py.dict_set_item_string(environ, "wsgi.run_once", false_obj);
    /* uwsgi.version：WSGI 允许 environ 带额外键，uWSGI 应用会读它。本引擎同时服务
     * wsgi/uwsgi 两个路由，统一注入，对纯 WSGI 应用无副作用。 */
    tmp = g_py.bytes_from_string_and_size("crucible", 8);
    if (tmp != NULL) {
        (void)g_py.dict_set_item_string(environ, "uwsgi.version", tmp);
        g_py.dec_ref(tmp);
        tmp = NULL;
    }

    /* 5) start_response / write：self = 本次请求的 state 字典（无跨请求共享） */
    state = g_py.dict_new();
    if (state == NULL) {
        crucible_py_err_text(errbuf, sizeof(errbuf), "构造响应状态失败");
        rc = crucible_py_fail(out, "%s: %s", label, errbuf);
        goto done;
    }
    write_fn = g_py.cfunction_new_ex((void *)&g_py_write_def, state, NULL);
    if (write_fn == NULL) {
        crucible_py_err_text(errbuf, sizeof(errbuf), "构造 write() 失败");
        rc = crucible_py_fail(out, "%s: %s", label, errbuf);
        goto done;
    }
    (void)g_py.dict_set_item_string(state, "write_callable", write_fn);
    tmp = g_py.list_new(0);
    if (tmp != NULL) {
        (void)g_py.dict_set_item_string(state, "written", tmp);
        g_py.dec_ref(tmp);
        tmp = NULL;
    }
    sr = g_py.cfunction_new_ex((void *)&g_py_sr_def, state, NULL);
    if (sr == NULL) {
        crucible_py_err_text(errbuf, sizeof(errbuf), "构造 start_response() 失败");
        rc = crucible_py_fail(out, "%s: %s", label, errbuf);
        goto done;
    }

    /* 6) application(environ, start_response) */
    args = g_py.tuple_new(2);
    if (args == NULL) {
        rc = crucible_py_fail(out, "%s: 构造调用参数失败", label);
        goto done;
    }
    g_py.inc_ref(environ);
    if (g_py.tuple_set_item(args, 0, environ) != 0) { /* 失败时已 DECREF */
        rc = crucible_py_fail(out, "%s: 构造调用参数失败", label);
        goto done;
    }
    g_py.inc_ref(sr);
    if (g_py.tuple_set_item(args, 1, sr) != 0) {
        rc = crucible_py_fail(out, "%s: 构造调用参数失败", label);
        goto done;
    }
    result = g_py.object_call(app, args, NULL);
    if (result == NULL) {
        trace = crucible_py_take_error();
        rc = crucible_py_serve_app_error(out, label, script, trace);
        free(trace);
        trace = NULL;
        goto done;
    }

    /* 7) 响应头 + write() 输出 + 迭代输出（PEP 3333 顺序：write() 先于迭代器） */
    (void)crucible_py_emit_headers(&hb, g_py.dict_get_item_string(state, "headers"));
    crucible_py_append_seq(&bb, g_py.dict_get_item_string(state, "written"));
    it = g_py.object_get_iter(result);
    if (it == NULL) {
        crucible_py_clear_error(); /* 非 iterable：仅用 write() 输出，不视为致命 */
    } else {
        void *chunk;
        while ((chunk = g_py.iter_next(it)) != NULL) {
            (void)crucible_py_append_obj(&bb, chunk);
            g_py.dec_ref(chunk);
        }
        crucible_py_clear_error();
        g_py.dec_ref(it);
        it = NULL;
    }
    close_fn = g_py.object_get_attr_string(result, "close");
    if (close_fn != NULL) {
        (void)g_py.object_call_object(close_fn, NULL);
        g_py.dec_ref(close_fn);
        close_fn = NULL;
    }
    crucible_py_clear_error();

    /* 8) 状态行 */
    st = g_py.dict_get_item_string(state, "status"); /* 借用 */
    if (st == NULL) {
        rc = crucible_py_serve_app_error(
            out, label, script,
            "application() 未调用 start_response()（PEP 3333 要求）\n");
        goto done;
    }
    if (appengine_result_alloc(out) != 0) {
        rc = -1;
        goto done;
    }
    {
        const char *ss = crucible_py_text(st, NULL, NULL);
        int code = crucible_py_status_code(ss);
        out->status = code > 0 ? code : 200;
    }
    if (hb.len == 0)
        (void)crucible_buf_puts(&hb, "Content-Type: text/plain; charset=utf-8\r\n");
    appengine_result_set_headers(out, hb.p != NULL ? hb.p : "");
    appengine_result_set_body(out, bb.p != NULL ? bb.p : "", bb.len);
    rc = 0;

done:
    /* 先释放 Python 引用（须持 GIL），再释放 GIL。锁在步骤 2 末尾已释放。 */
    crucible_py_xdecref(app);
    crucible_py_xdecref(environ);
    crucible_py_xdecref(args);
    crucible_py_xdecref(sr);
    crucible_py_xdecref(result);
    crucible_py_xdecref(state);
    crucible_py_xdecref(write_fn);
    crucible_py_xdecref(pybody);
    crucible_py_xdecref(wsgi_in);
    crucible_py_xdecref(sys_mod);
    crucible_py_xdecref(bools);
    crucible_py_xdecref(true_obj);
    crucible_py_xdecref(false_obj);
    if (we_gil)
        g_py.gil_release(gil);
    crucible_buf_free(&hb);
    crucible_buf_free(&bb);
    return rc;
}

/* ---------------------------------------------------------- ASGI 执行 --- */

/*
 * ASGI 需要事件循环，C 侧不便手写；这里把驱动逻辑作为 Python 源码 exec 进一个
 * 新建的命名空间（同进程内执行，不是 spawn），再读回结果字典。
 * 应用按 (script, mtime) 缓存：缓存在同解释器的 sys.modules 私有键下，语义与
 * WSGI 路径一致（import 一次的 ASGI 应用不会被每请求重新执行），脚本改动即重载。
 * 输入：__cr_script / __cr_method / __cr_path / __cr_query / __cr_body /
 *       __cr_ct / __cr_host / __cr_port / __cr_remote
 * 输出：__cr_result = {'status': str, 'headers': "K: V\r\n" 文本块, 'body': bytes}
 */
static const char *g_py_asgi_driver =
    "import asyncio, os, runpy, sys, types\n"
    "_C = sys.modules.get('__crucible_asgi_cache__')\n"
    "if _C is None:\n"
    "    _C = types.SimpleNamespace(apps={})\n"
    "    sys.modules['__crucible_asgi_cache__'] = _C\n"
    "try:\n"
    "    _mt = os.stat(__cr_script).st_mtime\n"
    "except OSError:\n"
    "    _mt = None\n"
    "_ent = _C.apps.get(__cr_script)\n"
    "if _ent is None or _ent[0] != _mt:\n"
    "    _ns = runpy.run_path(__cr_script)\n"
    "    _app = _ns.get('app') or _ns.get('application')\n"
    "    if _app is None:\n"
    "        raise RuntimeError('asgi: no app/application callable in ' + __cr_script)\n"
    "    _ent = (_mt, _app)\n"
    "    _C.apps[__cr_script] = _ent\n"
    "_app = _ent[1]\n"
    "_status = [200]\n"
    "_headers = []\n"
    "_body = bytearray()\n"
    "async def _receive():\n"
    "    return {'type': 'http.request', 'body': __cr_body, 'more_body': False}\n"
    "async def _send(message):\n"
    "    _t = message.get('type')\n"
    "    if _t == 'http.response.start':\n"
    "        _status[0] = int(message.get('status', 200))\n"
    "        _headers[:] = list(message.get('headers') or [])\n"
    "    elif _t == 'http.response.body':\n"
    "        _body.extend(message.get('body') or b'')\n"
    "_hdrs = [(b'host', __cr_host.encode('utf-8', 'surrogateescape'))]\n"
    "if __cr_ct:\n"
    "    _hdrs.append((b'content-type', __cr_ct.encode('utf-8', 'surrogateescape')))\n"
    "_scope = {\n"
    "    'type': 'http',\n"
    "    'asgi': {'version': '3.0', 'spec_version': '2.3'},\n"
    "    'http_version': '1.1',\n"
    "    'method': __cr_method,\n"
    "    'path': __cr_path,\n"
    "    'raw_path': __cr_path.encode('utf-8', 'surrogateescape'),\n"
    "    'query_string': __cr_query.encode('utf-8', 'surrogateescape'),\n"
    "    'root_path': '',\n"
    "    'scheme': 'http',\n"
    "    'headers': _hdrs,\n"
    "    'client': (__cr_remote or '0.0.0.0', 0),\n"
    "    'server': (__cr_host, __cr_port),\n"
    "}\n"
    "asyncio.run(_app(_scope, _receive, _send))\n"
    "__cr_result = {\n"
    "    'status': str(_status[0]),\n"
    "    'headers': ''.join('%s: %s\\r\\n' % (k.decode('latin-1'), v.decode('latin-1'))\n"
    "                       for k, v in _headers),\n"
    "    'body': bytes(_body),\n"
    "}\n";

/* builtins.compile + builtins.exec：不引用 PyRun_* 与编译期枚举常量。 */
static void *crucible_py_exec_source(const char *src, const char *fname, void *globals,
                                     char *err, size_t errsz)
{
    void *bi, *code, *r;

    bi = g_py.import_module("builtins");
    if (bi == NULL) {
        crucible_py_err_text(err, errsz, "import builtins 失败");
        return NULL;
    }
    code = g_py.object_call_method(bi, "compile", "sss", src, fname, "exec");
    if (code == NULL) {
        crucible_py_err_text(err, errsz, "compile 驱动失败");
        g_py.dec_ref(bi);
        return NULL;
    }
    r = g_py.object_call_method(bi, "exec", "OO", code, globals);
    g_py.dec_ref(code);
    g_py.dec_ref(bi);
    if (r == NULL) {
        crucible_py_err_text(err, errsz, "执行驱动失败");
        return NULL;
    }
    return r;
}

static int crucible_py_asgi_request(const char *label, const char *script,
                                    const char *docroot, const char *method,
                                    const char *path, const char *query,
                                    const char *content_type, const char *body,
                                    size_t body_len, const char *remote,
                                    const char *server_name, int server_port,
                                    int env_dirty, AppEngineResult *out)
{
    crucible_buf hb, bb;
    char errbuf[512];
    char hostbuf[320];
    char *htmp = NULL;
    char *trace = NULL;
    int gil = 0, rc = -1, we_gil = 0;
    void *g = NULL, *res = NULL, *pybody = NULL, *drv = NULL, *st = NULL, *hd = NULL;
    void *bdy = NULL, *portobj = NULL;
    const char *srv = server_name != NULL && server_name[0] != '\0' ? server_name : "crucible";
    int port = server_port > 0 ? server_port : 80;

    (void)docroot;
    memset(&hb, 0, sizeof(hb));
    memset(&bb, 0, sizeof(bb));

    if (out == NULL)
        return -1;
    if (script == NULL || script[0] == '\0')
        return crucible_py_fail(out, "%s: 未解析到脚本路径", label);
    if (body == NULL)
        body_len = 0;

    /* 步骤 1：初始化（首次调用，不需要 GIL）。 */
    pthread_mutex_lock(&g_py_lock);
    if (crucible_py_init_locked(errbuf, sizeof(errbuf)) != 0) {
        pthread_mutex_unlock(&g_py_lock);
        return crucible_py_fail(out, "%s: 嵌入式 CPython 不可用: %s", label, errbuf);
    }
    pthread_mutex_unlock(&g_py_lock);

    /* 步骤 2：只持 GIL（驱动在每请求独立命名空间里跑，无共享可变状态，不占进程锁）。 */
    gil = g_py.gil_ensure();
    we_gil = 1;
    if (env_dirty)
        crucible_py_sync_environ_locked();

    if (port == 80)
        snprintf(hostbuf, sizeof(hostbuf), "%s", srv);
    else
        snprintf(hostbuf, sizeof(hostbuf), "%s:%d", srv, port);
    pybody = g_py.bytes_from_string_and_size(body, (long)body_len);
    portobj = g_py.long_from_long(port);
    g = g_py.dict_new();
    if (pybody == NULL || portobj == NULL || g == NULL) {
        crucible_py_err_text(errbuf, sizeof(errbuf), "构造 ASGI 驱动参数失败");
        rc = crucible_py_fail(out, "%s: %s", label, errbuf);
        goto done;
    }
    (void)crucible_py_dict_set_str(g, "__cr_script", script);
    (void)crucible_py_dict_set_str(g, "__cr_method", method ? method : "GET");
    (void)crucible_py_dict_set_str(g, "__cr_path", path ? path : "/");
    (void)crucible_py_dict_set_str(g, "__cr_query", query ? query : "");
    (void)crucible_py_dict_set_str(g, "__cr_ct", content_type ? content_type : "");
    (void)crucible_py_dict_set_str(g, "__cr_host", hostbuf);
    (void)crucible_py_dict_set_str(g, "__cr_remote", remote ? remote : "");
    (void)g_py.dict_set_item_string(g, "__cr_body", pybody);
    (void)g_py.dict_set_item_string(g, "__cr_port", portobj);

    drv = crucible_py_exec_source(g_py_asgi_driver, "<crucible-asgi-driver>", g,
                                  errbuf, sizeof(errbuf));
    if (drv == NULL) {
        /* 驱动 exec 失败：几乎总是应用的导入/调用异常（驱动本身是固定代码）。
         * 给 500 + traceback（errbuf 里已是 traceback 文本），与 WSGI 路径一致；
         * 引擎不可用的情况在初始化阶段就已显式失败。 */
        rc = crucible_py_serve_app_error(out, label, script, errbuf);
        goto done;
    }
    res = g_py.dict_get_item_string(g, "__cr_result"); /* 借用 */
    if (res == NULL) {
        trace = crucible_py_take_error();
        rc = crucible_py_serve_app_error(out, label, script, trace);
        free(trace);
        trace = NULL;
        goto done;
    }
    st = g_py.dict_get_item_string(res, "status");  /* 借用 */
    hd = g_py.dict_get_item_string(res, "headers"); /* 借用：已是 "K: V\r\n" 文本块 */
    bdy = g_py.dict_get_item_string(res, "body");   /* 借用：bytes */

    if (hd != NULL) {
        long hl = 0;
        const char *hs = crucible_py_text(hd, &hl, &htmp);
        if (hs != NULL && hl > 0)
            (void)crucible_buf_append(&hb, hs, (size_t)hl);
        free(htmp);
        htmp = NULL;
    }
    if (bdy != NULL)
        (void)crucible_py_append_obj(&bb, bdy);
    crucible_py_clear_error();

    if (appengine_result_alloc(out) != 0) {
        rc = -1;
        goto done;
    }
    {
        const char *ss = crucible_py_text(st, NULL, NULL);
        int code = crucible_py_status_code(ss);
        out->status = code > 0 ? code : 200;
    }
    if (hb.len == 0)
        (void)crucible_buf_puts(&hb, "Content-Type: text/plain; charset=utf-8\r\n");
    appengine_result_set_headers(out, hb.p != NULL ? hb.p : "");
    appengine_result_set_body(out, bb.p != NULL ? bb.p : "", bb.len);
    rc = 0;

done:
    crucible_py_xdecref(drv);
    crucible_py_xdecref(pybody);
    crucible_py_xdecref(portobj);
    crucible_py_xdecref(g);
    if (we_gil)
        g_py.gil_release(gil);
    crucible_buf_free(&hb);
    crucible_buf_free(&bb);
    return rc;
}

/* ------------------------------------------------------------- 关闭 --- */

/*
 * shutdown 只清应用缓存，不 Py_FinalizeEx：
 *   - Py_FinalizeEx 必须在初始化线程调用，而本函数可能来自任意线程；
 *   - 解释器常驻是本进程多脚本引擎（python / wsgi / asgi / uwsgi）共存的前提。
 * 进程退出由内核回收。清缓存需要 GIL，走与请求相同的路径。
 */
static void crucible_py_embed_shutdown(void)
{
    pthread_mutex_lock(&g_py_lock);
    if (g_py_state == 1 && g_py.is_initialized != NULL && g_py.is_initialized()) {
        int gil = g_py.gil_ensure();
        crucible_py_app_cache_clear();
        g_py.gil_release(gil);
    }
    pthread_mutex_unlock(&g_py_lock);
}

#endif /* CRUCIBLE_HAVE_PYTHON */

#endif /* CRUCIBLE_PYEMBED_H */
