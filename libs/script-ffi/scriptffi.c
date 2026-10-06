/* scriptffi — 进程内解释器（Python / Ruby / Perl），无 popen 回退。
 *
 * Production path: dlopen libscriptffi.so from script_ffi.rs.
 *
 * 缺 CRUCIBLE_HAVE_* 时对应语言显式失败（返回 -1 并把诊断写进 out），
 * 既不 spawn 解释器、也不返回 "hello from ..." 之类假响应。
 * 跨 .so GIL 契约见 libs/app-engines/common/crucible_embed.h 文件头。
 */
#include "scriptffi.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <pthread.h>
#include <unistd.h>
#endif

static int g_ready;

/* ---------------------------------------------- 跨 .so 进程级初始化锁（F2） ---
 * 本 .so 只被构建、不直接服务请求，但它是所有嵌入式 CPython 引擎（libapp_python /
 * wsgi / asgi / uwsgi）的**共享初始化协调点**：这些 .so 各自嵌入同一份 libpython，
 * 若各自用自己的 pthread_once 做 Py_Initialize，并发冷启动时后到线程会在 NULL
 * tstate 上 PyEval_SaveThread → Py_FatalError(abort)。
 *
 * 调用方（见 libs/app-engines/common/crucible_pyinit.h）通过 dlopen 本 .so 并
 * dlsym 本符号，把**自己已解析好的** Py_IsInitialized / Py_Initialize /
 * PyEval_SaveThread 指针传进来——这样锁是进程内唯一的一份，而初始化的仍是调用方
 * 自己的解释器实例。此处不引用任何链接期 Py_* 符号：本 .so 未链接 libpython 时
 * 也必须能提供该符号。 */
#ifndef _WIN32
int crucible_py_ensure_init(int (*is_initialized)(void),
                            void (*initialize)(void), void *(*save_thread)(void),
                            char *err, size_t errsz)
{
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    static int state; /* 0 = 未尝试 1 = 就绪 -1 = 失败 */
    static char failmsg[256];

    if (err != NULL && errsz > 0)
        err[0] = '\0';
    pthread_mutex_lock(&lock);
    if (state == 1) {
        pthread_mutex_unlock(&lock);
        return 0;
    }
    if (state == -1) {
        if (err != NULL && errsz > 0)
            snprintf(err, errsz, "%s", failmsg);
        pthread_mutex_unlock(&lock);
        return -1;
    }
    if (is_initialized == NULL || initialize == NULL) {
        snprintf(failmsg, sizeof(failmsg), "Python 初始化 API 指针为空");
        state = -1;
        if (err != NULL && errsz > 0)
            snprintf(err, errsz, "%s", failmsg);
        pthread_mutex_unlock(&lock);
        return -1;
    }
    if (!is_initialized()) {
        initialize();
        /* 只由初始化线程释放 GIL：这里刚从 Py_Initialize 返回，tstate 必然在
         * 本线程。解释器已由别的 .so 初始化时不碰 GIL（那个 .so 已按契约释放）。 */
        if (save_thread != NULL)
            (void)save_thread();
    }
    state = 1;
    pthread_mutex_unlock(&lock);
    return 0;
}
#endif /* _WIN32 */

static const char *interp_for(const char *lang)
{
    if (!lang)
        return "python3";
    if (strcmp(lang, "python") == 0 || strcmp(lang, "py") == 0)
        return "python3";
    if (strcmp(lang, "ruby") == 0 || strcmp(lang, "rb") == 0)
        return "ruby";
    if (strcmp(lang, "perl") == 0 || strcmp(lang, "pl") == 0)
        return "perl";
    return "python3";
}

#if defined(CRUCIBLE_HAVE_PYTHON)
#include <Python.h>

/* 解释器初始化：走共享锁（跨 .so 唯一）。本函数不释放 GIL —— 只有真正执行
 * Py_Initialize 的线程才该释放，那由 crucible_py_ensure_init 内部保证。 */
static int crucible_scriptffi_py_boot(char *err, size_t errsz)
{
    /* PyEval_SaveThread 返回 PyThreadState*，共享 ABI 用 void*（宽度一致）；
     * GCC 15 把函数指针类型不兼容当错误，故显式转换。 */
    return crucible_py_ensure_init(Py_IsInitialized, Py_Initialize,
                                   (void *(*)(void))PyEval_SaveThread,
                                   err, errsz);
}

#ifndef _WIN32
/* 本 .so 的 Python 执行锁：`sys.stdout` 全局替换 + 执行 + 取回必须原子。
 * （本库当前无调用方，属 F2/P3 的顺手收口：保留功能但杜绝并发串写。） */
static pthread_mutex_t g_scriptffi_py_lock = PTHREAD_MUTEX_INITIALIZER;
#define SCRIPTFFI_PY_LOCK()   pthread_mutex_lock(&g_scriptffi_py_lock)
#define SCRIPTFFI_PY_UNLOCK() pthread_mutex_unlock(&g_scriptffi_py_lock)
#else
#define SCRIPTFFI_PY_LOCK()   ((void)0)
#define SCRIPTFFI_PY_UNLOCK() ((void)0)
#endif

static int run_python(const char *script_path, const char *method, const char *path,
                      const char *query, char *out, size_t out_len)
{
    FILE *fp = NULL;
    PyObject *sys_mod = NULL, *stdout_obj = NULL, *io_mod = NULL, *buf = NULL;
    PyObject *getvalue = NULL, *result = NULL, *globals = NULL;
    PyGILState_STATE gil;
    char errbuf[256];
    int n = -1;

    if (crucible_scriptffi_py_boot(errbuf, sizeof(errbuf)) != 0) {
        fprintf(stderr, "scriptffi: CPython 初始化失败: %s\n", errbuf);
        return -1;
    }
    gil = PyGILState_Ensure();
    SCRIPTFFI_PY_LOCK(); /* 全局 stdout 替换 + 执行 + 恢复 必须原子（F1 同类问题） */

    io_mod = PyImport_ImportModule("io");
    if (io_mod == NULL)
        goto done;
    buf = PyObject_CallMethod(io_mod, "StringIO", NULL);
    Py_DECREF(io_mod);
    io_mod = NULL;
    if (buf == NULL)
        goto done;

    sys_mod = PyImport_ImportModule("sys");
    if (sys_mod == NULL)
        goto done;
    stdout_obj = PyObject_GetAttrString(sys_mod, "stdout");
    if (stdout_obj == NULL)
        goto done;
    if (PyObject_SetAttrString(sys_mod, "stdout", buf) != 0)
        goto done;

    {
        PyObject *os = PyImport_ImportModule("os");
        if (os != NULL) {
            PyObject *environ = PyObject_GetAttrString(os, "environ");
            if (environ != NULL) {
                struct {
                    const char *k;
                    const char *v;
                } kv[4];
                int i;

                kv[0].k = "REQUEST_METHOD";
                kv[0].v = method ? method : "GET";
                kv[1].k = "PATH_INFO";
                kv[1].v = path ? path : "/";
                kv[2].k = "QUERY_STRING";
                kv[2].v = query ? query : "";
                kv[3].k = "SCRIPT_FILENAME";
                kv[3].v = script_path;
                for (i = 0; i < 4; i++) {
                    PyObject *k = PyUnicode_FromString(kv[i].k);
                    PyObject *v = PyUnicode_FromString(kv[i].v);
                    if (k == NULL || v == NULL) {
                        Py_XDECREF(k);
                        Py_XDECREF(v);
                        continue;
                    }
                    /* **不能用 PyDict_SetItemString**：os.environ 是 os._Environ
                     * （MutableMapping），不是 dict —— PyDict_* 会抛 SystemError，
                     * 返回值此前还被丢弃，导致请求环境静默不生效。 */
                    (void)PyObject_SetItem(environ, k, v);
                    Py_DECREF(k);
                    Py_DECREF(v);
                }
                Py_DECREF(environ);
            }
            Py_DECREF(os);
        }
        PyErr_Clear();
    }

    fp = fopen(script_path, "r");
    if (fp == NULL)
        goto done;
    /* 每请求独立命名空间（不再共享 __main__），并在执行前检查返回值：
     * 旧实现丢弃 PyRun_SimpleFileEx 的返回值，脚本抛异常时给出假成功。 */
    globals = PyDict_New();
    if (globals == NULL)
        goto done;
    {
        PyObject *name = PyUnicode_FromString("__main__");
        PyObject *file = PyUnicode_FromString(script_path);
        if (name != NULL)
            (void)PyDict_SetItemString(globals, "__name__", name);
        if (file != NULL)
            (void)PyDict_SetItemString(globals, "__file__", file);
        Py_XDECREF(name);
        Py_XDECREF(file);
    }
    result = PyRun_FileExFlags(fp, script_path, Py_file_input, globals, globals, 1, NULL);
    fp = NULL; /* 已由 CPython 关闭 */
    if (result == NULL) {
        if (PyErr_Occurred())
            PyErr_Print(); /* traceback 进本地日志并清异常 */
        PyErr_Clear();
        goto done;
    }
    Py_CLEAR(result);

    getvalue = PyObject_GetAttrString(buf, "getvalue");
    result = getvalue != NULL ? PyObject_CallObject(getvalue, NULL) : NULL;
    if (result != NULL && PyUnicode_Check(result)) {
        const char *s = PyUnicode_AsUTF8(result);
        if (s != NULL) {
            size_t m = strlen(s);
            if (m + 1 > out_len) {
                /* 旧实现静默截断超长输出。明确失败，让调用方报错而不是发半截 body。 */
                fprintf(stderr,
                        "scriptffi: 脚本输出 %lu 字节超过调用方缓冲 %lu，拒绝截断\n",
                        (unsigned long)m, (unsigned long)out_len);
            } else {
                memcpy(out, s, m + 1);
                n = (int)m;
            }
        }
    }

done:
    if (fp != NULL)
        fclose(fp);
    if (sys_mod != NULL && stdout_obj != NULL)
        (void)PyObject_SetAttrString(sys_mod, "stdout", stdout_obj);
    Py_XDECREF(globals);
    Py_XDECREF(result);
    Py_XDECREF(getvalue);
    Py_XDECREF(stdout_obj);
    Py_XDECREF(sys_mod);
    Py_XDECREF(buf);
    Py_XDECREF(io_mod);
    PyErr_Clear();
    SCRIPTFFI_PY_UNLOCK();
    PyGILState_Release(gil);
    return n;
}
#endif

#if defined(CRUCIBLE_HAVE_RUBY)
#include <ruby.h>
#ifndef _WIN32
static pthread_mutex_t g_scriptffi_ruby_lock = PTHREAD_MUTEX_INITIALIZER;
#define SCRIPTFFI_RUBY_LOCK()   pthread_mutex_lock(&g_scriptffi_ruby_lock)
#define SCRIPTFFI_RUBY_UNLOCK() pthread_mutex_unlock(&g_scriptffi_ruby_lock)
#else
#define SCRIPTFFI_RUBY_LOCK()   ((void)0)
#define SCRIPTFFI_RUBY_UNLOCK() ((void)0)
#endif
static int run_ruby(const char *script_path, char *out, size_t out_len)
{
    int state = 0;
    VALUE v;
    static int started;
    size_t m;

    SCRIPTFFI_RUBY_LOCK(); /* MRI 调用必须串行（F1 同组问题；见 rack 的崩溃记录） */
    if (!started) {
        ruby_init();
        ruby_init_loadpath();
        started = 1;
    }
    rb_eval_string_protect(
        "begin; require 'stringio'; $__c = StringIO.new; $stdout=$__c; "
        "rescue LoadError; $__c=nil; end",
        &state);
    rb_load_protect(rb_str_new_cstr(script_path), 0, &state);
    v = rb_eval_string_protect("$__c ? $__c.string : ''", &state);
    if (state == 0 && TYPE(v) == T_STRING) {
        m = (size_t)RSTRING_LEN(v);
        if (m + 1 > out_len) {
            fprintf(stderr, "scriptffi: ruby 输出 %lu 字节超过调用方缓冲 %lu\n",
                    (unsigned long)m, (unsigned long)out_len);
        } else {
            memcpy(out, RSTRING_PTR(v), m);
            out[m] = '\0';
            SCRIPTFFI_RUBY_UNLOCK();
            return (int)m;
        }
    }
    SCRIPTFFI_RUBY_UNLOCK();
    return -1;
}
#endif

#if defined(CRUCIBLE_HAVE_PERL)
#include <EXTERN.h>
#include <perl.h>
static PerlInterpreter *g_perl;
#ifndef _WIN32
static pthread_mutex_t g_scriptffi_perl_lock = PTHREAD_MUTEX_INITIALIZER;
#define SCRIPTFFI_PERL_LOCK()   pthread_mutex_lock(&g_scriptffi_perl_lock)
#define SCRIPTFFI_PERL_UNLOCK() pthread_mutex_unlock(&g_scriptffi_perl_lock)
#else
#define SCRIPTFFI_PERL_LOCK()   ((void)0)
#define SCRIPTFFI_PERL_UNLOCK() ((void)0)
#endif
static int run_perl(const char *script_path, char *out, size_t out_len)
{
    SV *sv;
    STRLEN n;
    char *s;
    char *args[] = {"", (char *)script_path};

    SCRIPTFFI_PERL_LOCK(); /* 单解释器被多线程调用必须串行（F1 同组问题） */
    if (!g_perl) {
        int argc = 1;
        char *a0 = "";
        char **argv = &a0;
        char **env = NULL;
        PERL_SYS_INIT3(&argc, &argv, &env);
        g_perl = perl_alloc();
        perl_construct(g_perl);
    }
    perl_parse(g_perl, NULL, 2, args, NULL);
    perl_run(g_perl);
    sv = eval_pv("do { local $/; open my $f,'<',$ARGV[0] or die; my $c=<$f>; "
                 "close $f; open my $o,'>',\\(my $b=''); my $old=select $o; "
                 "eval $c; select $old; $b }",
                 0);
    if (!sv || !SvOK(sv)) {
        SCRIPTFFI_PERL_UNLOCK();
        return -1;
    }
    s = SvPV(sv, n);
    if (!s) {
        SCRIPTFFI_PERL_UNLOCK();
        return -1;
    }
    if (n + 1 > out_len) { /* 旧实现静默截断 */
        fprintf(stderr, "scriptffi: perl 输出 %lu 字节超过调用方缓冲 %lu\n",
                (unsigned long)n, (unsigned long)out_len);
        SCRIPTFFI_PERL_UNLOCK();
        return -1;
    }
    memcpy(out, s, n);
    out[n] = '\0';
    SCRIPTFFI_PERL_UNLOCK();
    return (int)n;
}
#endif

/*
 * 嵌入不可用（缺 CRUCIBLE_HAVE_*）：显式失败。
 * 名字里不再带 popen——spec 禁止每请求 spawn 解释器，本库没有也不会有 spawn 路径。
 */
#if !defined(CRUCIBLE_HAVE_PYTHON) || !defined(CRUCIBLE_HAVE_RUBY) || \
    !defined(CRUCIBLE_HAVE_PERL)

static int run_embed_missing(const char *interp, const char *script_path, char *out,
                             size_t out_len)
{
    if (out && out_len > 0)
        out[0] = '\0';
    (void)script_path;
    fprintf(stderr,
            "scriptffi: %s 进程内解释器不可用（重建时加 CRUCIBLE_HAVE_*）；"
            "不做 popen 回退，也不返回假响应\n",
            interp);
    return -1;
}
#endif /* embed-missing 分支 */

int crucible_scriptffi_init(const char *lang)
{
    (void)lang;
    g_ready = 1;
    return 0;
}

int crucible_scriptffi_execute(
    const char *lang,
    const char *script_path,
    const char *method,
    const char *path,
    const char *query,
    const char *body,
    size_t body_len,
    char *out,
    size_t out_len)
{
    int n = -1;
    const char *interp;

    (void)body;
    (void)body_len;
    if (!g_ready || !out || out_len == 0) {
        return -1;
    }
    out[0] = '\0';

    interp = interp_for(lang);
    if (script_path && script_path[0]) {
        if (strcmp(interp, "python3") == 0) {
#if defined(CRUCIBLE_HAVE_PYTHON)
            n = run_python(script_path, method, path, query, out, out_len);
            if (n > 0)
                return n;
#else
            n = run_embed_missing(interp, script_path, out, out_len);
            if (n > 0)
                return n;
#endif
        } else if (strcmp(interp, "ruby") == 0) {
#if defined(CRUCIBLE_HAVE_RUBY)
            n = run_ruby(script_path, out, out_len);
            if (n > 0)
                return n;
#else
            n = run_embed_missing(interp, script_path, out, out_len);
            if (n > 0)
                return n;
#endif
        } else if (strcmp(interp, "perl") == 0) {
#if defined(CRUCIBLE_HAVE_PERL)
            n = run_perl(script_path, out, out_len);
            if (n > 0)
                return n;
#else
            n = run_embed_missing(interp, script_path, out, out_len);
            if (n > 0)
                return n;
#endif
        } else {
#if !defined(CRUCIBLE_HAVE_PYTHON) || !defined(CRUCIBLE_HAVE_RUBY) || \
    !defined(CRUCIBLE_HAVE_PERL)
            n = run_embed_missing(interp, script_path, out, out_len);
            if (n > 0)
                return n;
#endif
        }
    }

    /*
     * 旧实现在这里返回 "hello from %s scriptffi path=..." ——解释器缺失或脚本不存在
     * 时引擎看起来像服务了页面（假成功）。现在：写诊断并返回 -1（失败可见）。
     */
    snprintf(out, out_len,
             "scriptffi: 无法执行（lang=%s interp=%s script=%s）：进程内解释器不可用或"
             "脚本缺失。本引擎不做 popen 回退，也不返回假响应。\n",
             lang ? lang : "script", interp,
             script_path && script_path[0] ? script_path : "(no script)");
    return -1;
}
