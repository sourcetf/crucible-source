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
#include <unistd.h>
#endif

static int g_ready;

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

#ifndef _WIN32
#include <pthread.h>
static pthread_once_t g_py_once = PTHREAD_ONCE_INIT;
#define PY_BOOT_ONCE() pthread_once(&g_py_once, crucible_scriptffi_py_boot)
#else
#define PY_BOOT_ONCE() crucible_scriptffi_py_boot()
#endif

/* 解释器启动一次；启动线程立刻释放 GIL（否则同进程另一 .so 的线程会死等 GIL）。 */
static void crucible_scriptffi_py_boot(void)
{
    if (!Py_IsInitialized()) {
        Py_Initialize();
        (void)PyEval_SaveThread();
    }
}

static int run_python(const char *script_path, const char *method, const char *path,
                      const char *query, char *out, size_t out_len)
{
    FILE *fp = NULL;
    PyObject *sys_mod = NULL, *stdout_obj = NULL, *io_mod = NULL, *buf = NULL;
    PyObject *getvalue = NULL, *result = NULL;
    PyGILState_STATE gil;
    int n = -1;

    PY_BOOT_ONCE();
    gil = PyGILState_Ensure();

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
                    PyObject *v = PyUnicode_FromString(kv[i].v);
                    if (v == NULL)
                        continue;
                    (void)PyDict_SetItemString(environ, kv[i].k, v);
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
    (void)PyRun_SimpleFileEx(fp, script_path, 1); /* fp 由 CPython 关闭 */
    fp = NULL;

    getvalue = PyObject_GetAttrString(buf, "getvalue");
    result = getvalue != NULL ? PyObject_CallObject(getvalue, NULL) : NULL;
    if (result != NULL && PyUnicode_Check(result)) {
        const char *s = PyUnicode_AsUTF8(result);
        if (s != NULL) {
            snprintf(out, out_len, "%s", s);
            n = (int)strlen(out);
        }
    }

done:
    if (fp != NULL)
        fclose(fp);
    if (sys_mod != NULL && stdout_obj != NULL)
        (void)PyObject_SetAttrString(sys_mod, "stdout", stdout_obj);
    Py_XDECREF(result);
    Py_XDECREF(getvalue);
    Py_XDECREF(stdout_obj);
    Py_XDECREF(sys_mod);
    Py_XDECREF(buf);
    Py_XDECREF(io_mod);
    PyErr_Clear();
    PyGILState_Release(gil);
    return n;
}
#endif

#if defined(CRUCIBLE_HAVE_RUBY)
#include <ruby.h>
static int run_ruby(const char *script_path, char *out, size_t out_len)
{
    int state = 0;
    VALUE v;
    static int started;
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
        snprintf(out, out_len, "%.*s", (int)RSTRING_LEN(v), RSTRING_PTR(v));
        return (int)strlen(out);
    }
    return -1;
}
#endif

#if defined(CRUCIBLE_HAVE_PERL)
#include <EXTERN.h>
#include <perl.h>
static PerlInterpreter *g_perl;
static int run_perl(const char *script_path, char *out, size_t out_len)
{
    SV *sv;
    STRLEN n;
    char *s;
    char *args[] = {"", (char *)script_path};
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
    if (!sv || !SvOK(sv))
        return -1;
    s = SvPV(sv, n);
    if (!s)
        return -1;
    if (n >= out_len)
        n = out_len - 1;
    memcpy(out, s, n);
    out[n] = '\0';
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
