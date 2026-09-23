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
 * 谁调用 Py_Initialize 谁负责 PyEval_SaveThread 释放 GIL，且任何 .so 都不调用
 * Py_FinalizeEx。否则同进程的 libapp_wsgi/asgi/uwsgi（另走 dlopen+dlsym 嵌入）
 * 的请求线程会在 PyGILState_Ensure 上永久等待。
 */
#include "../app-engines/include/appengine.h"
#include "../app-engines/common/appengine_common.h"

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

#ifndef _WIN32
#include <pthread.h>
static pthread_once_t g_py_once = PTHREAD_ONCE_INIT;
#define PY_BOOT_ONCE() pthread_once(&g_py_once, crucible_py_boot)
#else
#define PY_BOOT_ONCE() crucible_py_boot()
#endif

/* 解释器启动：一次。启动线程立刻 PyEval_SaveThread 释放 GIL（跨 .so 契约）。 */
static void crucible_py_boot(void)
{
    if (!Py_IsInitialized()) {
        Py_Initialize();
        (void)PyEval_SaveThread();
    }
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

static int run_python_inprocess(const char *script, const char *method, const char *path,
                                const char *query, const char *remote, char **out_body,
                                size_t *out_len)
{
    FILE *fp = NULL;
    PyObject *sys_mod = NULL, *stdout_obj = NULL, *io_mod = NULL, *buf = NULL;
    PyObject *getvalue = NULL, *result = NULL, *sys_path = NULL;
    PyGILState_STATE gil;
    int rc = -1;

    PY_BOOT_ONCE();
    gil = PyGILState_Ensure(); /* 每请求拿 GIL；与 wsgi/asgi/uwsgi 共用同一解释器 */

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

    /* 请求上下文 → os.environ（键值都不泄漏引用：用 PyDict_SetItemString） */
    {
        PyObject *os = PyImport_ImportModule("os");
        if (os != NULL) {
            PyObject *environ = PyObject_GetAttrString(os, "environ");
            if (environ != NULL) {
                struct {
                    const char *k;
                    const char *v;
                } kv[5];
                int i;

                kv[0].k = "REQUEST_METHOD";
                kv[0].v = method ? method : "GET";
                kv[1].k = "PATH_INFO";
                kv[1].v = path ? path : "/";
                kv[2].k = "QUERY_STRING";
                kv[2].v = query ? query : "";
                kv[3].k = "REMOTE_ADDR";
                kv[3].v = remote ? remote : "";
                kv[4].k = "SCRIPT_FILENAME";
                kv[4].v = script;
                for (i = 0; i < 5; i++) {
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
    /* sys.path 前置脚本目录：应用 import 同目录模块时必需。 */
    sys_path = PyObject_GetAttrString(sys_mod, "path");
    if (sys_path != NULL) {
        char dirbuf[1024];
        const char *dir = script_dirname(script, dirbuf, sizeof(dirbuf));
        if (dir != NULL) {
            PyObject *d = PyUnicode_FromString(dir);
            if (d != NULL) {
                (void)PyList_Insert(sys_path, 0, d);
                Py_DECREF(d);
            }
        }
        Py_DECREF(sys_path);
        sys_path = NULL;
    }
    PyErr_Clear();

    fp = fopen(script, "r");
    if (fp == NULL)
        goto done;
    (void)PyRun_SimpleFileEx(fp, script, 1); /* fp 由 CPython 关闭 */
    fp = NULL;

    getvalue = PyObject_GetAttrString(buf, "getvalue");
    result = getvalue != NULL ? PyObject_CallObject(getvalue, NULL) : NULL;
    if (result != NULL && PyUnicode_Check(result)) {
        const char *s = PyUnicode_AsUTF8(result);
        if (s != NULL) {
            size_t n = strlen(s);
            char *body = (char *)malloc(n + 1);
            if (body != NULL) {
                memcpy(body, s, n + 1);
                *out_body = body;
                *out_len = n;
                rc = 0;
            }
        }
    }

done:
    if (fp != NULL)
        fclose(fp);
    if (sys_mod != NULL && stdout_obj != NULL)
        (void)PyObject_SetAttrString(sys_mod, "stdout", stdout_obj);
    Py_XDECREF(sys_path);
    Py_XDECREF(result);
    Py_XDECREF(getvalue);
    Py_XDECREF(stdout_obj);
    Py_XDECREF(sys_mod);
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

static int run_ruby_inprocess(const char *script, const char *method, const char *path,
                              const char *query, const char *remote, char **out_body,
                              size_t *out_len)
{
    int state = 0;
    VALUE out;
    static int ruby_started;

    if (!ruby_started) {
        ruby_init();
        ruby_init_loadpath();
        ruby_started = 1;
    }
    ruby_script(script);
    /* ENV inject */
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
    }
    /* Capture $stdout with StringIO when available; else eval and stringify. */
    rb_eval_string_protect(
        "begin; require 'stringio'; $__crucible_out = StringIO.new; "
        "$stdout = $__crucible_out; rescue LoadError; $__crucible_out = nil; end",
        &state);
    rb_load_protect(rb_str_new_cstr(script), 0, &state);
    out = rb_eval_string_protect(
        "$__crucible_out ? $__crucible_out.string : ''", &state);
    if (state == 0 && TYPE(out) == T_STRING) {
        long n = RSTRING_LEN(out);
        char *body = (char *)malloc((size_t)n + 1);
        if (!body)
            return -1;
        memcpy(body, RSTRING_PTR(out), (size_t)n);
        body[n] = '\0';
        *out_body = body;
        *out_len = (size_t)n;
        return n > 0 ? 0 : -1;
    }
    return -1;
}
#endif /* CRUCIBLE_HAVE_RUBY */

/* ---------- in-process Perl ---------- */
#if defined(CRUCIBLE_HAVE_PERL)
#include <EXTERN.h>
#include <perl.h>

static PerlInterpreter *my_perl;

static int run_perl_inprocess(const char *script, const char *method, const char *path,
                              const char *query, const char *remote, char **out_body,
                              size_t *out_len)
{
    char *embedding[] = {"", (char *)script};
    int argc = 2;
    char **argv = embedding;
    char **env = NULL;
    SV *out_sv;
    STRLEN n;
    char *s;

    if (!my_perl) {
        PERL_SYS_INIT3(&argc, &argv, &env);
        my_perl = perl_alloc();
        perl_construct(my_perl);
    }
    {
        char *args[] = {"", (char *)script};
        perl_parse(my_perl, NULL, 2, args, NULL);
    }
    /* ENV */
    {
        HV *envhv = get_hv("ENV", GV_ADD);
        hv_store(envhv, "REQUEST_METHOD", 14,
                 newSVpv(method ? method : "GET", 0), 0);
        hv_store(envhv, "PATH_INFO", 9, newSVpv(path ? path : "/", 0), 0);
        hv_store(envhv, "QUERY_STRING", 12, newSVpv(query ? query : "", 0), 0);
        hv_store(envhv, "REMOTE_ADDR", 11, newSVpv(remote ? remote : "", 0), 0);
        hv_store(envhv, "SCRIPT_FILENAME", 15, newSVpv(script, 0), 0);
    }
    perl_run(my_perl);
    /* Best-effort: scripts that print go to real stdout; capture via tie is heavy.
     * Read script and eval into scalar when file is small CGI-style. */
    out_sv = eval_pv("do { local $/; open my $fh, '<', $ENV{SCRIPT_FILENAME} or die $!; "
                     "my $c = <$fh>; close $fh; "
                     "open my $o, '>', \\(my $buf = ''); "
                     "my $old = select $o; eval $c; select $old; $buf }",
                     0);
    if (!out_sv || !SvOK(out_sv))
        return -1;
    s = SvPV(out_sv, n);
    if (!s || n == 0)
        return -1;
    {
        char *body = (char *)malloc(n + 1);
        if (!body)
            return -1;
        memcpy(body, s, n);
        body[n] = '\0';
        *out_body = body;
        *out_len = n;
    }
    return 0;
}
#endif /* CRUCIBLE_HAVE_PERL */

/*
 * 执行分派。任何"嵌入不可用 / 语言未知"都返回 -1 + 调用方写错误文本，
 * 不再有 popen 回退，也不再返回假 hello。
 */
static int run_lang(const char *lang, const char *script, const char *method, const char *path,
                    const char *query, const char *remote, char **out_body, size_t *out_len,
                    const char **mode_out)
{
    if (strcmp(lang, "python") == 0) {
#if defined(CRUCIBLE_HAVE_PYTHON)
        *mode_out = "inprocess-python";
        return run_python_inprocess(script, method, path, query, remote, out_body, out_len);
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
        return run_ruby_inprocess(script, method, path, query, remote, out_body, out_len);
#else
        *mode_out = "embed-missing";
        fprintf(stderr,
                "scriptffi: ruby embed not built; rebuild with -DCRUCIBLE_HAVE_RUBY "
                "(popen fallback removed)\n");
        return -1;
#endif
    }
    if (strcmp(lang, "perl") == 0) {
#if defined(CRUCIBLE_HAVE_PERL)
        *mode_out = "inprocess-perl";
        return run_perl_inprocess(script, method, path, query, remote, out_body, out_len);
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
    (void)lib_hint;
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
    AppEngineResult *out)
{
    const char *lang;
    char *result = NULL;
    size_t result_len = 0;
    char resolved[1024];
    char hdr[320];
    const char *mode = "none";

    (void)content_type;
    (void)body;
    (void)body_len;
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

    if (run_lang(lang, resolved, method, path, query, remote, &result, &result_len,
                 &mode) != 0) {
        free(result);
        return script_fail(out,
                           "%s: 进程内解释器不可用（mode=%s，script=%s）。"
                           "本引擎不做 popen 回退，也不返回假响应；"
                           "请用 CRUCIBLE_HAVE_%s 重建 libapp_%s.so",
                           lang, mode, resolved, strcmp(lang, "ruby") == 0 ? "RUBY"
                                                     : (strcmp(lang, "perl") == 0 ? "PERL"
                                                                                 : "PYTHON"),
                           lang);
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
