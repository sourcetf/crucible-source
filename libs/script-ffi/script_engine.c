/*
 * scriptffi app-engine — prefer in-process interpreters when headers available.
 *
 * Build with -DCRUCIBLE_HAVE_PYTHON / _RUBY / _PERL (see build_script_ffi.sh).
 * Popen is compiled ONLY in the per-language #else branch (headers missing).
 *
 * Built as libapp_python.so / libapp_ruby.so / libapp_perl.so with
 * -DCRUCIBLE_SCRIPT_LANG.
 */
#include "../app-engines/include/appengine.h"
#include "../app-engines/common/appengine_common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
/* no setenv on MSVC; keep Unix path primary for OpenBSD/Linux engines */
#else
#include <unistd.h>
#endif

static int g_ready;

static const char *default_lang(void)
{
#ifdef CRUCIBLE_SCRIPT_LANG
    return CRUCIBLE_SCRIPT_LANG;
#else
    return "python";
#endif
}

static const char *lang_name(const char *extra, const char *script)
{
    if (extra && extra[0]) {
        if (strcmp(extra, "python") == 0 || strcmp(extra, "py") == 0)
            return "python";
        if (strcmp(extra, "ruby") == 0 || strcmp(extra, "rb") == 0)
            return "ruby";
        if (strcmp(extra, "perl") == 0 || strcmp(extra, "pl") == 0)
            return "perl";
        return extra;
    }
    if (script) {
        const char *dot = strrchr(script, '.');
        if (dot) {
            if (strcmp(dot, ".py") == 0)
                return "python";
            if (strcmp(dot, ".rb") == 0)
                return "ruby";
            if (strcmp(dot, ".pl") == 0)
                return "perl";
        }
    }
    return default_lang();
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

/* ---------- in-process Python ---------- */
#if defined(CRUCIBLE_HAVE_PYTHON)
#include <Python.h>

static int run_python_inprocess(const char *script, const char *method, const char *path,
                                const char *query, const char *remote, char **out_body,
                                size_t *out_len)
{
    FILE *fp;
    PyObject *main_mod, *sys_mod, *stdout_obj, *io_mod, *buf, *getvalue, *result;
    int rc = -1;
    wchar_t *prog = NULL;

    if (!Py_IsInitialized()) {
        Py_Initialize();
    }

    /* Capture stdout via io.StringIO */
    io_mod = PyImport_ImportModule("io");
    if (!io_mod)
        return -1;
    buf = PyObject_CallMethod(io_mod, "StringIO", NULL);
    Py_DECREF(io_mod);
    if (!buf)
        return -1;

    sys_mod = PyImport_ImportModule("sys");
    if (!sys_mod) {
        Py_DECREF(buf);
        return -1;
    }
    stdout_obj = PyObject_GetAttrString(sys_mod, "stdout");
    PyObject_SetAttrString(sys_mod, "stdout", buf);

    {
        PyObject *os = PyImport_ImportModule("os");
        if (os) {
            PyObject *environ = PyObject_GetAttrString(os, "environ");
            if (environ) {
                PyObject *v;
                v = PyUnicode_FromString(method ? method : "GET");
                PyObject_SetItem(environ, PyUnicode_FromString("REQUEST_METHOD"), v);
                Py_XDECREF(v);
                v = PyUnicode_FromString(path ? path : "/");
                PyObject_SetItem(environ, PyUnicode_FromString("PATH_INFO"), v);
                Py_XDECREF(v);
                v = PyUnicode_FromString(query ? query : "");
                PyObject_SetItem(environ, PyUnicode_FromString("QUERY_STRING"), v);
                Py_XDECREF(v);
                v = PyUnicode_FromString(remote ? remote : "");
                PyObject_SetItem(environ, PyUnicode_FromString("REMOTE_ADDR"), v);
                Py_XDECREF(v);
                v = PyUnicode_FromString(script);
                PyObject_SetItem(environ, PyUnicode_FromString("SCRIPT_FILENAME"), v);
                Py_XDECREF(v);
                Py_DECREF(environ);
            }
            Py_DECREF(os);
        }
    }

    fp = fopen(script, "r");
    if (!fp) {
        if (stdout_obj)
            PyObject_SetAttrString(sys_mod, "stdout", stdout_obj);
        Py_XDECREF(stdout_obj);
        Py_DECREF(sys_mod);
        Py_DECREF(buf);
        return -1;
    }
    (void)prog;
    if (PyRun_SimpleFileEx(fp, script, 1) != 0) {
        /* fall through — still try to read any captured output */
    }

    getvalue = PyObject_GetAttrString(buf, "getvalue");
    result = getvalue ? PyObject_CallObject(getvalue, NULL) : NULL;
    Py_XDECREF(getvalue);
    if (result && PyUnicode_Check(result)) {
        const char *s = PyUnicode_AsUTF8(result);
        if (s) {
            size_t n = strlen(s);
            char *body = (char *)malloc(n + 1);
            if (body) {
                memcpy(body, s, n + 1);
                *out_body = body;
                *out_len = n;
                rc = 0;
            }
        }
    }
    Py_XDECREF(result);

    if (stdout_obj)
        PyObject_SetAttrString(sys_mod, "stdout", stdout_obj);
    Py_XDECREF(stdout_obj);
    Py_DECREF(sys_mod);
    Py_DECREF(buf);
    (void)main_mod;
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
 * POPEN FALLBACK — compiled only when at least one language lacks in-process
 * headers (used exclusively from that language's #else branch below).
 */
#if !defined(CRUCIBLE_HAVE_PYTHON) || !defined(CRUCIBLE_HAVE_RUBY) || \
    !defined(CRUCIBLE_HAVE_PERL)

static const char *interpreter_for(const char *lang)
{
    if (strcmp(lang, "ruby") == 0)
        return "ruby";
    if (strcmp(lang, "perl") == 0)
        return "perl";
    return "python3";
}

static int run_script_popen(const char *interp, const char *script, const char *method,
                            const char *path, const char *query, const char *remote,
                            char **out_body, size_t *out_len)
{
    /* Spec: Python/Ruby/Perl must not spawn. Fail closed when embed unavailable. */
    (void)interp;
    (void)script;
    (void)method;
    (void)path;
    (void)query;
    (void)remote;
    if (out_body)
        *out_body = NULL;
    if (out_len)
        *out_len = 0;
    fprintf(stderr,
            "scriptffi: in-process embed unavailable for this language; "
            "rebuild with CRUCIBLE_HAVE_* (popen fallback disabled)\n");
    return -1;
}

#endif /* popen available for languages without HAVE_* */

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
                "scriptffi: %s embed not built; rebuild with CRUCIBLE_HAVE_* "
                "(popen fallback disabled)\n",
                lang);
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
                "scriptffi: %s embed not built; rebuild with CRUCIBLE_HAVE_* "
                "(popen fallback disabled)\n",
                lang);
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
                "scriptffi: %s embed not built; rebuild with CRUCIBLE_HAVE_* "
                "(popen fallback disabled)\n",
                lang);
        return -1;
#endif
    }

#if !defined(CRUCIBLE_HAVE_PYTHON) || !defined(CRUCIBLE_HAVE_RUBY) || \
    !defined(CRUCIBLE_HAVE_PERL)
    *mode_out = "embed-missing";
    fprintf(stderr, "scriptffi: language embed missing; popen fallback disabled\n");
    return -1;
#else
    (void)script;
    (void)method;
    (void)path;
    (void)query;
    (void)remote;
    (void)out_body;
    (void)out_len;
    *mode_out = "unsupported";
    return -1;
#endif
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

    if (!g_ready || !out)
        return -1;

    lang = lang_name(extra, script);

    if (resolve_script(script, docroot, lang, resolved, sizeof(resolved)) != 0) {
        return appengine_fill_hello(out, lang, path);
    }

    if (run_lang(lang, resolved, method, path, query, remote, &result, &result_len, &mode) != 0) {
        return appengine_fill_hello(out, lang, path);
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
