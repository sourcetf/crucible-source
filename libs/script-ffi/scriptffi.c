/* scriptffi — prefer in-process interpreters when CRUCIBLE_HAVE_* is set.
 * Production path: dlopen libscriptffi.so from script_ffi.rs.
 *
 * Popen is compiled only as the per-language #else fallback when in-process
 * headers were missing at build time (see build_script_ffi.sh).
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

static int run_python(const char *script_path, const char *method, const char *path,
                      const char *query, char *out, size_t out_len)
{
    FILE *fp;
    PyObject *sys_mod, *stdout_obj, *io_mod, *buf, *getvalue, *result;
    int n = -1;

    if (!Py_IsInitialized())
        Py_Initialize();
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
                PyObject_SetItem(environ, PyUnicode_FromString("REQUEST_METHOD"),
                                 PyUnicode_FromString(method ? method : "GET"));
                PyObject_SetItem(environ, PyUnicode_FromString("PATH_INFO"),
                                 PyUnicode_FromString(path ? path : "/"));
                PyObject_SetItem(environ, PyUnicode_FromString("QUERY_STRING"),
                                 PyUnicode_FromString(query ? query : ""));
                PyObject_SetItem(environ, PyUnicode_FromString("SCRIPT_FILENAME"),
                                 PyUnicode_FromString(script_path));
                Py_DECREF(environ);
            }
            Py_DECREF(os);
        }
    }
    fp = fopen(script_path, "r");
    if (!fp) {
        if (stdout_obj)
            PyObject_SetAttrString(sys_mod, "stdout", stdout_obj);
        Py_XDECREF(stdout_obj);
        Py_DECREF(sys_mod);
        Py_DECREF(buf);
        return -1;
    }
    (void)PyRun_SimpleFileEx(fp, script_path, 1);
    getvalue = PyObject_GetAttrString(buf, "getvalue");
    result = getvalue ? PyObject_CallObject(getvalue, NULL) : NULL;
    Py_XDECREF(getvalue);
    if (result && PyUnicode_Check(result)) {
        const char *s = PyUnicode_AsUTF8(result);
        if (s) {
            snprintf(out, out_len, "%s", s);
            n = (int)strlen(out);
        }
    }
    Py_XDECREF(result);
    if (stdout_obj)
        PyObject_SetAttrString(sys_mod, "stdout", stdout_obj);
    Py_XDECREF(stdout_obj);
    Py_DECREF(sys_mod);
    Py_DECREF(buf);
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
 * Spec: Python/Ruby/Perl must not spawn via popen. Fail closed when embed
 * headers were missing at build time (rebuild with CRUCIBLE_HAVE_*).
 */
#if !defined(CRUCIBLE_HAVE_PYTHON) || !defined(CRUCIBLE_HAVE_RUBY) || \
    !defined(CRUCIBLE_HAVE_PERL)

static int run_popen_lang(const char *interp, const char *script_path, const char *method,
                          const char *path, const char *query, char *out, size_t out_len)
{
    (void)interp;
    (void)script_path;
    (void)method;
    (void)path;
    (void)query;
    if (out && out_len)
        out[0] = '\0';
    fprintf(stderr,
            "scriptffi: in-process embed unavailable; rebuild with CRUCIBLE_HAVE_* "
            "(popen fallback disabled)\n");
    return -1;
}
#endif /* popen disabled */


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

    interp = interp_for(lang);
    if (script_path && script_path[0]) {
        if (strcmp(interp, "python3") == 0) {
#if defined(CRUCIBLE_HAVE_PYTHON)
            n = run_python(script_path, method, path, query, out, out_len);
            if (n > 0)
                return n;
#else
            n = run_popen_lang(interp, script_path, method, path, query, out, out_len);
            if (n > 0)
                return n;
#endif
        } else if (strcmp(interp, "ruby") == 0) {
#if defined(CRUCIBLE_HAVE_RUBY)
            n = run_ruby(script_path, out, out_len);
            if (n > 0)
                return n;
#else
            n = run_popen_lang(interp, script_path, method, path, query, out, out_len);
            if (n > 0)
                return n;
#endif
        } else if (strcmp(interp, "perl") == 0) {
#if defined(CRUCIBLE_HAVE_PERL)
            n = run_perl(script_path, out, out_len);
            if (n > 0)
                return n;
#else
            n = run_popen_lang(interp, script_path, method, path, query, out, out_len);
            if (n > 0)
                return n;
#endif
        } else {
#if !defined(CRUCIBLE_HAVE_PYTHON) || !defined(CRUCIBLE_HAVE_RUBY) || \
    !defined(CRUCIBLE_HAVE_PERL)
            n = run_popen_lang(interp, script_path, method, path, query, out, out_len);
            if (n > 0)
                return n;
#endif
        }
    }

    snprintf(out, out_len,
             "hello from %s scriptffi path=%s method=%s query=%s script=%s interp=%s\n",
             lang ? lang : "script", path ? path : "/", method ? method : "GET",
             query ? query : "", script_path ? script_path : "", interp);
    return (int)strlen(out);
}
