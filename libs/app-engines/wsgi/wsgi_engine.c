/*
 * WSGI app-engine —— 进程内嵌入 CPython（静态嵌入，无每请求 spawn）。
 *
 * 旧实现：把一个 runner 脚本写到 /tmp 再 popen("python3 runner")，且 popen 前加了
 * 无条件 return -1，于是永远落到 appengine_fill_hello——既违反 spec（解释器必须
 * 进程内嵌入、禁止 spawn），又是"假成功"（坏引擎看起来像服务了页面）。
 *
 * 现在：CPython 通过 common/crucible_pyembed.h 在进程内嵌入（Py_Initialize 一次；
 * 该头文件解释了为什么用 dlopen+dlsym 绑定 CPython C API 而不是链接期符号）。
 * 每请求：构造 WSGI environ → 调用缓存的 application → 迭代返回值 → 填
 * AppEngineResult（状态行 / 响应头 / body）；应用抛异常 → 500 + traceback。
 * 宿主没有 libpython 或脚本缺失 → 显式错误（rc != 0 + error），绝不返回假 hello。
 *
 * 构建期开关：CRUCIBLE_EMBED_PYTHON_OFF 可关闭嵌入（此时全部请求显式失败）。
 */
#include "appengine.h"
#include "appengine_common.h"
#include "crucible_embed.h"
#include "crucible_pyembed.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static int g_inited;

/* 引擎级失败：填 out->error 并返回 -1（app_ffi 会把它变成 502 文本）。
 * 刻意放在 CRUCIBLE_HAVE_PYTHON 之外：关闭嵌入时同样需要显式失败。 */
static int wsgi_fail(AppEngineResult *out, const char *fmt, ...)
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

static int is_regular_file(const char *p)
{
    struct stat st;

    return p != NULL && p[0] != '\0' && stat(p, &st) == 0 && S_ISREG(st.st_mode);
}

/* 脚本解析：显式 script → docroot/index.py → docroot/app.py。 */
static const char *resolve_script(const char *script, const char *docroot, char *out,
                                  size_t outsz)
{
    if (is_regular_file(script)) {
        snprintf(out, outsz, "%s", script);
        return out;
    }
    if (docroot != NULL && docroot[0] != '\0') {
        snprintf(out, outsz, "%s/index.py", docroot);
        if (is_regular_file(out))
            return out;
        snprintf(out, outsz, "%s/app.py", docroot);
        if (is_regular_file(out))
            return out;
    }
    return NULL;
}

int appengine_init(const char *engine, const char *lib_hint)
{
#ifdef CRUCIBLE_HAVE_PYTHON
    char err[256];
#endif

    (void)engine;
    (void)lib_hint;
    g_inited = 1;
#ifdef CRUCIBLE_HAVE_PYTHON
    if (crucible_py_embed_ensure(err, sizeof(err)) == 0) {
        fprintf(stderr, "libapp_wsgi: 进程内 CPython 就绪 (%s)\n", crucible_py_embed_version());
    } else {
        /* 不阻止 .so 加载：每次请求给带原因的显式错误比只报 "init failed" 更有用。 */
        fprintf(stderr, "libapp_wsgi: 嵌入式 CPython 不可用: %s\n", err);
    }
#else
    fprintf(stderr,
            "libapp_wsgi: 构建时关闭了 Python 嵌入（-DCRUCIBLE_EMBED_PYTHON_OFF）\n");
#endif
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
    char pathbuf[1024];
    const char *use;

    /* P1-1：extra 为 JSON 表示本次请求带了 .env 变量（已由 Rust 侧 setenv），
     * 需要同步给 Python 的 os.environ；纯引擎名（legacy）时为 no-op。 */
    int env_dirty = extra != NULL && strchr(extra, '{') != NULL;

    if (!g_inited || out == NULL)
        return -1;

#ifdef CRUCIBLE_HAVE_PYTHON
    use = resolve_script(script, docroot, pathbuf, sizeof(pathbuf));
    if (use == NULL)
        return wsgi_fail(out,
                         "wsgi: 未找到 WSGI 脚本（script=%s docroot=%s，"
                         "尝试过 index.py / app.py）",
                         script != NULL ? script : "(null)",
                         docroot != NULL ? docroot : "(null)");
    return crucible_py_wsgi_request("wsgi", use, docroot, method, path, query,
                                    content_type, body, body_len, remote, server_name,
                                    server_port, env_dirty, out);
#else
    (void)script;
    (void)docroot;
    (void)pathbuf;
    (void)env_dirty;
    return wsgi_fail(out,
                     "wsgi: 本引擎构建时未嵌入 CPython（-DCRUCIBLE_EMBED_PYTHON_OFF）。"
                     "wsgi 禁止每请求 spawn 解释器，故不提供 popen 回退");
#endif
}

void appengine_shutdown(void)
{
    g_inited = 0;
#ifdef CRUCIBLE_HAVE_PYTHON
    crucible_py_embed_shutdown();
#endif
}
