/*
 * ASGI app-engine —— 进程内嵌入 CPython（静态嵌入，无每请求 spawn）。
 *
 * 旧实现：写 runner 到 /tmp 后 popen("python3 runner")（每请求 spawn 解释器，
 * spec 明令禁止），且失败即落 appengine_fill_hello（假成功）。宿主还根本没有 tsx/
 * 第三方依赖可依赖，所以实际永远是 hello 页面。
 *
 * 现在：走 common/crucible_pyembed.h 的进程内 CPython；ASGI 需要事件循环，驱动
 * 逻辑作为 Python 源码在**同进程**内 exec（不是 spawn），结果经 __cr_result 读回。
 * 应用抛异常 → 500 + traceback；缺 libpython / 脚本缺失 → 显式错误。
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
static int asgi_fail(AppEngineResult *out, const char *fmt, ...)
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

/* 脚本解析：显式 script → docroot/index.py → docroot/app.py → docroot/asgi.py。 */
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
        snprintf(out, outsz, "%s/asgi.py", docroot);
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
    if (crucible_py_embed_ensure(err, sizeof(err)) == 0)
        fprintf(stderr, "libapp_asgi: 进程内 CPython 就绪 (%s)\n", crucible_py_embed_version());
    else
        fprintf(stderr, "libapp_asgi: 嵌入式 CPython 不可用: %s\n", err);
#else
    fprintf(stderr,
            "libapp_asgi: 构建时关闭了 Python 嵌入（-DCRUCIBLE_EMBED_PYTHON_OFF）\n");
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
    int env_dirty = extra != NULL && strchr(extra, '{') != NULL;

    if (!g_inited || out == NULL)
        return -1;

#ifdef CRUCIBLE_HAVE_PYTHON
    use = resolve_script(script, docroot, pathbuf, sizeof(pathbuf));
    if (use == NULL)
        return asgi_fail(out,
                         "asgi: 未找到 ASGI 脚本（script=%s docroot=%s，"
                         "尝试过 index.py / app.py / asgi.py）",
                         script != NULL ? script : "(null)",
                         docroot != NULL ? docroot : "(null)");
    return crucible_py_asgi_request("asgi", use, docroot, method, path, query,
                                    content_type, body, body_len, remote, server_name,
                                    server_port, env_dirty, out);
#else
    (void)script;
    (void)docroot;
    (void)pathbuf;
    (void)env_dirty;
    return asgi_fail(out,
                     "asgi: 本引擎构建时未嵌入 CPython（-DCRUCIBLE_EMBED_PYTHON_OFF）。"
                     "asgi 禁止每请求 spawn 解释器，故不提供 popen 回退");
#endif
}

void appengine_shutdown(void)
{
    g_inited = 0;
#ifdef CRUCIBLE_HAVE_PYTHON
    crucible_py_embed_shutdown();
#endif
}
