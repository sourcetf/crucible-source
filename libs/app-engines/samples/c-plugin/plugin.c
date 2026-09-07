/*
 * Simple C app-engine plugin (hello world).
 * Built into libapp_c.so
 */
#include "appengine.h"
#include "appengine_common.h"

#include <stdio.h>
#include <string.h>

static int g_inited;

int appengine_init(const char *engine, const char *lib_hint)
{
    (void)lib_hint;
    g_inited = 1;
    fprintf(stderr, "c-plugin: init engine=%s\n", engine ? engine : "(null)");
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
    const char *hello;

    (void)script;
    (void)docroot;
    (void)method;
    (void)query;
    (void)content_type;
    (void)body;
    (void)body_len;
    (void)remote;
    (void)server_name;
    (void)server_port;

    if (!g_inited || out == NULL)
        return -1;
    /* P1-1：extra 携带的 .env 变量注入进程环境（legacy 引擎名输入为 no-op）。 */
    appengine_apply_extra(extra);
    hello = getenv("APP_HELLO");
    if (hello != NULL && hello[0] != '\0') {
        char buf[512];
        int n;

        n = snprintf(buf, sizeof(buf), "%s path=%s\n", hello, path ? path : "/");
        if (n < 0 || appengine_result_alloc(out) != 0)
            return -1;
        out->status = 200;
        if (appengine_result_set_headers(out, "Content-Type: text/plain; charset=utf-8\r\n") != 0)
            return -1;
        return appengine_result_set_body(out, buf, (size_t)n);
    }
    return appengine_fill_hello(out, "c", path);
}

void appengine_shutdown(void)
{
    g_inited = 0;
}
