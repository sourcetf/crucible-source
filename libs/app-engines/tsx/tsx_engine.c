/*
 * TSX/TS app-engine — run index.tsx / index.ts via npx tsx or node when present.
 */
#include "appengine.h"
#include "appengine_common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int g_inited;

static int file_ok(const char *p)
{
    FILE *f = fopen(p, "rb");
    if (!f)
        return 0;
    fclose(f);
    return 1;
}

static int run_tsx(const char *script, const char *method, const char *path,
                   const char *query, char **out, size_t *out_len)
{
    char cmd[2048];
    FILE *fp;
    char buf[4096];
    size_t cap = 4096, n = 0;
    char *acc;

    setenv("REQUEST_METHOD", method ? method : "GET", 1);
    setenv("PATH_INFO", path ? path : "/", 1);
    setenv("QUERY_STRING", query ? query : "", 1);
    setenv("SCRIPT_FILENAME", script, 1);

    /* Prefer tsx, then npx tsx, then node (for plain .js/.mjs). */
    if (access("/usr/local/bin/tsx", X_OK) == 0)
        snprintf(cmd, sizeof(cmd), "tsx \"%s\" 2>/dev/null", script);
    else if (access("/usr/bin/tsx", X_OK) == 0)
        snprintf(cmd, sizeof(cmd), "tsx \"%s\" 2>/dev/null", script);
    else
        snprintf(cmd, sizeof(cmd),
                 "(command -v tsx >/dev/null && tsx \"%s\") || "
                 "(command -v npx >/dev/null && npx --yes tsx \"%s\") || "
                 "node \"%s\" 2>/dev/null",
                 script, script, script);

    fp = popen(cmd, "r");
    if (!fp)
        return -1;
    acc = (char *)malloc(cap);
    if (!acc) {
        pclose(fp);
        return -1;
    }
    while (fgets(buf, sizeof(buf), fp)) {
        size_t bl = strlen(buf);
        if (n + bl + 1 >= cap) {
            char *nb;
            cap *= 2;
            nb = (char *)realloc(acc, cap);
            if (!nb) {
                free(acc);
                pclose(fp);
                return -1;
            }
            acc = nb;
        }
        memcpy(acc + n, buf, bl);
        n += bl;
    }
    pclose(fp);
    acc[n] = '\0';
    if (n == 0) {
        free(acc);
        return -1;
    }
    *out = acc;
    *out_len = n;
    return 0;
}

int appengine_init(const char *engine, const char *lib_hint)
{
    (void)engine;
    (void)lib_hint;
    g_inited = 1;
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
    char sp[1024];
    char *result = NULL;
    size_t rlen = 0;
    const char *use = NULL;

    (void)content_type;
    (void)body;
    (void)body_len;
    (void)remote;
    (void)server_name;
    (void)server_port;
    (void)extra;

    if (!g_inited || !out)
        return -1;

    if (script && script[0] && file_ok(script))
        use = script;
    else {
        snprintf(sp, sizeof(sp), "%s/index.tsx", docroot ? docroot : ".");
        if (file_ok(sp))
            use = sp;
        else {
            snprintf(sp, sizeof(sp), "%s/index.ts", docroot ? docroot : ".");
            if (file_ok(sp))
                use = sp;
        }
    }

    if (use && run_tsx(use, method, path, query, &result, &rlen) == 0) {
        appengine_result_alloc(out);
        out->status = 200;
        appengine_result_set_headers(out, "Content-Type: text/plain; charset=utf-8\r\n"
                                          "X-Crucible-Engine: tsx\r\n");
        appengine_result_set_body(out, result, rlen);
        free(result);
        return 0;
    }
    return appengine_fill_hello(out, "tsx", path);
}

void appengine_shutdown(void) { g_inited = 0; }
