/*
 * CGI app-engine — execute script as CGI with REQUEST_* env, parse CGI headers.
 */
#include "appengine.h"
#include "appengine_common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

static int g_inited;

static int file_ok(const char *p)
{
    struct stat st;
    if (!p || stat(p, &st) != 0)
        return 0;
    return S_ISREG(st.st_mode);
}

static int run_cgi(const char *script, const char *method, const char *path,
                   const char *query, const char *remote, const char *server_name,
                   int server_port, char **out, size_t *out_len)
{
    char cmd[2048];
    FILE *fp;
    char buf[4096];
    size_t cap = 4096, n = 0;
    char *acc;
    char portbuf[16];

    setenv("GATEWAY_INTERFACE", "CGI/1.1", 1);
    setenv("REQUEST_METHOD", method ? method : "GET", 1);
    setenv("PATH_INFO", path ? path : "/", 1);
    setenv("QUERY_STRING", query ? query : "", 1);
    setenv("SCRIPT_FILENAME", script, 1);
    setenv("SCRIPT_NAME", script, 1);
    setenv("REMOTE_ADDR", remote ? remote : "", 1);
    setenv("SERVER_NAME", server_name ? server_name : "crucible", 1);
    setenv("SERVER_PROTOCOL", "HTTP/1.1", 1);
    snprintf(portbuf, sizeof(portbuf), "%d", server_port > 0 ? server_port : 80);
    setenv("SERVER_PORT", portbuf, 1);

    /* Prefer direct exec; fall back to /bin/sh for non-executable scripts. */
    if (access(script, X_OK) == 0)
        snprintf(cmd, sizeof(cmd), "\"%s\" 2>/dev/null", script);
    else
        snprintf(cmd, sizeof(cmd), "/bin/sh \"%s\" 2>/dev/null", script);

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

static void apply_cgi_output(AppEngineResult *out, char *raw, size_t raw_len)
{
    char *sep = strstr(raw, "\r\n\r\n");
    char *body;
    size_t blen;
    int status = 200;
    char hdrbuf[2048];
    size_t o = 0;

    if (sep) {
        *sep = '\0';
        body = sep + 4;
        blen = raw_len - (size_t)(body - raw);
    } else if ((sep = strstr(raw, "\n\n")) != NULL) {
        *sep = '\0';
        body = sep + 2;
        blen = raw_len - (size_t)(body - raw);
    } else {
        appengine_result_alloc(out);
        out->status = 200;
        appengine_result_set_headers(out, "Content-Type: text/plain; charset=utf-8\r\n"
                                          "X-Crucible-Engine: cgi\r\n");
        appengine_result_set_body(out, raw, raw_len);
        return;
    }

    {
        char *line = raw;
        hdrbuf[0] = '\0';
        while (line && *line) {
            char *nl = strchr(line, '\n');
            size_t llen;
            if (nl)
                *nl = '\0';
            if (line[0] && line[strlen(line) - 1] == '\r')
                line[strlen(line) - 1] = '\0';
            llen = strlen(line);
            if (llen >= 7 && strncasecmp(line, "Status:", 7) == 0) {
                status = atoi(line + 7);
                if (status <= 0)
                    status = 200;
            } else if (llen > 0 && o + llen + 3 < sizeof(hdrbuf)) {
                memcpy(hdrbuf + o, line, llen);
                o += llen;
                hdrbuf[o++] = '\r';
                hdrbuf[o++] = '\n';
                hdrbuf[o] = '\0';
            }
            if (!nl)
                break;
            line = nl + 1;
        }
    }

    appengine_result_alloc(out);
    out->status = status;
    if (o == 0)
        appengine_result_set_headers(out, "Content-Type: text/plain; charset=utf-8\r\n"
                                          "X-Crucible-Engine: cgi\r\n");
    else
        appengine_result_set_headers(out, hdrbuf);
    appengine_result_set_body(out, body, blen);
}

int appengine_init(const char *engine, const char *lib_hint)
{
    (void)lib_hint;
    g_inited = 1;
    (void)engine;
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
    (void)extra;

    if (!g_inited || out == NULL)
        return -1;

    if (script && script[0] && file_ok(script))
        use = script;
    else {
        snprintf(sp, sizeof(sp), "%s/index.cgi", docroot ? docroot : ".");
        if (file_ok(sp))
            use = sp;
        else {
            snprintf(sp, sizeof(sp), "%s/cgi-bin/index.cgi", docroot ? docroot : ".");
            if (file_ok(sp))
                use = sp;
        }
    }

    if (use && run_cgi(use, method, path, query, remote, server_name, server_port,
                       &result, &rlen) == 0) {
        apply_cgi_output(out, result, rlen);
        free(result);
        return 0;
    }
    return appengine_fill_hello(out, "cgi", path);
}

void appengine_shutdown(void)
{
    g_inited = 0;
}
