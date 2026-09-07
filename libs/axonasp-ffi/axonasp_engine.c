/*
 * AxonASP-compatible Classic ASP engine —
 * Response.Write / <%= %> / Request.QueryString / Request.ServerVariables / HTML.
 */
#include "../app-engines/include/appengine.h"
#include "../app-engines/common/appengine_common.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define strcasecmp _stricmp
#else
#include <strings.h>
#endif

static int g_ready;

static int read_file(const char *path, char **out, size_t *out_len)
{
    FILE *f;
    long sz;
    char *buf;

    f = fopen(path, "rb");
    if (!f)
        return -1;
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return -1;
    }
    sz = ftell(f);
    if (sz < 0) {
        fclose(f);
        return -1;
    }
    rewind(f);
    buf = (char *)malloc((size_t)sz + 1);
    if (!buf) {
        fclose(f);
        return -1;
    }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf);
        fclose(f);
        return -1;
    }
    buf[sz] = '\0';
    fclose(f);
    *out = buf;
    *out_len = (size_t)sz;
    return 0;
}

static int ensure(char **out, size_t *cap, size_t need)
{
    if (need < *cap)
        return 0;
    size_t nc = *cap ? *cap * 2 : 1024;
    while (nc <= need)
        nc *= 2;
    char *nb = (char *)realloc(*out, nc);
    if (!nb)
        return -1;
    *out = nb;
    *cap = nc;
    return 0;
}

static void append(char **out, size_t *o, size_t *cap, const char *s, size_t n)
{
    if (ensure(out, cap, *o + n + 1) != 0)
        return;
    memcpy(*out + *o, s, n);
    *o += n;
    (*out)[*o] = '\0';
}

static int extract_quoted(const char *p, char *dst, size_t dst_len)
{
    const char *q1 = strchr(p, '"');
    const char *q2;
    if (!q1)
        q1 = strchr(p, '\'');
    if (!q1)
        return -1;
    char quote = *q1;
    q2 = strchr(q1 + 1, quote);
    if (!q2)
        return -1;
    size_t n = (size_t)(q2 - q1 - 1);
    if (n + 1 > dst_len)
        n = dst_len - 1;
    memcpy(dst, q1 + 1, n);
    dst[n] = '\0';
    return 0;
}

/* Decode one QueryString value for key (case-insensitive). */
static int query_get(const char *query, const char *key, char *dst, size_t dst_len)
{
    size_t klen;
    const char *p;
    if (!query || !key || !dst || dst_len == 0)
        return -1;
    dst[0] = '\0';
    klen = strlen(key);
    p = query;
    while (*p) {
        const char *eq = strchr(p, '=');
        const char *amp = strchr(p, '&');
        size_t namelen;
        if (!amp)
            amp = p + strlen(p);
        if (eq && eq < amp)
            namelen = (size_t)(eq - p);
        else
            namelen = (size_t)(amp - p);
        if (namelen == klen) {
            size_t i;
            int match = 1;
            for (i = 0; i < klen; i++) {
                if (tolower((unsigned char)p[i]) != tolower((unsigned char)key[i])) {
                    match = 0;
                    break;
                }
            }
            if (match) {
                if (eq && eq < amp) {
                    size_t vlen = (size_t)(amp - eq - 1);
                    if (vlen + 1 > dst_len)
                        vlen = dst_len - 1;
                    memcpy(dst, eq + 1, vlen);
                    dst[vlen] = '\0';
                }
                return 0;
            }
        }
        if (!*amp)
            break;
        p = amp + 1;
    }
    return -1;
}

static void eval_expression(const char *expr, size_t elen, const char *req_path,
                            const char *query, char **out, size_t *o, size_t *cap)
{
    char buf[2048];
    char key[256];
    char tmp[1024];

    if (elen >= sizeof(buf))
        elen = sizeof(buf) - 1;
    memcpy(buf, expr, elen);
    buf[elen] = '\0';

    /* Strip leading/trailing space */
    {
        char *s = buf;
        char *e;
        while (*s && isspace((unsigned char)*s))
            s++;
        e = s + strlen(s);
        while (e > s && isspace((unsigned char)e[-1]))
            *--e = '\0';
        if (s != buf)
            memmove(buf, s, strlen(s) + 1);
    }

    /* Literal string */
    if (buf[0] == '"' || buf[0] == '\'') {
        if (extract_quoted(buf, tmp, sizeof(tmp)) == 0)
            append(out, o, cap, tmp, strlen(tmp));
        return;
    }

    /* Request.QueryString("key") or Request.QueryString("key").Item */
    if (strstr(buf, "Request.QueryString") || strstr(buf, "Request.querystring")) {
        if (extract_quoted(buf, key, sizeof(key)) == 0) {
            if (query_get(query, key, tmp, sizeof(tmp)) == 0)
                append(out, o, cap, tmp, strlen(tmp));
        } else if (query && query[0]) {
            /* bare Request.QueryString → raw query */
            append(out, o, cap, query, strlen(query));
        }
        return;
    }

    /* Request.ServerVariables("PATH_INFO") etc. */
    if (strstr(buf, "Request.ServerVariables") || strstr(buf, "ServerVariables")) {
        if (extract_quoted(buf, key, sizeof(key)) == 0) {
            if (strcasecmp(key, "PATH_INFO") == 0 && req_path)
                append(out, o, cap, req_path, strlen(req_path));
            else if (strcasecmp(key, "QUERY_STRING") == 0 && query)
                append(out, o, cap, query, strlen(query));
            else if (strcasecmp(key, "SCRIPT_NAME") == 0 && req_path)
                append(out, o, cap, req_path, strlen(req_path));
        } else if (strstr(buf, "PATH_INFO") && req_path) {
            append(out, o, cap, req_path, strlen(req_path));
        }
        return;
    }

    if (strstr(buf, "PATH_INFO") && req_path) {
        append(out, o, cap, req_path, strlen(req_path));
        return;
    }
}

static char *render_asp(const char *src, size_t len, const char *path,
                        const char *req_path, const char *query)
{
    char *out = NULL;
    size_t cap = 0;
    size_t o = 0;
    size_t i = 0;

    while (i < len) {
        if (i + 1 < len && src[i] == '<' && src[i + 1] == '%') {
            const char *end = strstr(src + i + 2, "%>");
            size_t block_start;
            size_t block_end;
            if (!end)
                break;
            block_start = i + 2;
            block_end = (size_t)(end - src);
            i = block_end + 2;

            while (block_start < block_end && isspace((unsigned char)src[block_start]))
                block_start++;

            /* <%= expr %> */
            if (block_start < block_end && src[block_start] == '=') {
                eval_expression(src + block_start + 1, block_end - (block_start + 1),
                                req_path, query, &out, &o, &cap);
                continue;
            }

            /* Response.Write "..." / Response.Write("...") */
            if (strncmp(src + block_start, "Response.Write", 14) == 0 ||
                strncmp(src + block_start, "Response.write", 14) == 0) {
                char lit[2048];
                if (extract_quoted(src + block_start, lit, sizeof(lit)) == 0) {
                    append(&out, &o, &cap, lit, strlen(lit));
                } else {
                    /* Response.Write Request.QueryString("x") */
                    eval_expression(src + block_start + 14, block_end - (block_start + 14),
                                    req_path, query, &out, &o, &cap);
                }
                continue;
            }

            /* Response.WriteLine — treat like Write + newline */
            if (strncmp(src + block_start, "Response.WriteLine", 18) == 0 ||
                strncmp(src + block_start, "Response.writeln", 16) == 0) {
                char lit[2048];
                if (extract_quoted(src + block_start, lit, sizeof(lit)) == 0) {
                    append(&out, &o, &cap, lit, strlen(lit));
                    append(&out, &o, &cap, "\n", 1);
                }
                continue;
            }

            /* Inline Request.QueryString assignment-style echo in <% %> */
            if (strstr(src + block_start, "Request.QueryString") ||
                strstr(src + block_start, "Request.ServerVariables")) {
                eval_expression(src + block_start, block_end - block_start, req_path,
                                query, &out, &o, &cap);
                continue;
            }

            /* Response.ContentType / other statements — ignore for body */
            continue;
        }
        append(&out, &o, &cap, src + i, 1);
        i++;
    }
    {
        char foot[256];
        int n = snprintf(foot, sizeof(foot), "\n<!-- axonasp path=%s -->\n",
                         path ? path : "");
        if (n > 0)
            append(&out, &o, &cap, foot, (size_t)n);
    }
    return out;
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
    char *src = NULL;
    size_t src_len = 0;
    char *rendered = NULL;
    char script_path[1024];

    (void)method;
    (void)content_type;
    (void)body;
    (void)body_len;
    (void)remote;
    (void)server_name;
    (void)server_port;
    (void)extra;

    if (!g_ready || !out)
        return -1;

    if (script && script[0]) {
        if (read_file(script, &src, &src_len) != 0)
            return appengine_fill_hello(out, "asp", path);
    } else {
        snprintf(script_path, sizeof(script_path), "%s/index.asp",
                 docroot ? docroot : ".");
        if (read_file(script_path, &src, &src_len) != 0)
            return appengine_fill_hello(out, "asp", path);
    }

    rendered = render_asp(src, src_len, path, path, query ? query : "");
    free(src);
    if (!rendered)
        return -1;

    appengine_result_alloc(out);
    out->status = 200;
    appengine_result_set_headers(out, "Content-Type: text/html; charset=utf-8\r\n"
                                      "X-Crucible-Engine: asp\r\n");
    appengine_result_set_body(out, rendered, strlen(rendered));
    free(rendered);
    return 0;
}

void appengine_shutdown(void) { g_ready = 0; }
