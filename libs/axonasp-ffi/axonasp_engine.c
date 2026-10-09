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
#include <sys/stat.h>

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
    struct stat st;

    /* 常规文件检查必须在 fopen 之前：FIFO/字符设备上 fopen 会**阻塞**（FIFO 没有写端
     * 时 open 一直等），而 FFI 引擎调用没有墙钟超时 —— 一个 docroot 里的 FIFO 会把
     * 线程池线程永久钉住。cgi 引擎早就有 is_regular_file 这道闸，这里补齐。 */
    if (path == NULL || stat(path, &st) != 0 || !S_ISREG(st.st_mode))
        return -1;
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

/* 请求上下文：ServerVariables 的取值来源（ABI 形参 + headers 块 + 进程环境）。
 *
 * 为什么需要它：ABI 的 `headers` 块（与 h2/h3 的 `:authority` 合成）与 `extra` 此前在
 * 本引擎里被整体忽略 ⇒ `Request.ServerVariables("HTTP_HOST")` 恒为空、`.env` 变量
 * 也读不到。经典 ASP 应用大量依赖 ServerVariables 做主机判定/协议判定/读取部署参数，
 * 恒空会让脚本走进错误分支（真机实测：`/asp-b/` 带 .env，`wm=`/`host=` 都是空）。 */
struct asp_ctx {
    const char *method;
    const char *req_path;
    const char *query;
    const char *remote;
    const char *server_name;
    int server_port;
    const char *headers; /* ABI 请求头块（"Name: Value\r\n"），可 NULL */
};

/* Classic ASP 的 ServerVariables 取值顺序：先本引擎已知的 CGI 变量，再请求头
 * （HTTP_* / 原名两种写法），最后进程环境（`host` 侧 env_lock 把本应用的 `.env`
 * 装在这里；本引擎不自报 env 隔离，所以一直在锁内、值有效）。 */
static int asp_server_variable(const struct asp_ctx *ctx, const char *key,
                               char *dst, size_t dst_len)
{
    const char *v;

    dst[0] = '\0';
    if (key == NULL || key[0] == '\0')
        return 0;
    if (strcasecmp(key, "PATH_INFO") == 0 || strcasecmp(key, "SCRIPT_NAME") == 0) {
        snprintf(dst, dst_len, "%s", ctx->req_path != NULL ? ctx->req_path : "");
        return 1;
    }
    if (strcasecmp(key, "QUERY_STRING") == 0) {
        snprintf(dst, dst_len, "%s", ctx->query != NULL ? ctx->query : "");
        return 1;
    }
    if (strcasecmp(key, "REQUEST_METHOD") == 0) {
        snprintf(dst, dst_len, "%s", ctx->method != NULL ? ctx->method : "GET");
        return 1;
    }
    if (strcasecmp(key, "REMOTE_ADDR") == 0) {
        snprintf(dst, dst_len, "%s", ctx->remote != NULL ? ctx->remote : "");
        return 1;
    }
    if (strcasecmp(key, "SERVER_NAME") == 0) {
        snprintf(dst, dst_len, "%s", ctx->server_name != NULL ? ctx->server_name : "");
        return 1;
    }
    if (strcasecmp(key, "SERVER_PORT") == 0) {
        snprintf(dst, dst_len, "%d", ctx->server_port);
        return 1;
    }
    /* 请求头（HTTP_HOST / HTTP_X_* 或原头名） */
    if (appengine_header_lookup(ctx->headers, key, dst, dst_len))
        return 1;
    /* 进程环境（含宿主按应用 `.env` 装进来的键；`PATH_INFO` 等已被上面截住） */
    v = getenv(key);
    if (v != NULL) {
        snprintf(dst, dst_len, "%s", v);
        return 1;
    }
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

static void eval_expression(const struct asp_ctx *ctx, const char *expr, size_t elen,
                            char **out, size_t *o, size_t *cap)
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
            if (query_get(ctx->query, key, tmp, sizeof(tmp)) == 0)
                append(out, o, cap, tmp, strlen(tmp));
        } else if (ctx->query != NULL && ctx->query[0]) {
            /* bare Request.QueryString → raw query */
            append(out, o, cap, ctx->query, strlen(ctx->query));
        }
        return;
    }

    /* Request.ServerVariables("HTTP_HOST") / ("PATH_INFO") / ("WINDOWMARK") 等 */
    if (strstr(buf, "Request.ServerVariables") || strstr(buf, "ServerVariables")) {
        if (extract_quoted(buf, key, sizeof(key)) == 0) {
            if (asp_server_variable(ctx, key, tmp, sizeof(tmp)))
                append(out, o, cap, tmp, strlen(tmp));
        } else if (ctx->req_path != NULL && strstr(buf, "PATH_INFO")) {
            append(out, o, cap, ctx->req_path, strlen(ctx->req_path));
        }
        return;
    }

    if (ctx->req_path != NULL && strstr(buf, "PATH_INFO")) {
        append(out, o, cap, ctx->req_path, strlen(ctx->req_path));
        return;
    }
}

static char *render_asp(const struct asp_ctx *ctx, const char *src, size_t len)
{
    char *out = NULL;
    size_t cap = 0;
    size_t o = 0;
    size_t i = 0;
    const char *path = ctx->req_path;

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
                eval_expression(ctx, src + block_start + 1, block_end - (block_start + 1),
                                &out, &o, &cap);
                continue;
            }

            /* Response.WriteLine —— **必须先于** Response.Write 判：后者的 14 字节前缀
             * 是前者的子串，旧顺序让 WriteLine 永远走 Write 分支、丢掉换行
             * （真机实测 `<% Response.WriteLine "L1" %>` 输出 "L1" 无换行）。 */
            if (strncmp(src + block_start, "Response.WriteLine", 18) == 0 ||
                strncmp(src + block_start, "Response.writeln", 16) == 0) {
                char lit[2048];
                if (extract_quoted(src + block_start, lit, sizeof(lit)) == 0) {
                    append(&out, &o, &cap, lit, strlen(lit));
                    append(&out, &o, &cap, "\n", 1);
                } else {
                    eval_expression(ctx, src + block_start + 18,
                                    block_end - (block_start + 18), &out, &o, &cap);
                }
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
                    eval_expression(ctx, src + block_start + 14, block_end - (block_start + 14),
                                    &out, &o, &cap);
                }
                continue;
            }

            /* Inline Request.QueryString assignment-style echo in <% %> */
            if (strstr(src + block_start, "Request.QueryString") ||
                strstr(src + block_start, "Request.ServerVariables")) {
                eval_expression(ctx, src + block_start, block_end - block_start,
                                &out, &o, &cap);
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
        /* 截断时 n 是「本来要写多长」——大于 sizeof(foot) 即越界读栈。 */
        if (n > 0 && (size_t)n > sizeof(foot) - 1)
            n = (int)sizeof(foot) - 1;
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
    const char *headers,
    AppEngineResult *out)
{
    char *src = NULL;
    size_t src_len = 0;
    char *rendered = NULL;
    char script_path[1024];
    struct asp_ctx ctx;

    (void)content_type;
    (void)body;
    (void)body_len;
    /* `.env`：本引擎不自报 env 隔离（见 appengine.h），宿主会把它装进**进程环境**
     * 后才调用 —— 脚本经 `Request.ServerVariables("KEY")` 的 getenv 兜底读到；
     * `extra` 里的 JSON 形式因此不再需要在这里解析（与 cgi/cgi_script 的子进程
     * envp 路径等价，且不会写入进程 env）。 */
    (void)extra;

    memset(&ctx, 0, sizeof(ctx));
    ctx.method = method;
    ctx.req_path = path;
    ctx.query = query;
    ctx.remote = remote;
    ctx.server_name = server_name;
    ctx.server_port = server_port > 0 ? server_port : 80;
    ctx.headers = headers;

    if (!g_ready || !out)
        return -1;

    if (script && script[0]) {
        if (read_file(script, &src, &src_len) != 0) {
            /* 脚本不存在 → **404**（此前回落 `appengine_fill_hello` 回 200
             * "hello from asp engine path=..." —— 软 404：缓存/探测/监控都以为页面存在）。
             * 绝对路径只进 out->error（Rust 侧节流写日志），客户端拿固定文本。 */
            appengine_result_alloc(out);
            out->status = 404;
            appengine_result_set_headers(
                out, "Content-Type: text/plain; charset=utf-8\r\n");
            appengine_result_set_body(out, "asp: script not found\n", 22);
            appengine_result_set_error(out, script);
            return 0;
        }
    } else {
        snprintf(script_path, sizeof(script_path), "%s/index.asp",
                 docroot ? docroot : ".");
        if (read_file(script_path, &src, &src_len) != 0) {
            appengine_result_alloc(out);
            out->status = 404;
            appengine_result_set_headers(
                out, "Content-Type: text/plain; charset=utf-8\r\n");
            appengine_result_set_body(out, "asp: script not found\n", 22);
            appengine_result_set_error(out, script_path);
            return 0;
        }
    }

    rendered = render_asp(&ctx, src, src_len);
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
