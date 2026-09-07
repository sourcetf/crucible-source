#include "appengine_common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *appengine_strdup(const char *s)
{
    size_t n;
    char *p;

    if (s == NULL)
        return NULL;
    n = strlen(s) + 1;
    p = (char *)malloc(n);
    if (p == NULL)
        return NULL;
    memcpy(p, s, n);
    return p;
}

int appengine_result_alloc(AppEngineResult *out)
{
    if (out == NULL)
        return -1;
    memset(out, 0, sizeof(*out));
    return 0;
}

int appengine_result_set_body(AppEngineResult *out, const void *data, size_t len)
{
    char *p;

    if (out == NULL)
        return -1;
    free(out->body);
    out->body = NULL;
    out->body_len = 0;
    if (data == NULL || len == 0)
        return 0;
    p = (char *)malloc(len + 1);
    if (p == NULL)
        return -1;
    memcpy(p, data, len);
    p[len] = '\0';
    out->body = p;
    out->body_len = len;
    return 0;
}

int appengine_result_set_headers(AppEngineResult *out, const char *headers)
{
    if (out == NULL)
        return -1;
    free(out->headers);
    out->headers = NULL;
    out->headers_len = 0;
    if (headers == NULL)
        return 0;
    out->headers = appengine_strdup(headers);
    if (out->headers == NULL)
        return -1;
    out->headers_len = strlen(out->headers);
    return 0;
}

int appengine_result_set_error(AppEngineResult *out, const char *msg)
{
    if (out == NULL)
        return -1;
    free(out->error);
    out->error = appengine_strdup(msg);
    return out->error == NULL && msg != NULL ? -1 : 0;
}

int appengine_fill_hello(AppEngineResult *out, const char *engine_name, const char *path)
{
    char buf[512];
    int n;

    if (appengine_result_alloc(out) != 0)
        return -1;
    out->status = 200;
    if (appengine_result_set_headers(out, "Content-Type: text/plain; charset=utf-8\r\n") != 0)
        return -1;
    n = snprintf(buf, sizeof(buf), "hello from %s engine path=%s\n",
                 engine_name ? engine_name : "unknown",
                 path ? path : "/");
    if (n < 0)
        return -1;
    return appengine_result_set_body(out, buf, (size_t)n);
}

void appengine_result_free(AppEngineResult *out)
{
    if (out == NULL)
        return;
    free(out->headers);
    free(out->body);
    free(out->error);
    memset(out, 0, sizeof(*out));
}

/* ------------------------------------------------------------ extra env ---
 * P1-1: extra 语义升级——Rust 侧（app_ffi::call_exec）在有 .env 变量时传 JSON：
 *   {"engine":"<name>","env":{"K":"V",...}}
 * 无变量时仍是 legacy 纯引擎名字符串（向后兼容，本函数 no-op）。
 * 极简扫描器：只识别 "env": { "K":"V" , ... } 形态，支持 \" \\ \/ \n \t \r
 * \b \f 与 \uXXXX（取低 8 位落地；.env 值约定为单字节文本）。
 * setenv 的线程安全由 libc 内部锁保证（OpenBSD）；并发 getenv 可能读到旧值，
 * 与 env_lock（Rust 侧）现状一致，可接受。 */

static int ae_hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* 解析一个 JSON 字符串（s 指向起始引号），写入 out（cap 含 NUL）；
 * 返回消费的字符数（含结束引号），失败返回 0。 */
static size_t ae_json_string(const char *s, const char *end, char *out, size_t cap)
{
    size_t used = 0;
    const char *p = s;

    if (p >= end || *p != '"')
        return 0;
    p++;
    while (p < end && *p != '"') {
        char ch = *p;
        if (ch == '\\') {
            p++;
            if (p >= end)
                return 0;
            switch (*p) {
            case 'n': ch = '\n'; break;
            case 't': ch = '\t'; break;
            case 'r': ch = '\r'; break;
            case 'b': ch = '\b'; break;
            case 'f': ch = '\f'; break;
            case '/': ch = '/'; break;
            case '"': ch = '"'; break;
            case '\\': ch = '\\'; break;
            case 'u': {
                int v = 0, i;
                if (end - p < 5)
                    return 0;
                for (i = 1; i <= 4; i++) {
                    int h = ae_hexval((unsigned char)p[i]);
                    if (h < 0)
                        return 0;
                    v = (v << 4) | h;
                }
                p += 4;
                ch = (char)(v & 0xff);
                break;
            }
            default:
                return 0;
            }
            p++;
        } else {
            p++;
        }
        if (used + 1 >= cap)
            return 0;
        out[used++] = ch;
    }
    if (p >= end)
        return 0;
    out[used] = '\0';
    return (size_t)(p - s + 1);
}

int appengine_apply_extra(const char *extra)
{
    const char *p, *end, *envk;
    char key[256], val[2048];

    if (extra == NULL)
        return -1;
    /* legacy：非 JSON（找不到 '{'）→ 纯引擎名，no-op。 */
    p = strchr(extra, '{');
    if (p == NULL)
        return 0;
    end = extra + strlen(extra);
    envk = strstr(p, "\"env\"");
    if (envk == NULL)
        return 0;
    p = strchr(envk + 5, '{');
    if (p == NULL)
        return 0;
    p++;
    for (;;) {
        const char *kq;
        size_t n;

        while (p < end &&
               (*p == ' ' || *p == ',' || *p == '\n' || *p == '\r' || *p == '\t'))
            p++;
        if (p >= end || *p == '}')
            break;
        kq = strchr(p, '"');
        if (kq == NULL || kq >= end)
            break;
        n = ae_json_string(kq, end, key, sizeof(key));
        if (n == 0)
            break;
        p = kq + n;
        while (p < end && (*p == ' ' || *p == ':'))
            p++;
        if (p >= end || *p != '"')
            break;
        n = ae_json_string(p, end, val, sizeof(val));
        if (n == 0)
            break;
        p += n;
        if (key[0] != '\0')
            setenv(key, val, 1);
    }
    return 0;
}
