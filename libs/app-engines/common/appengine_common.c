#include "appengine_common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int appengine_abi_version(void)
{
    return APPENGINE_ABI_VERSION;
}

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
    /* snprintf 返回的是「本来要写多长」：被截断时它 >= sizeof(buf)。
     * 直接把它当长度用，会从栈上的 buf 越界读并把栈内容塞进响应体
     * （远程内存泄露；路径足够长时还会跑出线程栈）。 */
    if ((size_t)n >= sizeof(buf))
        n = (int)sizeof(buf) - 1;
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
        /* 解码后含 NUL（`\u0000` 或字面 NUL）一律判为无效：
         * 环境变量名/值里的 NUL 没有合法用途，而它会**在 NUL 处截断** —— 于是键
         * `A\u0000B` 会静默变成设置变量 `A`（打到另一个名字上）。Rust 侧的
         * `env_lock::normalized()` 已经滤掉含 NUL 的键，但传给本函数的是**未过滤**的
         * env 集合 ⇒ 这里必须自己挡。 */
        if (ch == '\0')
            return 0;
        out[used++] = ch;
    }
    if (p >= end)
        return 0;
    out[used] = '\0';
    return (size_t)(p - s + 1);
}

/* 跳过当前这个 JSON 字符串（不落地），返回消费的字符数；畸形返回 0。
 *
 * 用途：**值太长装不下时跳过这一项、继续解析后面的**，而不是中断整段 env
 * —— 见 appengine_apply_extra 里调用点的说明。 */
static size_t ae_json_skip_string(const char *s, const char *end)
{
    const char *p = s;

    if (p >= end || *p != '"')
        return 0;
    p++;
    while (p < end && *p != '"') {
        if (*p == '\\') {
            p++;
            if (p >= end)
                return 0;
        }
        p++;
    }
    if (p >= end)
        return 0;
    return (size_t)(p - s + 1);
}

/* ------------------------------------------------------- request headers --- */

/* 头部值上限（单条）。超长的行整体跳过：回调方的落地缓冲都是有界的
 * （环境变量/ASCIIZ 键值），截断会产生「半条 Cookie」这类静默错误。 */
#define AE_HEADER_VALUE_MAX 16384
#define AE_HEADER_NAME_MAX  256

/* 名字按 HTTP token 的实用子集校验：字母/数字/`-`/`_`/`.`。
 * 其它字符（空格、控制字符、`:` 已在切分时排除）会让 CGI 环境键非法或歧义。 */
static int ae_header_name_ok(const char *n, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)n[i];

        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.')
            continue;
        return 0;
    }
    return 1;
}

/* 大小写不敏感比较 `a[0..n)` 与 NUL 结尾的 b；要求 strlen(b) == n。 */
static int ae_ieq(const char *a, size_t n, const char *b)
{
    size_t i;

    if (strlen(b) != n)
        return 0;
    for (i = 0; i < n; i++) {
        unsigned char ca = (unsigned char)a[i];
        unsigned char cb = (unsigned char)b[i];

        if (ca >= 'A' && ca <= 'Z')
            ca = (unsigned char)(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z')
            cb = (unsigned char)(cb - 'A' + 'a');
        if (ca != cb)
            return 0;
    }
    return 1;
}

/* Content-Type/Content-Length 有独立形参，头块里不发、也不回调（防覆盖）。 */
static int ae_header_is_body_meta(const char *n, size_t len)
{
    return ae_ieq(n, len, "content-type") || ae_ieq(n, len, "content-length");
}

int appengine_headers_foreach(
    const char *headers,
    int (*cb)(void *ctx, const char *name, size_t name_len,
              const char *value, size_t value_len),
    void *ctx)
{
    const char *p;
    int count = 0;

    if (headers == NULL || cb == NULL)
        return 0;
    p = headers;
    while (*p != '\0') {
        const char *line_end = p;
        const char *colon;
        size_t llen, name_len, value_len;
        const char *value;

        while (*line_end != '\0' && *line_end != '\r' && *line_end != '\n')
            line_end++;
        llen = (size_t)(line_end - p);
        if (llen > 0) {
            colon = (const char *)memchr(p, ':', llen);
            if (colon != NULL) {
                name_len = (size_t)(colon - p);
                value = colon + 1;
                while (value < line_end && (*value == ' ' || *value == '\t'))
                    value++;
                value_len = (size_t)(line_end - value);
                if (name_len > 0 && name_len <= AE_HEADER_NAME_MAX &&
                    value_len <= AE_HEADER_VALUE_MAX &&
                    ae_header_name_ok(p, name_len) &&
                    !ae_header_is_body_meta(p, name_len)) {
                    int rc = cb(ctx, p, name_len, value, value_len);

                    if (rc != 0)
                        return rc;
                    count++;
                }
            }
        }
        if (*line_end == '\r')
            line_end++;
        if (*line_end == '\n')
            line_end++;
        p = line_end;
    }
    return count;
}

size_t appengine_cgi_http_key(char *out, size_t out_sz, const char *name, size_t name_len)
{
    size_t i, n = 0;

    if (out == NULL || out_sz == 0 || name == NULL)
        return 0;
    if (out_sz < name_len + 6)
        return 0;
    memcpy(out, "HTTP_", 5);
    n = 5;
    for (i = 0; i < name_len; i++) {
        unsigned char c = (unsigned char)name[i];

        if (c >= 'a' && c <= 'z')
            c = (unsigned char)(c - 'a' + 'A');
        else if (c == '-')
            c = '_';
        out[n++] = (char)c;
    }
    out[n] = '\0';
    return n;
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
        if (n == 0) {
            /* 键太长/含 NUL 时**跳过这个键**、继续解析它后面的值（键超长不是「后面全不要了」）。
             * 与值那条同一理由；键在实践里很短，这里是防御性对称处理。 */
            n = ae_json_skip_string(kq, end);
            if (n == 0)
                break;
            key[0] = '\0'; /* 标记为「本项不落地」，值仍会被跳过 */
        }
        p = kq + n;
        while (p < end && (*p == ' ' || *p == ':'))
            p++;
        if (p >= end || *p != '"')
            break;
        n = ae_json_string(p, end, val, sizeof(val));
        if (n == 0) {
            /* **不能 break**：`ae_json_string` 在「放不下」时返回 0，而这里最容易发生的
             * 就是**值 ≥ sizeof(val)（2048 字节）** —— base64 密钥、长列表、内联 JSON 都很
             * 容易超。原实现的 `break` 会把这之后**所有**变量一起丢掉：应用「莫名少了几
             * 个环境变量」，而配置、日志、面板**全都正常**，没有任何一行线索（这是本项目
             * 最忌讳的那类故障）。改为跳过这一项、继续解析后面的。
             * 键也一样处理（键超长同样是「这一项不要了」，而不是「后面全不要了」）。 */
            n = ae_json_skip_string(p, end);
            if (n == 0)
                break; /* 真的畸形了才停 */
            p += n;
            continue;
        }
        p += n;
        /* 键含 `=` 时 POSIX `setenv` 会失败（EINVAL）—— 显式跳过，别指望 libc 兜底
         * （NUL 的情况已在 ae_json_string 里挡掉）。 */
        if (key[0] != '\0' && strchr(key, '=') == NULL)
            setenv(key, val, 1);
    }
    return 0;
}
