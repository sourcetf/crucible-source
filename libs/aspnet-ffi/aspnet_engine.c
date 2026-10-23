/*
 * ASP.NET / ASPX minimal engine — serves .aspx/.html with <%= %> expansion
 * when hostfxr CoreCLR is unavailable. Prefer hostfxr when present.
 *
 * Exported ABI (must match libs/app-engines/include/appengine.h):
 *   appengine_init / appengine_execute / appengine_shutdown
 *   appengine_result_free is provided via appengine_common.c (linked in).
 *
 * Smoke tests: always return HTTP 200 with clear X-Crucible-Engine markers
 * (aspnet-mini / aspnet-smoke) even when hostfxr dlopen fails.
 */
#include "../app-engines/include/appengine.h"
#include "../app-engines/common/appengine_common.h"

#include <dlfcn.h>
#include <glob.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#ifdef _WIN32
#define strcasecmp _stricmp
#else
#include <pthread.h>
#include <strings.h> /* strcasecmp（ServerVariables 的键名比较） */
#endif

static int g_ready;
static void *g_hostfxr;
static int g_hostfxr_ok;
/* ---------------------------------------------------------------------------
 * 真 hostfxr 路径：进程内加载托管程序集并调用 UnmanagedCallersOnly 入口
 *
 * 为什么需要：旧实现只 dlopen("libhostfxr.so") 然后把 g_hostfxr_ok 置 1，
 * **从未调用 hostfxr 的任何 API** —— 即使机器装了 .NET，/aspnet/ 也永远是 mini
 * 渲染器（body 是 C 代码拼的），规格 §16.6 的「hostfxr 进程内」无法验证。
 *
 * 约定（最小、可验证）：
 *   <docroot>/bin/CrucibleAspNetSample.dll + .runtimeconfig.json
 *   类型 Crucible.AspNet.Sample.Handler，方法 Render：
 *     int Render(const char *method, const char *path, const char *query,
 *                const char *body, const char *source,
 *                char *out, int out_cap);   // 返回写入字节数，<0 失败
 *   C 侧把 .aspx 源文本交给托管渲染器；成功时响应头带
 *   X-Crucible-Engine: aspnet-hostfxr + X-Crucible-AspNet-Mode: hostfxr。
 *   托管程序集缺失/加载失败 → 保持原来的 mini 渲染器（诚实降级，200 仍来自样例）。
 * ------------------------------------------------------------------------- */
typedef int (*hostfxr_initialize_for_runtime_config_fn)(const char *, const void *, void **);
typedef int (*hostfxr_get_runtime_delegate_fn)(void *, int, void **);
typedef int (*hostfxr_close_fn)(void *);
typedef int (*load_assembly_and_get_function_pointer_fn)(
    const char *, const char *, const char *, const char *, void *, void **);
typedef int (*aspx_managed_render_fn)(
    const char *, const char *, const char *, const char *, const char *, char *, int);

#define ASPX_HDT_LOAD_ASSEMBLY_AND_GET_FUNCTION_POINTER 5

/* 定义在文件后面（FIFO 安全的存在性判定）。 */
static int is_regular_file(const char *p);

struct aspx_managed {
    int state; /* 0=未尝试 1=不可用 2=就绪 */
    void *ctx; /* hostfxr host context */
    load_assembly_and_get_function_pointer_fn load;
    aspx_managed_render_fn render;
    char assembly[1024];
    char runtimeconfig[1024];
};
static struct aspx_managed g_managed;
#ifndef _WIN32
static pthread_mutex_t g_managed_mx = PTHREAD_MUTEX_INITIALIZER;
#endif

static void aspx_managed_lock(void)
{
#ifndef _WIN32
    pthread_mutex_lock(&g_managed_mx);
#endif
}
static void aspx_managed_unlock(void)
{
#ifndef _WIN32
    pthread_mutex_unlock(&g_managed_mx);
#endif
}

/* 在 DOTNET_ROOT / 常见安装位置找 libhostfxr.so，返回第一个能 dlopen 的。 */
static void *aspx_load_hostfxr(void)
{
    const char *roots[5];
    char envbuf[1024];
    glob_t g;
    size_t i;
    void *h = NULL;
    const char *dotnet_root = getenv("DOTNET_ROOT");

    roots[0] = dotnet_root;
    roots[1] = getenv("DOTNET_ROOT_X64");
    roots[2] = "/usr/lib/dotnet";
    roots[3] = "/usr/share/dotnet";
    roots[4] = "/usr/local/share/dotnet";
    for (i = 0; i < sizeof(roots) / sizeof(roots[0]); i++) {
        size_t k;
        if (roots[i] == NULL || roots[i][0] == '\0')
            continue;
        memset(&g, 0, sizeof(g));
        snprintf(envbuf, sizeof(envbuf), "%s/host/fxr/*/libhostfxr.so", roots[i]);
        if (glob(envbuf, 0, NULL, &g) != 0) {
            globfree(&g);
            continue;
        }
        for (k = 0; k < g.gl_pathc; k++) {
            h = dlopen(g.gl_pathv[k], RTLD_NOW | RTLD_LOCAL);
            if (h != NULL) {
                fprintf(stderr, "aspnet-hostfxr: using %s\n", g.gl_pathv[k]);
                break;
            }
        }
        globfree(&g);
        if (h != NULL)
            return h;
    }
    /* 最后兜底：LD_LIBRARY_PATH 里的裸名（容器/自定义布局）。 */
    h = dlopen("libhostfxr.so", RTLD_NOW | RTLD_LOCAL);
    if (h == NULL)
        h = dlopen("libhostfxr.so.8", RTLD_NOW | RTLD_LOCAL);
    if (h == NULL)
        h = dlopen("libhostfxr.so.6", RTLD_NOW | RTLD_LOCAL);
    return h;
}

/* 尝试初始化托管渲染器（幂等；失败后不再重试，避免每请求都 dlopen/报错）。 */
static int aspx_managed_ensure(const char *docroot)
{
    hostfxr_initialize_for_runtime_config_fn init_fn;
    hostfxr_get_runtime_delegate_fn get_delegate;
    hostfxr_close_fn close_fn;
    int rc;

    aspx_managed_lock();
    if (g_managed.state != 0) {
        rc = (g_managed.state == 2) ? 1 : 0;
        aspx_managed_unlock();
        return rc;
    }
    g_managed.state = 1; /* 先假定不可用；成功再改 2（锁内单写者） */
    if (docroot == NULL || docroot[0] == '\0')
        goto fail;
    snprintf(g_managed.assembly, sizeof(g_managed.assembly),
             "%s/bin/CrucibleAspNetSample.dll", docroot);
    snprintf(g_managed.runtimeconfig, sizeof(g_managed.runtimeconfig),
             "%s/bin/CrucibleAspNetSample.runtimeconfig.json", docroot);
    if (!is_regular_file(g_managed.assembly) || !is_regular_file(g_managed.runtimeconfig)) {
        /* 绝大多数部署没有托管样例：不算错误，保持 mini（不刷日志）。 */
        goto fail;
    }
    if (g_hostfxr == NULL) {
        g_hostfxr = aspx_load_hostfxr();
    }
    if (g_hostfxr == NULL)
        goto fail;
    init_fn = (hostfxr_initialize_for_runtime_config_fn)
        dlsym(g_hostfxr, "hostfxr_initialize_for_runtime_config");
    get_delegate = (hostfxr_get_runtime_delegate_fn)
        dlsym(g_hostfxr, "hostfxr_get_runtime_delegate");
    close_fn = (hostfxr_close_fn)dlsym(g_hostfxr, "hostfxr_close");
    if (init_fn == NULL || get_delegate == NULL || close_fn == NULL)
        goto fail;
    rc = init_fn(g_managed.runtimeconfig, NULL, &g_managed.ctx);
    /* 0=Success, 1=Success_HostAlreadyInitialized, 2=Success_DifferentRuntimeProperties */
    if (rc < 0 || rc > 2) {
        fprintf(stderr, "aspnet-hostfxr: initialize_for_runtime_config(%s) rc=%d\n",
                g_managed.runtimeconfig, rc);
        g_managed.ctx = NULL;
        goto fail;
    }
    rc = get_delegate(g_managed.ctx,
                      ASPX_HDT_LOAD_ASSEMBLY_AND_GET_FUNCTION_POINTER,
                      (void **)&g_managed.load);
    if (rc < 0 || g_managed.load == NULL) {
        fprintf(stderr, "aspnet-hostfxr: get_runtime_delegate rc=%d\n", rc);
        goto fail;
    }
    rc = g_managed.load(g_managed.assembly,
                        "Crucible.AspNet.Sample.Handler, CrucibleAspNetSample",
                        "Render",
                        /* hostfxr 的 UNMANAGEDCALLERSONLY_METHOD 哨兵值是
                         * ((const char_t*)-1)，**不是**字面量
                         * "UNMANAGEDCALLERSONLY_METHOD"（后者只是文档里的宏名）。
                         * 传字面量会得到 0x80131522 并静默退回 mini。 */
                        (const char *)(intptr_t)-1, NULL,
                        (void **)&g_managed.render);
    if (rc != 0 || g_managed.render == NULL) {
        fprintf(stderr, "aspnet-hostfxr: load_assembly_and_get_function_pointer rc=%d\n", rc);
        goto fail;
    }
    g_managed.state = 2;
    fprintf(stderr, "aspnet-hostfxr: managed handler ready (%s)\n", g_managed.assembly);
    aspx_managed_unlock();
    return 1;

fail:
    aspx_managed_unlock();
    return 0;
}

/* 请求上下文：ServerVariables 的取值来源（ABI 形参 + headers 块 + 进程环境）。
 * 与 AxonASP 引擎同一套语义（`.env` 经宿主 env_lock 装进进程 env 后由 getenv 兜底读）。 */
struct aspx_ctx {
    const char *method;
    const char *req_path;
    const char *query;
    const char *remote;
    const char *server_name;
    int server_port;
    const char *headers;
};

static int aspx_server_variable(const struct aspx_ctx *c, const char *key,
                                char *dst, size_t dst_len)
{
    const char *v;

    dst[0] = '\0';
    if (key == NULL || key[0] == '\0')
        return 0;
    if (strcasecmp(key, "PATH_INFO") == 0 || strcasecmp(key, "SCRIPT_NAME") == 0) {
        snprintf(dst, dst_len, "%s", c->req_path != NULL ? c->req_path : "");
        return 1;
    }
    if (strcasecmp(key, "QUERY_STRING") == 0) {
        snprintf(dst, dst_len, "%s", c->query != NULL ? c->query : "");
        return 1;
    }
    if (strcasecmp(key, "REQUEST_METHOD") == 0) {
        snprintf(dst, dst_len, "%s", c->method != NULL ? c->method : "GET");
        return 1;
    }
    if (strcasecmp(key, "REMOTE_ADDR") == 0) {
        snprintf(dst, dst_len, "%s", c->remote != NULL ? c->remote : "");
        return 1;
    }
    if (strcasecmp(key, "SERVER_NAME") == 0) {
        snprintf(dst, dst_len, "%s", c->server_name != NULL ? c->server_name : "");
        return 1;
    }
    if (strcasecmp(key, "SERVER_PORT") == 0) {
        snprintf(dst, dst_len, "%d", c->server_port);
        return 1;
    }
    if (appengine_header_lookup(c->headers, key, dst, dst_len))
        return 1;
    v = getenv(key);
    if (v != NULL) {
        snprintf(dst, dst_len, "%s", v);
        return 1;
    }
    return 0;
}

/* Extract value of key= from a query string (first match). */
static int query_get(const char *query, const char *key, char *out, size_t out_sz)
{
    size_t klen;
    const char *p;

    if (!out || out_sz == 0)
        return -1;
    out[0] = '\0';
    if (!query || !key || !key[0])
        return -1;
    klen = strlen(key);
    p = query;
    while (*p) {
        if ((p == query || p[-1] == '&') && strncmp(p, key, klen) == 0 && p[klen] == '=') {
            const char *v = p + klen + 1;
            size_t n = 0;
            while (v[n] && v[n] != '&' && n + 1 < out_sz)
                n++;
            memcpy(out, v, n);
            out[n] = '\0';
            return 0;
        }
        p++;
    }
    return -1;
}

static int read_file(const char *path, char **out, size_t *out_len)
{
    FILE *f;
    long sz;
    char *buf;
    struct stat st;

    *out = NULL;
    *out_len = 0;
    /* 常规文件检查必须在 fopen 之前：FIFO/字符设备上 fopen 会**阻塞**（FIFO 无写端时
     * open 一直等），而 FFI 引擎调用没有墙钟超时 —— docroot 里一个 FIFO 就能把线程池
     * 线程永久钉住（cgi 引擎早有 is_regular_file 这道闸，这里补齐）。 */
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
    if (sz < 0 || sz > 2 * 1024 * 1024) {
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
    fclose(f);
    buf[sz] = '\0';
    *out = buf;
    *out_len = (size_t)sz;
    return 0;
}

/* Expand <%= Request.QueryString("x") %> / <%= "literal" %> / bare QueryString /
 * <%= Request.ServerVariables("HTTP_HOST") %>（`()[]` 与单双引号均可）。 */
static char *render_aspx(const struct aspx_ctx *ctx, const char *src, size_t src_len)
{
    const char *query = ctx->query;
    size_t cap = src_len + 256;
    char *out = (char *)malloc(cap);
    size_t o = 0;
    size_t i = 0;
    if (!out)
        return NULL;
    while (i < src_len) {
        if (i + 2 < src_len && src[i] == '<' && src[i + 1] == '%' && src[i + 2] == '=') {
            size_t j = i + 3;
            size_t expr_start;
            char expr[256];
            size_t elen;
            char qval[256];

            while (j + 1 < src_len && !(src[j] == '%' && src[j + 1] == '>'))
                j++;
            expr_start = i + 3;
            elen = (j > expr_start) ? (j - expr_start) : 0;
            if (elen >= sizeof(expr))
                elen = sizeof(expr) - 1;
            memcpy(expr, src + expr_start, elen);
            expr[elen] = '\0';
            /* trim */
            {
                char *s = expr;
                char *e;
                while (*s == ' ' || *s == '\t' || *s == '\n' || *s == '\r')
                    s++;
                e = s + strlen(s);
                while (e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\n' || e[-1] == '\r'))
                    e--;
                *e = '\0';
                if (s != expr)
                    memmove(expr, s, strlen(s) + 1);
            }

            qval[0] = '\0';
            if (strstr(expr, "ServerVariables")) {
                /* Request.ServerVariables("HTTP_HOST") / ["WINDOWMARK"]：取引号里的键名。
                 * 此前 aspx 表达式里没有 ServerVariables 分支 ⇒ 恒空（与 ASP 引擎同一
                 * 缺陷；.env / HTTP_* 对应用的可见性跨引擎应一致）。 */
                const char *q = strchr(expr, '"');
                const char *q2;
                if (!q)
                    q = strchr(expr, '\'');
                if (q) {
                    char delim = *q;
                    q++;
                    q2 = strchr(q, delim);
                    if (q2 && (size_t)(q2 - q) < 64) {
                        char key[64];
                        size_t kn = (size_t)(q2 - q);
                        memcpy(key, q, kn);
                        key[kn] = '\0';
                        aspx_server_variable(ctx, key, qval, sizeof(qval));
                    }
                }
            } else if (strstr(expr, "QueryString")) {
                const char *q = strchr(expr, '"');
                const char *q2;
                if (!q)
                    q = strchr(expr, '\'');
                if (q) {
                    char delim = *q;
                    q++;
                    q2 = strchr(q, delim);
                    if (q2 && (size_t)(q2 - q) < 64) {
                        char key[64];
                        size_t kn = (size_t)(q2 - q);
                        memcpy(key, q, kn);
                        key[kn] = '\0';
                        query_get(query ? query : "", key, qval, sizeof(qval));
                    }
                } else if (query && query[0]) {
                    /* bare QueryString → whole query string */
                    snprintf(qval, sizeof(qval), "%s", query);
                }
            } else if ((expr[0] == '"' && expr[strlen(expr) - 1] == '"') ||
                       (expr[0] == '\'' && expr[strlen(expr) - 1] == '\'')) {
                size_t n = strlen(expr);
                if (n >= 2 && n - 2 < sizeof(qval)) {
                    memcpy(qval, expr + 1, n - 2);
                    qval[n - 2] = '\0';
                }
            }

            {
                size_t qlen = strlen(qval);
                if (o + qlen + 1 > cap) {
                    char *nb;
                    cap = (o + qlen + 1) * 2;
                    nb = (char *)realloc(out, cap);
                    if (!nb) {
                        free(out);
                        return NULL;
                    }
                    out = nb;
                }
                memcpy(out + o, qval, qlen);
                o += qlen;
            }
            i = (j + 1 < src_len) ? j + 2 : src_len;
            continue;
        }
        /* strip <% ... %> script blocks */
        if (i + 1 < src_len && src[i] == '<' && src[i + 1] == '%') {
            size_t j = i + 2;
            while (j + 1 < src_len && !(src[j] == '%' && src[j + 1] == '>'))
                j++;
            i = (j + 1 < src_len) ? j + 2 : src_len;
            continue;
        }
        if (o + 2 > cap) {
            char *nb;
            cap *= 2;
            nb = (char *)realloc(out, cap);
            if (!nb) {
                free(out);
                return NULL;
            }
            out = nb;
        }
        out[o++] = src[i++];
    }
    out[o] = '\0';
    return out;
}

/* 常规文件判定：**不能用 fopen 探测存在性** —— FIFO/字符设备上 fopen 会阻塞
 *（FIFO 无写端时 open 一直等），而 FFI 引擎调用没有墙钟超时、调用期间还持有宿主的
 * env 锁 ⇒ 一个 FIFO 就能把**所有**依赖 env 锁的引擎永久挂住（真机实测：
 * `/aspnet-a/fifo.aspx` 让随后 wsgi/asgi/lua 全部超时）。 */
static int is_regular_file(const char *p)
{
    struct stat st;

    return p != NULL && p[0] != '\0' && stat(p, &st) == 0 && S_ISREG(st.st_mode);
}

static int resolve_aspx(const char *script, const char *docroot, const char *path,
                        char *filepath, size_t filepath_sz)
{
    const char *name = script && script[0] ? script : NULL;

    if (name) {
        /* 宿主（app_ffi）传进来的 `script` 是**已解析好的脚本路径**（已含 docroot），
         * 这里不能再 join docroot —— 否则变成 `docroot/docroot/x.aspx`，永远打不开，
         * 只能靠后面那条 index 兜底掩盖（而兜底正是软 404 的来源）。直接用。 */
        snprintf(filepath, filepath_sz, "%s", name);
        if (is_regular_file(filepath))
            return 0;
    }
    /* Derive from request path: /foo.aspx → docroot/foo.aspx */
    if (path && path[0]) {
        const char *p = path;
        while (*p == '/')
            p++;
        if (docroot && docroot[0])
            snprintf(filepath, filepath_sz, "%s/%s", docroot, p);
        else
            snprintf(filepath, filepath_sz, "%s", p);
        if (is_regular_file(filepath))
            return 0;
    }
    /* 不再回落 `docroot/index.aspx`：那会让 `/aspnet/<不存在的>.aspx` 返回首页内容
     * （软 404，URL 不变但内容是别的页面）。宿主侧对目录请求已把 script 解析成
     * `index.aspx`（`app_ffi::rel_script_path`），所以这里不需要这条兜底。 */
    return -1;
}

int appengine_init(const char *engine, const char *lib_hint)
{
    (void)engine;
    (void)lib_hint;
    g_hostfxr = NULL;
    g_hostfxr_ok = 0;
    memset(&g_managed, 0, sizeof(g_managed));
    /* 真正的 hostfxr 搜索（DOTNET_ROOT / /usr/lib/dotnet / /usr/share/dotnet …）。
     * 旧实现只认裸名 libhostfxr.so[.6/.8]，用户级安装（~/local/usr/lib/dotnet）与
     * 发行版布局都不在默认 loader 路径里 ⇒ 永远走 mini。 */
    g_hostfxr = aspx_load_hostfxr();
    if (g_hostfxr)
        g_hostfxr_ok = 1;
    /* Mini ASPX renderer is always available when hostfxr is absent. */
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
    char filepath[1024] = {0};
    char *raw = NULL;
    size_t raw_len = 0;
    char *rendered = NULL;
    struct aspx_ctx ctx;

    (void)content_type;
    (void)body;
    (void)body_len;
    /* `extra`（.env JSON）不在这里解析：本引擎不自报 env 隔离，宿主已把 `.env`
     * 装进**进程环境**后才调用，ServerVariables 的 getenv 兜底即可读到。 */
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

    appengine_result_alloc(out);

    if (resolve_aspx(script, docroot, path, filepath, sizeof(filepath)) == 0 &&
        read_file(filepath, &raw, &raw_len) == 0 && raw) {
        /* 真 hostfxr 优先：docroot/bin/CrucibleAspNetSample.dll 存在且 CoreCLR 就绪时，
         * 由托管代码渲染（真的经过 hostfxr_initialize_for_runtime_config +
         * load_assembly_and_get_function_pointer），失败才退回 mini。 */
        if (aspx_managed_ensure(docroot)) {
            int cap = (int)raw_len + 8192;
            char *mbuf;
            int n;
            if (cap < 16384)
                cap = 16384;
            if (cap > 4 * 1024 * 1024)
                cap = 4 * 1024 * 1024;
            mbuf = (char *)malloc((size_t)cap);
            if (mbuf != NULL) {
                n = g_managed.render(method != NULL ? method : "GET",
                                     path != NULL ? path : "/",
                                     query != NULL ? query : "",
                                     body != NULL ? body : "",
                                     raw, mbuf, cap);
                if (n >= 0) {
                    out->status = 200;
                    appengine_result_set_headers(
                        out, "Content-Type: text/html; charset=utf-8\r\n"
                             "X-Crucible-Engine: aspnet-hostfxr\r\n"
                             "X-Crucible-AspNet-Mode: hostfxr\r\n");
                    appengine_result_set_body(out, mbuf, (size_t)n);
                    free(mbuf);
                    free(raw);
                    return 0;
                }
                fprintf(stderr,
                        "aspnet-hostfxr: managed render failed rc=%d, falling back to mini\n", n);
                free(mbuf);
            }
        }
        rendered = render_aspx(&ctx, raw, raw_len);
        free(raw);
        if (rendered) {
            /* Ensure smoke tests see a non-empty body even for empty templates. */
            if (rendered[0] == '\0') {
                free(rendered);
                rendered = NULL;
            } else {
                out->status = 200;
                appengine_result_set_headers(
                    out, "Content-Type: text/html; charset=utf-8\r\n"
                         "X-Crucible-Engine: aspnet-mini\r\n"
                         "X-Crucible-AspNet-Mode: mini-aspx\r\n");
                appengine_result_set_body(out, rendered, strlen(rendered));
                free(rendered);
                return 0;
            }
        }
    }

    /* 脚本不存在 → **404**。此前走「smoke-friendly」分支回 200，body 里还带
     * `script=%s`（app_ffi 传来的 canonicalize 后的**服务器绝对路径**）—— 既是软 404
     * （页面不存在却 200），又向客户端泄露绝对路径。统一为固定 404 文本，细节只进
     * out->error（Rust 侧节流写日志）。 */
    out->status = 404;
    appengine_result_set_headers(out, "Content-Type: text/plain; charset=utf-8\r\n"
                                      "X-Crucible-Engine: aspnet-mini\r\n"
                                      "X-Crucible-AspNet-Mode: mini-aspx\r\n");
    appengine_result_set_body(out, "aspnet: script not found\n", 25);
    appengine_result_set_error(
        out, filepath[0] ? filepath : (script && script[0] ? script : "index.aspx"));
    return 0;
}

void appengine_shutdown(void)
{
    if (g_hostfxr != NULL) {
        if (g_managed.ctx != NULL) {
            hostfxr_close_fn close_fn = (hostfxr_close_fn)dlsym(g_hostfxr, "hostfxr_close");
            if (close_fn != NULL)
                close_fn(g_managed.ctx);
        }
        dlclose(g_hostfxr);
        g_hostfxr = NULL;
    }
    memset(&g_managed, 0, sizeof(g_managed));
    g_hostfxr_ok = 0;
    g_ready = 0;
}
