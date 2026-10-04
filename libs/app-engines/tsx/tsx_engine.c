/*
 * TSX/TS app-engine —— h2/h3 字节路径的产物服务端（编译由 Rust 管线负责）。
 *
 * 架构（规格 §7.7「一键编译 + watch 部署」）：
 *   - h1 请求：src/server/apps/tsx.rs 内置编译管线（esbuild/tsc/swc）+ watch，
 *     产物写 <out_dir>（默认 <docroot>/dist），请求直接读产物；
 *   - h2/h3 请求：走 app_ffi 到本 .so。本引擎**只服务已编译产物**——把
 *     `script`（app_ffi 已解析成 docroot 下的绝对源路径）映射成
 *     `<docroot>/dist/<同名>.js`，读出发回；产物不存在就诚实报错并指出先触发编译。
 *
 * 本引擎**不**按请求 spawn 解释器/编译器（旧实现 popen("tsx/npx/node …") 把请求
 * 派生路径拼进 shell 字符串，既是每请求进程风暴也是命令注入面，已删除）。
 * 这里也不假装 hello：没有产物就是错误。
 *
 * 边界与约定：
 *   - 只读 <docroot>/dist 下的普通文件；源码 .ts/.tsx 绝不外发；
 *   - 单份产物 ≤ 64MiB（与 Rust 侧 MAX_PRODUCT_BYTES 同口径）；
 *   - 若配置把 out_dir 指到别处（非 <docroot>/dist），h2/h3 这条路径找不到产物，
 *     会返回明确错误（h1/面板编译管线仍然按配置工作）。
 */
#include "appengine.h"
#include "appengine_common.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define TSX_MAX_PRODUCT (64UL * 1024UL * 1024UL)

static int g_inited;

/* 引擎级失败：填 out->error 并返回 -1（app_ffi 会把它变成固定 502 文本，详情进日志）。 */
static int tsx_fail(AppEngineResult *out, const char *fmt, ...)
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

/* 源文件定位（仅用于把状态报清楚）：显式 script → docroot/index.tsx → index.ts。 */
static const char *resolve_script(const char *script, const char *docroot, char *out,
                                  size_t outsz)
{
    if (is_regular_file(script)) {
        snprintf(out, outsz, "%s", script);
        return out;
    }
    if (docroot != NULL && docroot[0] != '\0') {
        snprintf(out, outsz, "%s/index.tsx", docroot);
        if (is_regular_file(out))
            return out;
        snprintf(out, outsz, "%s/index.ts", docroot);
        if (is_regular_file(out))
            return out;
    }
    return NULL;
}

/* script（docroot 下的绝对路径）→ 相对 docroot 的路径；不在 docroot 下返回 -1。 */
static int rel_under_docroot(const char *script, const char *docroot, char *out, size_t outsz)
{
    const char *rel;
    size_t dl;

    if (script == NULL || script[0] == '\0' || docroot == NULL || docroot[0] == '\0')
        return -1;
    dl = strlen(docroot);
    while (dl > 1 && docroot[dl - 1] == '/')
        dl--;
    if (strncmp(script, docroot, dl) != 0 || script[dl] != '/')
        return -1;
    rel = script + dl + 1;
    if (rel[0] == '\0')
        return -1;
    if (snprintf(out, outsz, "%s", rel) >= (int)outsz)
        return -1;
    /* 纵深防御：app_ffi 已做过防穿越，这里再拒一次 `..`。 */
    if (strstr(out, "..") != NULL)
        return -1;
    return 0;
}

/* 源相对路径 → 产物相对路径：`.tsx/.ts/.mts/.cts` 扩展名换成 `.js`；
 * 无扩展名（app_ffi 对目录请求回落 index.tsx，通常不会出现）就追加 `.js`； */
static int map_to_js(const char *rel, char *out, size_t outsz)
{
    static const char *const src_exts[] = {".tsx", ".mts", ".cts", ".ts"};
    size_t n = strlen(rel);
    size_t i;

    for (i = 0; i < sizeof(src_exts) / sizeof(src_exts[0]); i++) {
        size_t el = strlen(src_exts[i]);
        if (n > el && strcmp(rel + n - el, src_exts[i]) == 0) {
            size_t base = n - el;
            if (base + 3 + 1 > outsz)
                return -1;
            memcpy(out, rel, base);
            memcpy(out + base, ".js", 4); /* 含 NUL */
            return 0;
        }
    }
    if (n + 3 + 1 > outsz)
        return -1;
    snprintf(out, outsz, "%s.js", rel);
    return 0;
}

static int serve_product(const char *script, const char *docroot, AppEngineResult *out)
{
    char pathbuf[1024];
    char rel[1024];
    char jsrel[1024];
    char prod[2048];
    const char *use;
    struct stat st;
    FILE *f;
    char *buf;
    size_t len;
    int n;

    use = resolve_script(script, docroot, pathbuf, sizeof(pathbuf));
    if (use == NULL)
        return tsx_fail(out,
                        "tsx: 未找到 TypeScript 源（script=%s docroot=%s，尝试过 "
                        "index.tsx / index.ts）",
                        script != NULL ? script : "(null)",
                        docroot != NULL ? docroot : "(null)");
    if (rel_under_docroot(use, docroot, rel, sizeof(rel)) != 0)
        return tsx_fail(out, "tsx: 源路径不在 docroot 下（script=%s docroot=%s）", use,
                        docroot != NULL ? docroot : "(null)");
    if (map_to_js(rel, jsrel, sizeof(jsrel)) != 0)
        return tsx_fail(out, "tsx: 产物路径过长（%s）", rel);

    n = snprintf(prod, sizeof(prod), "%s/dist/%s", docroot, jsrel);
    if (n < 0 || (size_t)n >= sizeof(prod))
        return tsx_fail(out, "tsx: 产物路径过长（%s）", jsrel);

    if (stat(prod, &st) != 0 || !S_ISREG(st.st_mode))
        return tsx_fail(out,
                        "tsx: 编译产物不存在（%s）。TSX 编译/监听由内置管线负责："
                        "先用 HTTP/1.1 请求应用根（或开启 watch = true）触发编译后重试；"
                        "产物默认写在 <docroot>/dist/ 下",
                        prod);
    if (st.st_size < 0 || (unsigned long long)st.st_size > TSX_MAX_PRODUCT)
        return tsx_fail(out, "tsx: 产物过大（%lld 字节，上限 %lu）", (long long)st.st_size,
                        (unsigned long)TSX_MAX_PRODUCT);

    len = (size_t)st.st_size;
    buf = (char *)malloc(len + 1);
    if (buf == NULL)
        return tsx_fail(out, "tsx: 产物内存分配失败（%lu 字节）", (unsigned long)len);
    f = fopen(prod, "rb");
    if (f == NULL) {
        free(buf);
        return tsx_fail(out, "tsx: 打开产物失败（%s: %s）", prod, strerror(errno));
    }
    if (len > 0 && fread(buf, 1, len, f) != len) {
        fclose(f);
        free(buf);
        return tsx_fail(out, "tsx: 读取产物失败（%s）", prod);
    }
    fclose(f);
    buf[len] = '\0';

    if (appengine_result_alloc(out) != 0) {
        free(buf);
        return -1;
    }
    out->status = 200;
    if (appengine_result_set_headers(out,
                                     "Content-Type: text/javascript; charset=utf-8\r\n"
                                     "Cache-Control: no-cache\r\n") != 0
        || appengine_result_set_body(out, buf, len) != 0) {
        free(buf);
        return -1;
    }
    free(buf);
    return 0;
}

int appengine_init(const char *engine, const char *lib_hint)
{
    (void)engine;
    (void)lib_hint;
    g_inited = 1;
    fprintf(stderr,
            "libapp_tsx: 只服务 <docroot>/dist 下由 src/server/apps/tsx.rs 编译管线"
            "（一键编译 + watch，支持 esbuild/tsc/swc）产出的 JS，不按请求 spawn 编译器\n");
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
    (void)method;
    (void)path;
    (void)query;
    (void)content_type;
    (void)body;
    (void)body_len;
    (void)remote;
    (void)server_name;
    (void)server_port;
    (void)extra;
    (void)headers;

    if (!g_inited || out == NULL)
        return -1;
    return serve_product(script, docroot, out);
}

void appengine_shutdown(void)
{
    g_inited = 0;
}
