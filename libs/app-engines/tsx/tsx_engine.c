/*
 * TSX/TS app-engine —— 不再每请求 spawn（node/tsx 侧车才是契约路径）。
 *
 * 旧实现：popen("(command -v tsx …) || (command -v npx … && npx --yes tsx …) ||
 * node …")——每请求 spawn 解释器，且把**请求派生的脚本路径**插进 shell 字符串
 * （命令注入面）；失败即 appengine_fill_hello（假成功）。
 *
 * 本项目的 tsx 契约不是"每请求跑解释器"，而是 options_catalog.rs 里写明的
 * "One-click compile + watch deploy"（一键编译 + 监听部署）：TypeScript 由构建/
 * 部署步骤编译一次，产物交给静态文件路径或**常驻 node 侧车**服务。
 *   - Rust 侧入口：src/server/apps/tsx.rs → sidecar_engine::handle_with_fallback
 *     （libapp_tsx.so → sidecar → UDS socket，三者皆无才 502）；
 *   - 本机有 node，但没有 tsx，也没有常量侧车配置。
 *
 * 因此本引擎：不 spawn、不假 hello，返回显式错误并指出应当走哪条路（侧车/编译产物
 * 静态服务）。这里不新增任何协议或产物约定。
 */
#include "appengine.h"
#include "appengine_common.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static int g_inited;

/* 引擎级失败：填 out->error 并返回 -1（app_ffi 会把它变成 502 文本）。 */
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

int appengine_init(const char *engine, const char *lib_hint)
{
    (void)engine;
    (void)lib_hint;
    g_inited = 1;
    fprintf(stderr,
            "libapp_tsx: 本引擎不执行 TypeScript（禁止每请求 spawn）；tsx 应为"
            "『一键编译 + watch 部署』或 node 侧车，见 tsx_engine.c 文件头\n");
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

    (void)method;
    (void)query;
    (void)content_type;
    (void)body;
    (void)body_len;
    (void)remote;
    (void)server_name;
    (void)server_port;
    (void)extra;

    if (!g_inited || out == NULL)
        return -1;

    use = resolve_script(script, docroot, pathbuf, sizeof(pathbuf));
    if (use == NULL)
        return tsx_fail(out,
                        "tsx: 未找到 TypeScript 源（script=%s docroot=%s，尝试过 "
                        "index.tsx / index.ts）",
                        script != NULL ? script : "(null)",
                        docroot != NULL ? docroot : "(null)");
    /*
     * 显式失败：每请求 spawn（node/tsx/npx）被 spec 禁止，且 shell 字符串里插请求
     * 派生路径本身就是命令注入面——两条都已删除。正确路径是"编译一次 + 静态/侧车
     * 常驻服务"。
     */
    return tsx_fail(out,
                    "tsx: 本引擎不按请求执行 TypeScript（%s）。tsx 应用的契约是"
                    "『一键编译 + watch 部署』：编译产物由静态文件路径或常驻 node 侧车"
                    "服务（Rust 侧见 src/server/apps/tsx.rs → sidecar；配置 sidecar/"
                    "socket 后本 .so 不再是唯一路径）。本机有 node 但没有 tsx，"
                    "每请求 spawn tsx/npx/node 被 spec 禁止，故不提供回退",
                    use);
}

void appengine_shutdown(void)
{
    g_inited = 0;
}
