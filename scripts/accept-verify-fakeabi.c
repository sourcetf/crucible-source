/* accept-verify-fakeabi.c — 假应用引擎 .so（工号 1009 / agent-verify4，wave-7）
 *
 * 编译两次（见 accept-verify.sh）：
 *   旧代： gcc -shared -fPIC -DHAVE_ABI=0 -DMARKER_PATH='"<scratch>/abi-old.marker"'
 *   异版： gcc -shared -fPIC -DHAVE_ABI=1 -DABI_REPORT=99 -DMARKER_PATH='"<scratch>/abi-bad.marker"'
 *
 * 目的：黑盒复核 host（src/server/apps/app_ffi.rs 的 ABI 握手）对「陈旧/异版 .so」的处置：
 *   * 缺 `appengine_abi_version`（旧代产物）→ 必须在 dlsym 后、**调用前**拒载（客户端 502）；
 *   * 自报版本 ≠ host 期望（APPENGINE_ABI_VERSION=2）→ 同样拒载。
 * 两类 .so 的 `appengine_execute` 一旦被调用就写 marker 并返回非 0 —— **不 abort**，
 * 这样即使真踩到缺陷（host 错误地调用）也不会把整套验收打断，而 marker 文件就是
 * 「错误调用发生」的铁证。
 */
#include <stddef.h>
#include <stdio.h>

#ifndef MARKER_PATH
#define MARKER_PATH "/tmp/accept-verify-fakeabi.marker"
#endif
#ifndef ABI_REPORT
#define ABI_REPORT 99
#endif

/* 与 include/appengine.h 的 AppEngineResult 同名前向声明即可：本 .so 永不返回 0，
 * host 不会读 out（也不需要真布局）。 */
struct AppEngineResult;

static void mark(const char *what) {
    FILE *f = fopen(MARKER_PATH, "a");
    if (f) {
        fprintf(f, "%s\n", what);
        fclose(f);
    }
}

int appengine_init(const char *engine, const char *lib_hint) {
    (void)engine;
    (void)lib_hint;
    mark("init");
    return 0;
}

int appengine_execute(const char *script, const char *docroot, const char *method,
                      const char *path, const char *query, const char *content_type,
                      const unsigned char *body, size_t body_len, const char *remote,
                      const char *server_name, int server_port, const char *extra,
                      const char *headers, struct AppEngineResult *out) {
    (void)script; (void)docroot; (void)method; (void)path; (void)query;
    (void)content_type; (void)body; (void)body_len; (void)remote; (void)server_name;
    (void)server_port; (void)extra; (void)headers; (void)out;
    mark("execute");   /* 被调用即写 marker（= host 没做 ABI 校验） */
    return 7;
}

void appengine_result_free(struct AppEngineResult *out) { (void)out; }

void appengine_shutdown(void) { mark("shutdown"); }

#if HAVE_ABI
int appengine_abi_version(void) { return ABI_REPORT; }
#endif
