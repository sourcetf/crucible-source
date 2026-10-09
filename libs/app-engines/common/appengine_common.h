#ifndef APPENGINE_COMMON_H
#define APPENGINE_COMMON_H

#include <stddef.h>
#include "appengine.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Allocate and zero a result; returns 0 on success. */
int appengine_result_alloc(AppEngineResult *out);

/* Set body (copies); returns 0 on success. */
int appengine_result_set_body(AppEngineResult *out, const void *data, size_t len);

/* Set a single Content-Type style header block; returns 0 on success. */
int appengine_result_set_headers(AppEngineResult *out, const char *headers);

/* Set error string (copies); returns 0 on success. */
int appengine_result_set_error(AppEngineResult *out, const char *msg);

/* strdup-like helper that returns NULL on failure. */
char *appengine_strdup(const char *s);

/* Fill a simple 200 text/plain hello response. */
int appengine_fill_hello(AppEngineResult *out, const char *engine_name, const char *path);

/* P1-1: apply env vars carried in `extra` (JSON {"engine":...,"env":{...}}) to
 * the process environment via setenv(). Legacy non-JSON input (plain engine
 * name) is a no-op. Returns 0 on success/no-op, -1 on bad arguments. */
int appengine_apply_extra(const char *extra);

/* Same parse as appengine_apply_extra, but hands each (key,value) to `cb`
 * instead of calling setenv(). Used by engines that must not touch the process
 * env (cgi builds its child envp directly). Returns 0 on success/no-op. */
int appengine_extra_env_foreach(const char *extra,
                                int (*cb)(void *ctx, const char *k, const char *v),
                                void *ctx);

/* The base-env block set via appengine_set_base_env(), or NULL if unset. */
const char *appengine_base_env_block(void);

/* ---------------------------------------------------------- request headers ---
 * ABI 请求头块（appengine_execute 的 headers 参数）：
 *   每行 `Name: Value`，行间 `\r\n`，可为 NULL/空。
 * appengine_headers_foreach 逐条解析**有效**头并回调：
 *   - 空行 / 无冒号行 / 名字含非法字符 / 名或值超长的行直接跳过（防御）；
 *   - Content-Type / Content-Length 不回调：它们有独立形参，避免覆盖；
 *   - name/value 指向块内，**不保证 NUL 结尾**，仅在回调期间有效。
 * 返回回调过的头条数。cb 返回非 0 立即停止并返回该值。
 */
int appengine_headers_foreach(
    const char *headers,
    int (*cb)(void *ctx, const char *name, size_t name_len,
              const char *value, size_t value_len),
    void *ctx);

/* CGI 环境键：`HTTP_` + 名字大写 + `-`→`_`（RFC 3875 惯例）。
 * out 需 >= name_len + 6 字节；返回写入的键长（不含 NUL），0 = 参数非法。 */
size_t appengine_cgi_http_key(char *out, size_t out_sz, const char *name, size_t name_len);

#ifdef __cplusplus
}
#endif

#endif /* APPENGINE_COMMON_H */
