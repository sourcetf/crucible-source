/*
 * Crucible app-engine ABI.
 * Loaded via dlopen(RTLD_NOW|RTLD_GLOBAL); symbols resolved with dlsym.
 */
#ifndef APPENGINE_H
#define APPENGINE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct AppEngineResult {
    int status;
    char *headers;       /* "Name: value\r\n" pairs, NUL-terminated block */
    size_t headers_len;
    char *body;
    size_t body_len;
    char *error;         /* optional error string; may be NULL */
} AppEngineResult;

/*
 * Initialize the engine.
 * engine: engine slug (e.g. "c", "go", "rust", "lua")
 * lib_hint: optional path hint / script path; may be NULL
 * returns 0 on success, non-zero on failure
 */
int appengine_init(const char *engine, const char *lib_hint);

/*
 * Execute one request. Caller must free *out with appengine_result_free.
 * returns 0 on success (out filled), non-zero on failure
 *
 * headers: request-header block, **one header per line** in the form
 *          `Name: Value`, lines separated by `\r\n`, NUL-terminated; may be
 *          NULL or empty. Names arrive as received (mixed case). Hop-by-hop
 *          headers (Connection/Keep-Alive/TE/Transfer-Encoding/Upgrade/
 *          Trailer/Proxy-*) are already filtered by the host; Content-Type /
 *          Content-Length are NOT repeated here (they have dedicated
 *          parameters). CGI-semantics engines map each header to the
 *          environment as: uppercase the name, replace `-` with `_`, prefix
 *          `HTTP_` (`X-Request-Id: t` -> `HTTP_X_REQUEST_ID=t`).
 *          ASGI (scope["headers"]) / Rack / ngx.req.get_headers() expose the
 *          original lower-case names instead.
 */
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
    AppEngineResult *out);

void appengine_result_free(AppEngineResult *out);

void appengine_shutdown(void);

#ifdef __cplusplus
}
#endif

#endif /* APPENGINE_H */
