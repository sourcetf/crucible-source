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

#ifdef __cplusplus
}
#endif

#endif /* APPENGINE_COMMON_H */
