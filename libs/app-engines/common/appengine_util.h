#ifndef APPENGINE_UTIL_H
#define APPENGINE_UTIL_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Join docroot + rel path into out (NUL-terminated). Returns 0 on success. */
int appengine_join_path(char *out, size_t out_sz, const char *docroot, const char *rel);

/* True when path is a readable regular file. */
int appengine_file_readable(const char *path);

/* Resolve script: explicit script if readable, else docroot/index.<ext>. */
int appengine_resolve_script(const char *script, const char *docroot, const char *index_name,
                             char *out, size_t out_sz);

/* Strip leading slashes from URI path for docroot join. */
const char *appengine_rel_path(const char *path);

#ifdef __cplusplus
}
#endif

#endif /* APPENGINE_UTIL_H */
