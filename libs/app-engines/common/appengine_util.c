#include "appengine_util.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

const char *appengine_rel_path(const char *path)
{
    if (!path)
        return "";
    while (*path == '/')
        path++;
    return path;
}

int appengine_join_path(char *out, size_t out_sz, const char *docroot, const char *rel)
{
    const char *base;
    const char *r;
    int n;

    if (!out || out_sz == 0)
        return -1;
    base = docroot && docroot[0] ? docroot : ".";
    r = appengine_rel_path(rel);
    if (r[0] == '\0') {
        n = snprintf(out, out_sz, "%s", base);
    } else {
        n = snprintf(out, out_sz, "%s/%s", base, r);
    }
    return (n > 0 && (size_t)n < out_sz) ? 0 : -1;
}

int appengine_file_readable(const char *path)
{
    struct stat st;
    if (!path || path[0] == '\0')
        return 0;
    if (stat(path, &st) != 0)
        return 0;
    return S_ISREG(st.st_mode) ? 1 : 0;
}

int appengine_resolve_script(const char *script, const char *docroot, const char *index_name,
                             char *out, size_t out_sz)
{
    if (script && script[0] && appengine_file_readable(script)) {
        snprintf(out, out_sz, "%s", script);
        return 0;
    }
    if (appengine_join_path(out, out_sz, docroot, index_name ? index_name : "index") != 0)
        return -1;
    return appengine_file_readable(out) ? 0 : -1;
}
