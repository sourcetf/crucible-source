/* aspnet-ffi — hostfxr in-process stub (NativeAOT / hostfxr wiring in later pass). */
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT __attribute__((visibility("default")))
#endif

EXPORT int crucible_aspnet_execute(
    const char *method,
    const char *path,
    const char *query,
    char *out,
    size_t out_len)
{
    if (!out || out_len == 0) {
        return -1;
    }
    snprintf(out, out_len,
             "aspnet ffi stub: hostfxr not fully wired method=%s path=%s query=%s\n"
             "build libapp_aspnet.so via scripts/build_aspnet_ffi.sh for appengine ABI\n",
             method ? method : "GET",
             path ? path : "/",
             query ? query : "");
    (void)strlen(out);
    return -1; /* stub: not a success path */
}
