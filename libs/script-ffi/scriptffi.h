#ifndef CRUCIBLE_SCRIPTFFI_H
#define CRUCIBLE_SCRIPTFFI_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int crucible_scriptffi_init(const char *lang);
int crucible_scriptffi_execute(
    const char *lang,
    const char *script_path,
    const char *method,
    const char *path,
    const char *query,
    const char *body,
    size_t body_len,
    char *out,
    size_t out_len);

#ifdef __cplusplus
}
#endif

#endif
