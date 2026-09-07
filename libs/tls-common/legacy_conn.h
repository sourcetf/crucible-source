#ifndef CRUCIBLE_LEGACY_CONN_H
#define CRUCIBLE_LEGACY_CONN_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* Opaque legacy TLS connection (NSS or TomCrypt). */
typedef struct crucible_legacy_conn crucible_legacy_conn;

ssize_t crucible_legacy_read(crucible_legacy_conn *c, void *buf, size_t len);
ssize_t crucible_legacy_write(crucible_legacy_conn *c, const void *buf, size_t len);
void crucible_legacy_shutdown(crucible_legacy_conn *c);
void crucible_legacy_free(crucible_legacy_conn *c);

#endif
