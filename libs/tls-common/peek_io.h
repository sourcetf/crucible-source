#ifndef CRUCIBLE_PEEK_IO_H
#define CRUCIBLE_PEEK_IO_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

struct peek_state {
    int fd;
    const uint8_t *peek;
    size_t peek_len;
    size_t peek_off;
};

struct peek_io {
    struct peek_state state;
    void *ctx;
    ssize_t (*read_fn)(void *ctx, void *buf, size_t len);
    ssize_t (*write_fn)(void *ctx, const void *buf, size_t len);
};

int peek_io_init(struct peek_io *io, int fd, const uint8_t *peek, size_t peek_len);

#endif
