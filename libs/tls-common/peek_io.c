/* peek_io — serve peek buffer before blocking socket reads (NSS/TomCrypt handshakes). */

#include "peek_io.h"

#include <string.h>
#include <unistd.h>

static ssize_t peek_read(void *ctx, void *buf, size_t len) {
    struct peek_state *st = (struct peek_state *)ctx;
    if (st->peek_off < st->peek_len) {
        size_t n = st->peek_len - st->peek_off;
        if (n > len) {
            n = len;
        }
        memcpy(buf, st->peek + st->peek_off, n);
        st->peek_off += n;
        return (ssize_t)n;
    }
    return read(st->fd, buf, len);
}

static ssize_t peek_write(void *ctx, const void *buf, size_t len) {
    struct peek_state *st = (struct peek_state *)ctx;
    return write(st->fd, buf, len);
}

int peek_io_init(struct peek_io *io, int fd, const uint8_t *peek, size_t peek_len) {
    if (!io) {
        return -1;
    }
    io->state.fd = fd;
    io->state.peek = peek;
    io->state.peek_len = peek_len;
    io->state.peek_off = 0;
    io->read_fn = peek_read;
    io->write_fn = peek_write;
    io->ctx = &io->state;
    return 0;
}
