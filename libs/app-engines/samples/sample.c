#include "appengine.h"
#include <stdio.h>

static int sample_init(void *ctx) {
    (void)ctx;
    return 0;
}

static int sample_handle(void *ctx, const char *path) {
    (void)ctx;
    printf("handle: %s\n", path);
    return 0;
}

static void sample_shutdown(void *ctx) {
    (void)ctx;
}

static AppEngine engine = {
    .name = "sample",
    .init = sample_init,
    .handle = sample_handle,
    .shutdown = sample_shutdown,
};

AppEngine *appengine_register(void) {
    return &engine;
}
