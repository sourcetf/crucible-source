/* Crucible Go shared-memory IPC protocol (Rust + Go must match). */
#ifndef CRUCIBLE_GO_SHM_PROTOCOL_H
#define CRUCIBLE_GO_SHM_PROTOCOL_H

#include <stdint.h>

#define GO_SHM_MAGIC     0x4352474fu /* 'CRGO' */
#define GO_SHM_VERSION   1u
#define GO_SHM_SLOTS     64u
#define GO_SHM_BODY_MAX  65536u
#define GO_SHM_PATH_MAX  512u
#define GO_SHM_METHOD_MAX 16u

enum go_shm_slot_state {
    GO_SHM_IDLE = 0,
    GO_SHM_REQ_READY = 1,
    GO_SHM_RESP_READY = 2,
};

struct go_shm_header {
    uint32_t magic;
    uint32_t version;
    uint32_t slot_count;
    uint32_t slot_stride;
    uint32_t body_cap;
};

struct go_shm_slot {
    uint32_t state;
    uint32_t http_status;
    uint32_t req_body_len;
    uint32_t resp_body_len;
    char method[GO_SHM_METHOD_MAX];
    char path[GO_SHM_PATH_MAX];
    /* followed in mmap layout: req_body[body_cap] + resp_body[body_cap] */
};

#endif
