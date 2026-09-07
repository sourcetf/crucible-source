/* Minimal PEM → DER (base64 body) for NSS / TomCrypt shims.
 * All scans are length-bounded — never strstr() on non-NUL Rust buffers.
 */

#include "pem_util.h"

#include <stdlib.h>
#include <string.h>

static int b64_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static uint8_t *b64_decode(const char *in, size_t in_len, size_t *out_len) {
    size_t cap = (in_len / 4) * 3 + 4;
    uint8_t *out = (uint8_t *)malloc(cap ? cap : 1);
    if (!out) {
        return NULL;
    }
    size_t o = 0;
    int acc = 0;
    int bits = 0;
    for (size_t i = 0; i < in_len; i++) {
        char c = in[i];
        if (c == '=' || c == '\r' || c == '\n' || c == ' ' || c == '\t') {
            continue;
        }
        int v = b64_val(c);
        if (v < 0) {
            continue;
        }
        acc = (acc << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[o++] = (uint8_t)((acc >> bits) & 0xff);
        }
    }
    *out_len = o;
    return out;
}

static const char *memfind(const char *hay, size_t hay_len, const char *needle) {
    size_t nlen = strlen(needle);
    if (nlen == 0 || hay_len < nlen) {
        return NULL;
    }
    for (size_t i = 0; i + nlen <= hay_len; i++) {
        if (memcmp(hay + i, needle, nlen) == 0) {
            return hay + i;
        }
    }
    return NULL;
}

uint8_t *crucible_pem_to_der(const char *pem, size_t pem_len, size_t *der_len_out) {
    if (!pem || !der_len_out || pem_len == 0) {
        return NULL;
    }
    const char *begin = memfind(pem, pem_len, "-----BEGIN");
    if (!begin) {
        /* Assume already DER. */
        uint8_t *copy = (uint8_t *)malloc(pem_len);
        if (!copy) {
            return NULL;
        }
        memcpy(copy, pem, pem_len);
        *der_len_out = pem_len;
        return copy;
    }
    size_t begin_off = (size_t)(begin - pem);
    size_t rem = pem_len - begin_off;
    const char *hdr_dash = memfind(begin, rem, "-----");
    if (!hdr_dash) {
        return NULL;
    }
    /* First "-----" is start of BEGIN line; find end of header line (second -----). */
    size_t after_first = (size_t)(hdr_dash - begin) + 5;
    if (after_first >= rem) {
        return NULL;
    }
    const char *hdr_end = memfind(begin + after_first, rem - after_first, "-----");
    if (!hdr_end) {
        return NULL;
    }
    const char *body = hdr_end + 5;
    while (body < pem + pem_len && (*body == '\r' || *body == '\n')) {
        body++;
    }
    size_t body_off = (size_t)(body - pem);
    if (body_off >= pem_len) {
        return NULL;
    }
    const char *end = memfind(body, pem_len - body_off, "-----END");
    if (!end) {
        return NULL;
    }
    return b64_decode(body, (size_t)(end - body), der_len_out);
}

void crucible_pem_free(uint8_t *der) {
    free(der);
}

/* Encode short DER length (<128 or up to 2-byte long form). */
static size_t der_len_bytes(size_t n, uint8_t out[3]) {
    if (n < 0x80) {
        out[0] = (uint8_t)n;
        return 1;
    }
    if (n <= 0xff) {
        out[0] = 0x81;
        out[1] = (uint8_t)n;
        return 2;
    }
    out[0] = 0x82;
    out[1] = (uint8_t)((n >> 8) & 0xff);
    out[2] = (uint8_t)(n & 0xff);
    return 3;
}

int crucible_rsa_pkcs1_to_pkcs8(const uint8_t *pkcs1, size_t pkcs1_len,
                                uint8_t **out, size_t *out_len) {
    if (!pkcs1 || !out || !out_len || pkcs1_len < 2) {
        return -1;
    }
    *out = NULL;
    *out_len = 0;

    if (pkcs1[0] == 0x30) {
        const uint8_t oid[] = {0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01};
        for (size_t i = 0; i + sizeof(oid) < pkcs1_len && i < 64; i++) {
            if (memcmp(pkcs1 + i, oid, sizeof(oid)) == 0) {
                return 1; /* already PKCS#8 */
            }
        }
    }

    static const uint8_t algid[] = {
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00};

    uint8_t oct_len[3];
    size_t oct_len_n = der_len_bytes(pkcs1_len, oct_len);
    size_t oct_total = 1 + oct_len_n + pkcs1_len;

    static const uint8_t ver[] = {0x02, 0x01, 0x00};
    size_t seq_content = sizeof(ver) + sizeof(algid) + oct_total;
    uint8_t seq_len[3];
    size_t seq_len_n = der_len_bytes(seq_content, seq_len);
    size_t total = 1 + seq_len_n + seq_content;

    uint8_t *buf = (uint8_t *)malloc(total);
    if (!buf) {
        return -1;
    }
    size_t o = 0;
    buf[o++] = 0x30;
    memcpy(buf + o, seq_len, seq_len_n);
    o += seq_len_n;
    memcpy(buf + o, ver, sizeof(ver));
    o += sizeof(ver);
    memcpy(buf + o, algid, sizeof(algid));
    o += sizeof(algid);
    buf[o++] = 0x04;
    memcpy(buf + o, oct_len, oct_len_n);
    o += oct_len_n;
    memcpy(buf + o, pkcs1, pkcs1_len);
    o += pkcs1_len;

    *out = buf;
    *out_len = o;
    return 0;
}
