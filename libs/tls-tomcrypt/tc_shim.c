/* libtomcrypt SSLv2 server — pure SSLv2 ClientHello records (version 0x0002).
 *
 * This is the oldest compatibility stack. NSS handles SSLv3 / IE6 v2-compatible
 * hellos; BoringSSL handles TLS 1.2/1.3 + ECH + PQC. Do not collapse these paths.
 *
 * Relay fd peer must be bridged to TCP; peek already on relay peer.
 */

#include "../tls-common/peek_io.h"
#include "../tls-common/pem_util.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef CRUCIBLE_HAVE_TOMCRYPT
/* Force ARGTYPE=2 for this TU so any LTC_ARGCHK macro expansion returns errors
 * instead of abort(). The linked libtomcrypt.a must also be built with ARGTYPE=2
 * (see scripts/build_libtomcrypt.sh / build.rs). Incomplete SSLv2 probes must
 * never kill the webserver process. */
#ifdef ARGTYPE
#undef ARGTYPE
#endif
#define ARGTYPE 2
#include <tomcrypt.h>
/* LibTomMath descriptor — required before rsa_import / mp ops. */
extern const ltc_math_descriptor ltm_desc;
#endif

typedef struct crucible_tomcrypt_conn {
    int fd;
    struct peek_io io;
#ifdef CRUCIBLE_HAVE_TOMCRYPT
    rsa_key rsa;
    int rsa_ready;
    uint8_t master_key[16];
    uint8_t server_write_key[16];
    uint8_t client_write_key[16];
    rc4_state rc4_read;
    rc4_state rc4_write;
    int rc4_ready;
    int handshake_done;
    uint8_t challenge[16];
    size_t challenge_len;
    uint8_t conn_id[16];
    size_t conn_id_len;
#endif
} crucible_tomcrypt_conn;

void crucible_tomcrypt_free(crucible_tomcrypt_conn *c);

static int send_all(int fd, const uint8_t *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, buf + off, len - off);
        if (n <= 0) {
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

static int read_exact(struct peek_io *io, uint8_t *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = io->read_fn(io->ctx, buf + off, len - off);
        if (n <= 0) {
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

#ifdef CRUCIBLE_HAVE_TOMCRYPT
static int load_rsa_from_pem(crucible_tomcrypt_conn *c, const char *key_pem, size_t key_len) {
    if (!c || !key_pem || key_len == 0) {
        return -1;
    }
    size_t der_len = 0;
    uint8_t *der = crucible_pem_to_der(key_pem, key_len, &der_len);
    if (!der || der_len == 0) {
        return -1;
    }
    int err = rsa_import(der, (unsigned long)der_len, &c->rsa);
    if (err != CRYPT_OK) {
        /* Try PKCS#8 wrapping then import again (some builds only take PKCS#1). */
        uint8_t *pkcs8 = NULL;
        size_t pkcs8_len = 0;
        if (crucible_rsa_pkcs1_to_pkcs8(der, der_len, &pkcs8, &pkcs8_len) == 0 && pkcs8) {
            err = rsa_import(pkcs8, (unsigned long)pkcs8_len, &c->rsa);
            crucible_pem_free(pkcs8);
        }
    }
    crucible_pem_free(der);
    if (err != CRYPT_OK) {
        return -1;
    }
    /* Sanity: modulus size must be in a plausible RSA range for CMK decrypt. */
    {
        int sz = rsa_get_size(&c->rsa);
        if (sz <= 0 || sz > 512) {
            rsa_free(&c->rsa);
            return -1;
        }
    }
    c->rsa_ready = 1;
    return 0;
}

/* SSLv2 key material: MD5(master + "0" + challenge + conn_id) ||
 *                     MD5(master + "1" + challenge + conn_id) ... */
static int sslv2_derive_keys(crucible_tomcrypt_conn *c) {
    uint8_t material[32];
    for (int i = 0; i < 2; i++) {
        hash_state md5;
        uint8_t buf[128];
        size_t n = 0;
        memcpy(buf + n, c->master_key, 16);
        n += 16;
        buf[n++] = (uint8_t)('0' + i);
        memcpy(buf + n, c->challenge, c->challenge_len);
        n += c->challenge_len;
        memcpy(buf + n, c->conn_id, c->conn_id_len);
        n += c->conn_id_len;
        if (md5_init(&md5) != CRYPT_OK || md5_process(&md5, buf, (unsigned long)n) != CRYPT_OK ||
            md5_done(&md5, material + (size_t)i * 16) != CRYPT_OK) {
            return -1;
        }
    }
    /* RC4_128_WITH_MD5: client-write = first 16, server-write = next 16. */
    memcpy(c->client_write_key, material, 16);
    memcpy(c->server_write_key, material + 16, 16);
    if (rc4_stream_setup(&c->rc4_read, c->client_write_key, 16) != CRYPT_OK) {
        return -1;
    }
    if (rc4_stream_setup(&c->rc4_write, c->server_write_key, 16) != CRYPT_OK) {
        return -1;
    }
    c->rc4_ready = 1;
    return 0;
}

static int sslv2_send_server_hello(crucible_tomcrypt_conn *c, const uint8_t *cert_der, size_t cert_len) {
    /* Minimal SERVER-HELLO offering RC4_128_WITH_MD5 (cipher 0x010080). */
    uint8_t body[64];
    size_t o = 0;
    body[o++] = 0x04; /* SERVER-HELLO */
    body[o++] = 0x00; /* session-id-hit */
    body[o++] = 0x01; /* certificate-type = x.509 */
    body[o++] = 0x00;
    body[o++] = 0x02; /* server-version SSL 2.0 */
    body[o++] = (uint8_t)((cert_len >> 8) & 0xff);
    body[o++] = (uint8_t)(cert_len & 0xff);
    body[o++] = 0x00;
    body[o++] = 0x03; /* cipher-specs-length = 3 */
    body[o++] = 0x00;
    body[o++] = 0x10; /* connection-id-length = 16 */

    size_t rec_len = o + cert_len + 3 + 16;
    uint8_t hdr[2] = {(uint8_t)(0x80 | ((rec_len >> 8) & 0x7f)), (uint8_t)(rec_len & 0xff)};
    if (send_all(c->fd, hdr, 2) != 0 || send_all(c->fd, body, o) != 0) {
        return -1;
    }
    if (cert_len && send_all(c->fd, cert_der, cert_len) != 0) {
        return -1;
    }
    /* cipher-spec RC4_128_WITH_MD5 = 0x01 0x00 0x80 */
    uint8_t cipher[3] = {0x01, 0x00, 0x80};
    if (send_all(c->fd, cipher, 3) != 0) {
        return -1;
    }
    /* connection-id */
    for (size_t i = 0; i < 16; i++) {
        c->conn_id[i] = (uint8_t)(0xA0 + i);
    }
    c->conn_id_len = 16;
    return send_all(c->fd, c->conn_id, 16);
}
#endif

int crucible_tomcrypt_init(void) {
#ifdef CRUCIBLE_HAVE_TOMCRYPT
    static int ready = 0;
    if (ready) {
        return 0;
    }
    /* Without this, rsa_import hits LTC_ARGCHK(ltc_mp.name != NULL) and aborts the process. */
    ltc_mp = ltm_desc;
    if (ltc_mp.name == NULL) {
        return -1;
    }
    if (register_hash(&md5_desc) == -1) {
        return -1;
    }
    ready = 1;
#endif
    return 0;
}

crucible_tomcrypt_conn *crucible_tomcrypt_accept(int relay_fd, const uint8_t *peek, size_t peek_len,
                                               const char *cert_pem, size_t cert_len,
                                               const char *key_pem, size_t key_len) {
    /* Never abort: all failure paths return NULL after free. */
    if (relay_fd < 0 || !cert_pem || cert_len == 0 || !key_pem || key_len == 0) {
        return NULL;
    }
    if (crucible_tomcrypt_init() != 0) {
        return NULL;
    }

    crucible_tomcrypt_conn *c = (crucible_tomcrypt_conn *)calloc(1, sizeof(crucible_tomcrypt_conn));
    if (!c) {
        return NULL;
    }
    c->fd = relay_fd;
    /* ClientHello is parsed from `peek` only. Do NOT put it in peek_io — otherwise
     * CMK reads re-consume the hello and can feed garbage into RSA (LTC_ARGCHK abort). */
    if (peek_io_init(&c->io, relay_fd, NULL, 0) != 0) {
        free(c);
        return NULL;
    }

    if (!peek || peek_len < 7 || !(peek[0] & 0x80) || peek[2] != 0x01) {
        crucible_tomcrypt_free(c);
        return NULL;
    }

#ifdef CRUCIBLE_HAVE_TOMCRYPT
    /* CLIENT-HELLO version must be SSL 2.0 (0x0002). IE6 v2-compatible → NSS. */
    if (!(peek[3] == 0x00 && peek[4] == 0x02)) {
        crucible_tomcrypt_free(c);
        return NULL;
    }

    /* SSLv2 CLIENT-HELLO: type(1) ver(2) cipher_len(2) session_len(2) challenge_len(2) ...
     * Reject truncated/probe packets before any RSA work (avoids LTC_ARGCHK abort). */
    if (peek_len < 11) {
        crucible_tomcrypt_free(c);
        return NULL;
    }
    {
        size_t cipher_len = ((size_t)peek[5] << 8) | (size_t)peek[6];
        size_t session_len = ((size_t)peek[7] << 8) | (size_t)peek[8];
        size_t challenge_len = ((size_t)peek[9] << 8) | (size_t)peek[10];
        size_t need = 11 + cipher_len + session_len + challenge_len;
        if (challenge_len == 0 || challenge_len > 32 || cipher_len > 256 || session_len > 256
            || need > peek_len || need < 11) {
            /* Incomplete ClientHello (acceptance probe) — soft reject, no abort. */
            crucible_tomcrypt_free(c);
            return NULL;
        }
        size_t ch_off = 11 + cipher_len + session_len;
        if (ch_off + challenge_len > peek_len) {
            crucible_tomcrypt_free(c);
            return NULL;
        }
        size_t copy = challenge_len < sizeof(c->challenge) ? challenge_len : sizeof(c->challenge);
        memcpy(c->challenge, peek + ch_off, copy);
        c->challenge_len = copy;
    }

    if (load_rsa_from_pem(c, key_pem, key_len) != 0) {
        crucible_tomcrypt_free(c);
        return NULL;
    }

    size_t cert_der_len = 0;
    uint8_t *cert_der = crucible_pem_to_der(cert_pem, cert_len, &cert_der_len);
    if (!cert_der || cert_der_len == 0) {
        if (cert_der) {
            crucible_pem_free(cert_der);
        }
        crucible_tomcrypt_free(c);
        return NULL;
    }

    if (sslv2_send_server_hello(c, cert_der, cert_der_len) != 0) {
        crucible_pem_free(cert_der);
        crucible_tomcrypt_free(c);
        return NULL;
    }
    crucible_pem_free(cert_der);

    /* CLIENT-MASTER-KEY */
    uint8_t cmk_hdr[2];
    if (read_exact(&c->io, cmk_hdr, 2) != 0) {
        crucible_tomcrypt_free(c);
        return NULL;
    }
    size_t rec_len = ((cmk_hdr[0] & 0x7f) << 8) | cmk_hdr[1];
    if (rec_len < 5 || rec_len > 512) {
        crucible_tomcrypt_free(c);
        return NULL;
    }
    uint8_t rec[512];
    if (read_exact(&c->io, rec, rec_len) != 0) {
        crucible_tomcrypt_free(c);
        return NULL;
    }
    if (rec[0] != 0x02) { /* CLIENT-MASTER-KEY */
        crucible_tomcrypt_free(c);
        return NULL;
    }

    uint8_t clear_key[16];
    uint8_t enc_key[512]; /* up to 4096-bit RSA modulus */
    unsigned long enc_len = 0;
    size_t off = 1;
    /* cipher-spec (3) */
    if (off + 3 > rec_len) {
        crucible_tomcrypt_free(c);
        return NULL;
    }
    off += 3;
    if (off >= rec_len) {
        crucible_tomcrypt_free(c);
        return NULL;
    }
    uint8_t clear_len = rec[off++];
    /* RC4_128 master is 16 bytes; clear portion must leave room for encrypted secret. */
    if (clear_len >= 16 || off + clear_len + 2 > rec_len) {
        crucible_tomcrypt_free(c);
        return NULL;
    }
    memcpy(clear_key, rec + off, clear_len);
    off += clear_len;
    uint16_t enc_key_len = (uint16_t)((rec[off] << 8) | rec[off + 1]);
    off += 2;
    /* Validate CMK ciphertext length against RSA modulus before decrypt.
     * Bad lengths historically tripped LTC_ARGCHK → abort() on ARGTYPE=0 builds. */
    {
        int rsa_bytes = rsa_get_size(&c->rsa);
        if (rsa_bytes <= 0 || rsa_bytes > (int)sizeof(enc_key)) {
            crucible_tomcrypt_free(c);
            return NULL;
        }
        if (enc_key_len == 0 || (int)enc_key_len != rsa_bytes
            || off + enc_key_len > rec_len || enc_key_len > sizeof(enc_key)) {
            crucible_tomcrypt_free(c);
            return NULL;
        }
    }
    memcpy(enc_key, rec + off, enc_key_len);
    enc_len = enc_key_len;

    uint8_t decrypted[512];
    unsigned long dec_len = sizeof(decrypted);
    int stat = 0;
    int err = rsa_decrypt_key_ex(enc_key, enc_len, decrypted, &dec_len, NULL, 0, 0,
                                 LTC_PKCS_1_V1_5, &stat, &c->rsa);
    if (err != CRYPT_OK || stat != 1 || dec_len == 0 || dec_len > sizeof(decrypted)
        || dec_len + (size_t)clear_len < 16) {
        crucible_tomcrypt_free(c);
        return NULL;
    }
    memset(c->master_key, 0, sizeof(c->master_key));
    memcpy(c->master_key, clear_key, clear_len);
    {
        size_t room = 16 - (size_t)clear_len;
        size_t take = dec_len < room ? dec_len : room;
        memcpy(c->master_key + clear_len, decrypted, take);
    }
    if (sslv2_derive_keys(c) != 0) {
        crucible_tomcrypt_free(c);
        return NULL;
    }
    c->handshake_done = 1;
    return c;
#else
    (void)cert_pem;
    (void)cert_len;
    (void)key_pem;
    (void)key_len;
    crucible_tomcrypt_free(c);
    return NULL;
#endif
}

ssize_t crucible_tomcrypt_read(crucible_tomcrypt_conn *c, void *buf, size_t len) {
    if (!c) {
        return -1;
    }
#ifdef CRUCIBLE_HAVE_TOMCRYPT
    if (!c->handshake_done || !c->rc4_ready) {
        return -1;
    }
    uint8_t hdr[2];
    if (read_exact(&c->io, hdr, 2) != 0) {
        return -1;
    }
    size_t rec_len = ((hdr[0] & 0x7f) << 8) | hdr[1];
    if (rec_len == 0 || rec_len > 16384) {
        return -1;
    }
    uint8_t *tmp = (uint8_t *)malloc(rec_len);
    if (!tmp) {
        return -1;
    }
    if (read_exact(&c->io, tmp, rec_len) != 0) {
        free(tmp);
        return -1;
    }
    /* Decrypt in place with client-write RC4; strip 16-byte MD5 MAC if present. */
    if (rc4_stream_crypt(&c->rc4_read, tmp, rec_len, tmp) != CRYPT_OK) {
        free(tmp);
        return -1;
    }
    size_t payload = rec_len;
    if (payload >= 16) {
        payload -= 16; /* MD5 MAC trailer */
    }
    if (payload > len) {
        payload = len;
    }
    memcpy(buf, tmp, payload);
    free(tmp);
    return (ssize_t)payload;
#else
    return c->io.read_fn(c->io.ctx, buf, len);
#endif
}

ssize_t crucible_tomcrypt_write(crucible_tomcrypt_conn *c, const void *buf, size_t len) {
    if (!c) {
        return -1;
    }
#ifdef CRUCIBLE_HAVE_TOMCRYPT
    if (!c->handshake_done || !c->rc4_ready) {
        return -1;
    }
    if (len == 0 || len > 16384) {
        return -1;
    }
    size_t rec_len = len + 16;
    uint8_t *tmp = (uint8_t *)malloc(rec_len);
    if (!tmp) {
        return -1;
    }
    memcpy(tmp, buf, len);
    /* MAC = MD5(server_write_key[0..15] || data) — simplified SSLv2 MAC. */
    hash_state md5;
    uint8_t *mac_in = (uint8_t *)malloc(16 + len);
    if (!mac_in) {
        free(tmp);
        return -1;
    }
    memcpy(mac_in, c->server_write_key, 16);
    memcpy(mac_in + 16, buf, len);
    if (md5_init(&md5) != CRYPT_OK
        || md5_process(&md5, mac_in, (unsigned long)(16 + len)) != CRYPT_OK
        || md5_done(&md5, tmp + len) != CRYPT_OK) {
        free(mac_in);
        free(tmp);
        return -1;
    }
    free(mac_in);
    if (rc4_stream_crypt(&c->rc4_write, tmp, rec_len, tmp) != CRYPT_OK) {
        free(tmp);
        return -1;
    }
    uint8_t hdr[2] = {(uint8_t)(0x80 | ((rec_len >> 8) & 0x7f)), (uint8_t)(rec_len & 0xff)};
    int ok = send_all(c->fd, hdr, 2) == 0 && send_all(c->fd, tmp, rec_len) == 0;
    free(tmp);
    return ok ? (ssize_t)len : -1;
#else
    return c->io.write_fn(c->io.ctx, buf, len);
#endif
}

void crucible_tomcrypt_free(crucible_tomcrypt_conn *c) {
    if (!c) {
        return;
    }
#ifdef CRUCIBLE_HAVE_TOMCRYPT
    if (c->rsa_ready) {
        rsa_free(&c->rsa);
    }
    if (c->rc4_ready) {
        rc4_stream_done(&c->rc4_read);
        rc4_stream_done(&c->rc4_write);
    }
#endif
    if (c->fd >= 0) {
        close(c->fd);
        c->fd = -1;
    }
    free(c);
}
