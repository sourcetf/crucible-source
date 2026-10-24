/* libtomcrypt SSLv2 server — pure SSLv2 ClientHello records (version 0x0002).
 *
 * This is the oldest compatibility stack. NSS handles SSLv3 / IE6 v2-compatible
 * hellos; BoringSSL handles TLS 1.2/1.3 + ECH + PQC. Do not collapse these paths.
 *
 * Wire protocol (SSL 2.0, see draft-hickman-netscape-ssl-00 and OpenSSL 1.0.2
 * ssl/s2_*.c — the reference implementation old clients interoperated with):
 *
 *   C -> S  CLIENT-HELLO        (plaintext)
 *   S -> C  SERVER-HELLO        (plaintext: cert + cipher spec + conn-id)
 *   C -> S  CLIENT-MASTER-KEY   (plaintext: 10-byte header + clear/enc/keyarg)
 *   S -> C  SERVER-VERIFY       (encrypted: type 5 + client challenge)
 *   C -> S  CLIENT-FINISHED     (encrypted: type 3 + conn-id echo)
 *   S -> C  SERVER-FINISHED     (encrypted: type 6 + session-id)
 *   < application data (encrypted records, per-direction MD5 MAC + sequence) >
 *
 * Record layer for RC4_128_WITH_MD5 (cipher 0x010080), exactly as OpenSSL:
 *   2-byte header  0x80|len_hi, len_lo           (no padding for stream ciphers)
 *   payload        MD5-MAC(16) || data
 *   MAC            MD5(write_key || data+padding || seq_be32)
 *   sequence       per direction, starts at 0, incremented after every record
 *                  (CLIENT-FINISHED is client seq 0; SERVER-VERIFY is server
 *                  seq 0, SERVER-FINISHED seq 1).
 *
 * The previous shim used a private layout (MAC *after* data, 1-byte clear-key
 * length, no CLIENT-FINISHED/SERVER-VERIFY/SERVER-FINISHED). It only worked
 * against its own probe and could never complete a handshake with a real
 * SSLv2 client. Do not "simplify" this back.
 *
 * Relay fd peer must be bridged to TCP; peek already on relay peer.
 */

#include "../tls-common/peek_io.h"
#include "../tls-common/pem_util.h"

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef CRUCIBLE_HAVE_TOMCRYPT
/* Force ARGTYPE=4 for this TU so LTC_ARGCHK returns CRYPT_INVALID_ARG instead of
 * abort()/continuing. The linked libtomcrypt.a must be built with the same value
 * (see scripts/build_libtomcrypt.sh / build.rs).
 *
 * **ARGTYPE 编号（1.18.2 与 master 一致）**：
 *   0 = crypt_argchk() → abort, 1 = assert(), 2 = 打印 warning 后**继续**,
 *   3 = 空操作, 4 = return CRYPT_INVALID_ARG。
 * 旧代码误用 2：实测 NULL 参数会打印 "warning: ARGCHK failed" 后带着 NULL
 * 指针继续跑 → SIGSEGV（未完成 SSLv2 探针可远程打死 webserver）。必须用 4。 */
#ifdef ARGTYPE
#undef ARGTYPE
#endif
#define ARGTYPE 4
#include <tomcrypt.h>
/* LibTomMath descriptor — required before rsa_import / mp ops. */
extern const ltc_math_descriptor ltm_desc;
#endif

/* SSLv2 message types. */
#define SSL2_MT_CLIENT_HELLO 0x01
#define SSL2_MT_CLIENT_MASTER_KEY 0x02
#define SSL2_MT_CLIENT_FINISHED 0x03
#define SSL2_MT_SERVER_HELLO 0x04
#define SSL2_MT_SERVER_VERIFY 0x05
#define SSL2_MT_SERVER_FINISHED 0x06

#define SSL2_MAC_MD5_SIZE 16
/* 2-byte header: 15-bit length. 3-byte header: 14-bit length + padding byte. */
#define SSL2_MAX_RECORD_2BYTE 0x7FFF
#define SSL2_MAX_RECORD_3BYTE 0x3FFF
#define SSL2_MAX_RECORD SSL2_MAX_RECORD_2BYTE

#define SSL2_CONN_ID_LEN 16
#define SSL2_SESSION_ID_LEN 16
#define SSL2_APP_RECORD_MAX 16384

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
    uint32_t read_seq;
    uint32_t write_seq;
    uint8_t challenge[32];
    size_t challenge_len;
    uint8_t conn_id[16];
    size_t conn_id_len;
    uint8_t session_id[16];
    size_t session_id_len;
    /* Decrypted app-data left over when the caller's buffer is smaller than
     * one record. SSLv2 2-byte-header records can carry up to 32767 bytes and
     * h1 reads in ~16 KiB chunks, so a single-record read could otherwise
     * silently truncate (buffer is sized for the full 2-byte-header maximum). */
    uint8_t pending[SSL2_MAX_RECORD];
    size_t pending_len;
    size_t pending_off;
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
/* /dev/urandom is available on both Linux and OpenBSD. The values are session
 * and connection identifiers, not long-term secrets, but they must not repeat
 * between connections. */
static int random_bytes(uint8_t *buf, size_t len) {
    FILE *f = fopen("/dev/urandom", "rb");
    size_t got = 0;
    if (f) {
        got = fread(buf, 1, len, f);
        fclose(f);
    }
    return got == len ? 0 : -1;
}

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
    /* SSLv2 key schedule (draft-hickman-netscape-ssl-00 §1.2), RC4_128_MD5:
     *   CLIENT-READ-KEY  = MD5(master || "0" || challenge || conn_id)
     *   CLIENT-WRITE-KEY = MD5(master || "1" || challenge || conn_id)
     *   SERVER-READ-KEY  = CLIENT-WRITE-KEY
     *   SERVER-WRITE-KEY = CLIENT-READ-KEY
     * 旧代码把前 16 字节当 client-write（即把 "0"/"1" 用反了）：对端若按规范
     * 用 "1" 加密客户端记录，服务端会用 "0" 解密，第一帧就 MAC/数据全错。
     * 这里按规范取：client_write = "1" 段，server_write = "0" 段。 */
    memcpy(c->client_write_key, material + 16, 16);
    memcpy(c->server_write_key, material, 16);
    if (rc4_stream_setup(&c->rc4_read, c->client_write_key, 16) != CRYPT_OK) {
        return -1;
    }
    if (rc4_stream_setup(&c->rc4_write, c->server_write_key, 16) != CRYPT_OK) {
        return -1;
    }
    c->rc4_ready = 1;
    return 0;
}

/* MD5(key || data(+padding) || seq_be32), the SSLv2 record MAC (OpenSSL
 * ssl2_mac; the 4-byte sequence is part of the MAC old clients compute). */
static int ssl2_record_mac(const uint8_t *key, const uint8_t *data, size_t len,
                           uint32_t seq, uint8_t out[SSL2_MAC_MD5_SIZE]) {
    hash_state md5;
    uint8_t seqbuf[4];
    seqbuf[0] = (uint8_t)(seq >> 24);
    seqbuf[1] = (uint8_t)(seq >> 16);
    seqbuf[2] = (uint8_t)(seq >> 8);
    seqbuf[3] = (uint8_t)seq;
    if (md5_init(&md5) != CRYPT_OK || md5_process(&md5, key, 16) != CRYPT_OK ||
        md5_process(&md5, data, (unsigned long)len) != CRYPT_OK ||
        md5_process(&md5, seqbuf, 4) != CRYPT_OK || md5_done(&md5, out) != CRYPT_OK) {
        return -1;
    }
    return 0;
}

/* Send one SSLv2 record. When `encrypted`, the record payload is
 * MAC(16) || body and the whole payload goes through the server RC4 stream. */
static int ssl2_send_record(crucible_tomcrypt_conn *c, const uint8_t *body, size_t len,
                            int encrypted) {
    uint8_t *payload = NULL;
    size_t payload_len = len;
    if (encrypted) {
        if (len > SSL2_MAX_RECORD_2BYTE - SSL2_MAC_MD5_SIZE) {
            return -1;
        }
        payload_len = SSL2_MAC_MD5_SIZE + len;
        payload = (uint8_t *)malloc(payload_len);
        if (!payload) {
            return -1;
        }
        memcpy(payload + SSL2_MAC_MD5_SIZE, body, len);
        if (ssl2_record_mac(c->server_write_key, body, len, c->write_seq, payload) != 0) {
            free(payload);
            return -1;
        }
        if (rc4_stream_crypt(&c->rc4_write, payload, payload_len, payload) != CRYPT_OK) {
            free(payload);
            return -1;
        }
    } else {
        payload = (uint8_t *)body; /* not owned */
    }
    if (payload_len > SSL2_MAX_RECORD_2BYTE) {
        if (payload != body) {
            free(payload);
        }
        return -1;
    }
    uint8_t hdr[2] = {(uint8_t)(0x80 | ((payload_len >> 8) & 0x7f)),
                      (uint8_t)(payload_len & 0xff)};
    int ok = send_all(c->fd, hdr, 2) == 0 && send_all(c->fd, payload, payload_len) == 0;
    if (encrypted) {
        free(payload);
    }
    if (ok) {
        /* OpenSSL increments the sequence for **every** record it writes,
         * including the plaintext SERVER-HELLO. A client that counts only
         * encrypted records computes a different MAC for SERVER-VERIFY (the
         * first encrypted server record uses seq 1, not 0). */
        c->write_seq++;
    }
    return ok ? 0 : -1;
}

/* Read one SSLv2 record (2- or 3-byte header). Once keys are installed every
 * record is decrypted and its MAC verified with the current read sequence;
 * padding is removed. Returns a malloc'd buffer in *out. */
static int ssl2_recv_record(crucible_tomcrypt_conn *c, uint8_t **out, size_t *out_len) {
    uint8_t hdr[2];
    size_t rec_len;
    size_t padding = 0;
    size_t max_len = SSL2_MAX_RECORD_2BYTE;
    if (read_exact(&c->io, hdr, 2) != 0) {
        return -1;
    }
    if (hdr[0] & 0x80) {
        rec_len = ((size_t)(hdr[0] & 0x7f) << 8) | (size_t)hdr[1];
    } else {
        uint8_t pad_byte;
        if (read_exact(&c->io, &pad_byte, 1) != 0) {
            return -1;
        }
        rec_len = ((size_t)(hdr[0] & 0x3f) << 8) | (size_t)hdr[1];
        padding = pad_byte;
        max_len = SSL2_MAX_RECORD_3BYTE;
    }
    /* The limit depends on the header form: a 2-byte header carries 15 length
     * bits (32767), a 3-byte header only 14 (16383). Using the 3-byte limit
     * for both rejected valid >16 KiB records that OpenSSL clients do send
     * (ssl2_write picks a 2-byte header up to SSL2_MAX_RECORD_LENGTH_2_BYTE_
     * HEADER when the cipher is a stream cipher). */
    if (rec_len == 0 || rec_len > max_len) {
        return -1;
    }
    uint8_t *buf = (uint8_t *)malloc(rec_len);
    if (!buf) {
        return -1;
    }
    if (read_exact(&c->io, buf, rec_len) != 0) {
        free(buf);
        return -1;
    }
    if (c->rc4_ready) {
        if (rec_len < SSL2_MAC_MD5_SIZE + padding) {
            free(buf);
            return -1;
        }
        if (rc4_stream_crypt(&c->rc4_read, buf, rec_len, buf) != CRYPT_OK) {
            free(buf);
            return -1;
        }
        size_t data_len = rec_len - SSL2_MAC_MD5_SIZE - padding;
        uint8_t mac[SSL2_MAC_MD5_SIZE];
        /* MAC covers data + padding, exactly like OpenSSL (ract_data_length
         * includes padding when ssl2_mac() runs). */
        if (ssl2_record_mac(c->client_write_key, buf + SSL2_MAC_MD5_SIZE,
                            data_len + padding, c->read_seq, mac) != 0) {
            free(buf);
            return -1;
        }
        if (memcmp(mac, buf, SSL2_MAC_MD5_SIZE) != 0) {
            free(buf);
            return -1;
        }
        c->read_seq++;
        memmove(buf, buf + SSL2_MAC_MD5_SIZE, data_len);
        *out_len = data_len;
    } else {
        *out_len = rec_len;
        /* Sequence counts every record in each direction (see send path). */
        c->read_seq++;
    }
    *out = buf;
    return 0;
}

static int sslv2_send_server_hello(crucible_tomcrypt_conn *c, const uint8_t *cert_der,
                                   size_t cert_len) {
    /* Minimal SERVER-HELLO offering RC4_128_WITH_MD5 (cipher 0x010080). */
    uint8_t body[64];
    size_t o = 0;
    body[o++] = SSL2_MT_SERVER_HELLO;
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
    if (cert_len > SSL2_MAX_RECORD_2BYTE || rec_len > SSL2_MAX_RECORD_2BYTE) {
        return -1;
    }
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
    if (random_bytes(c->conn_id, sizeof(c->conn_id)) != 0) {
        return -1;
    }
    c->conn_id_len = sizeof(c->conn_id);
    if (random_bytes(c->session_id, sizeof(c->session_id)) != 0) {
        return -1;
    }
    c->session_id_len = sizeof(c->session_id);
    int ok = send_all(c->fd, c->conn_id, c->conn_id_len);
    if (ok == 0) {
        /* Every written record consumes a sequence number (OpenSSL does the
         * same for cleartext records); SERVER-VERIFY is therefore seq 1. */
        c->write_seq++;
    }
    return ok;
}

/* CLIENT-MASTER-KEY, SSLv2 wire layout (OpenSSL s2_srvr.c):
 *   type(1) cipher(3) clear_len(2) enc_len(2) key_arg_len(2)
 *   clear_key(clear_len) encrypted_key(enc_len) key_arg(key_arg_len)
 * The old shim read clear_len as one byte and had no key_arg field, so a real
 * client's lengths were shifted and RSA decryption always failed. */
static int sslv2_read_client_master_key(crucible_tomcrypt_conn *c) {
    uint8_t *rec = NULL;
    size_t rec_len = 0;
    if (ssl2_recv_record(c, &rec, &rec_len) != 0) {
        return -1;
    }
    if (rec_len < 10 || rec_len > 2048 || rec[0] != SSL2_MT_CLIENT_MASTER_KEY ||
        rec[1] != 0x01 || rec[2] != 0x00 || rec[3] != 0x80) {
        /* We only offer RC4_128_WITH_MD5; refuse anything else. */
        free(rec);
        return -1;
    }
    size_t clear_len = ((size_t)rec[4] << 8) | (size_t)rec[5];
    size_t enc_key_len = ((size_t)rec[6] << 8) | (size_t)rec[7];
    size_t key_arg_len = ((size_t)rec[8] << 8) | (size_t)rec[9];
    if (key_arg_len > 8 || clear_len >= 16 || enc_key_len == 0 ||
        enc_key_len > 512 || clear_len + enc_key_len + key_arg_len + 10 != rec_len) {
        free(rec);
        return -1;
    }
    int rsa_bytes = rsa_get_size(&c->rsa);
    if (rsa_bytes <= 0 || (int)enc_key_len != rsa_bytes) {
        free(rec);
        return -1;
    }

    uint8_t clear_key[16] = {0};
    memcpy(clear_key, rec + 10, clear_len);
    const uint8_t *enc_key = rec + 10 + clear_len;
    /* key_arg (IV/export material) follows the encrypted key; RC4_128 has none,
     * and the key schedule above doesn't use it. Parsed for wire conformance. */

    uint8_t decrypted[512];
    unsigned long dec_len = sizeof(decrypted);
    int stat = 0;
    int err = rsa_decrypt_key_ex(enc_key, (unsigned long)enc_key_len, decrypted, &dec_len, NULL,
                                 0, 0, LTC_PKCS_1_V1_5, &stat, &c->rsa);
    if (err != CRYPT_OK || stat != 1 || dec_len == 0 || dec_len > sizeof(decrypted) ||
        dec_len + clear_len < 16) {
        free(rec);
        return -1;
    }
    memset(c->master_key, 0, sizeof(c->master_key));
    memcpy(c->master_key, clear_key, clear_len);
    {
        size_t room = 16 - clear_len;
        size_t take = dec_len < room ? dec_len : room;
        memcpy(c->master_key + clear_len, decrypted, take);
    }
    free(rec);
    return 0;
}

/* Full post-CMK handshake: SERVER-VERIFY -> CLIENT-FINISHED -> SERVER-FINISHED.
 * OpenSSL's server sends SERVER-VERIFY before reading CLIENT-FINISHED; a client
 * may send CLIENT-FINISHED before reading, both fit in the TCP buffers. */
static int sslv2_finish_handshake(crucible_tomcrypt_conn *c) {
    uint8_t verify_msg[1 + sizeof(c->challenge)];
    verify_msg[0] = SSL2_MT_SERVER_VERIFY;
    memcpy(verify_msg + 1, c->challenge, c->challenge_len);
    if (ssl2_send_record(c, verify_msg, 1 + c->challenge_len, 1) != 0) {
        return -1;
    }

    uint8_t *rec = NULL;
    size_t rec_len = 0;
    if (ssl2_recv_record(c, &rec, &rec_len) != 0) {
        return -1;
    }
    int ok = rec_len == 1 + c->conn_id_len && rec[0] == SSL2_MT_CLIENT_FINISHED &&
             memcmp(rec + 1, c->conn_id, c->conn_id_len) == 0;
    free(rec);
    if (!ok) {
        return -1;
    }

    uint8_t finished_msg[1 + sizeof(c->session_id)];
    finished_msg[0] = SSL2_MT_SERVER_FINISHED;
    memcpy(finished_msg + 1, c->session_id, c->session_id_len);
    return ssl2_send_record(c, finished_msg, 1 + c->session_id_len, 1);
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

    if (!peek || peek_len < 7 || !(peek[0] & 0x80) || peek[2] != SSL2_MT_CLIENT_HELLO) {
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
        if (challenge_len == 0 || challenge_len > sizeof(c->challenge) || cipher_len > 256 ||
            session_len > 256 || need > peek_len || need < 11) {
            /* Incomplete ClientHello (acceptance probe) — soft reject, no abort. */
            crucible_tomcrypt_free(c);
            return NULL;
        }
        size_t ch_off = 11 + cipher_len + session_len;
        if (ch_off + challenge_len > peek_len) {
            crucible_tomcrypt_free(c);
            return NULL;
        }
        memcpy(c->challenge, peek + ch_off, challenge_len);
        c->challenge_len = challenge_len;
    }

    if (load_rsa_from_pem(c, key_pem, key_len) != 0) {
        crucible_tomcrypt_free(c);
        return NULL;
    }

    /* The CLIENT-HELLO was consumed by the Rust peek path, not by
     * ssl2_recv_record(); account for it so the plaintext CLIENT-MASTER-KEY is
     * read with sequence 1 and the encrypted CLIENT-FINISHED with sequence 2,
     * matching OpenSSL's "every record counts" rule. */
    c->read_seq = 1;

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

    if (sslv2_read_client_master_key(c) != 0) {
        crucible_tomcrypt_free(c);
        return NULL;
    }
    if (sslv2_derive_keys(c) != 0) {
        crucible_tomcrypt_free(c);
        return NULL;
    }
    /* SERVER-VERIFY / CLIENT-FINISHED / SERVER-FINISHED are the actual SSLv2
     * full handshake — without them the peer has no proof that both sides
     * derived the same keys, and real clients reject the session. */
    if (sslv2_finish_handshake(c) != 0) {
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
    if (len == 0) {
        return 0;
    }
    /* Serve leftover bytes from a previous (larger) record first. */
    if (c->pending_off < c->pending_len) {
        size_t n = c->pending_len - c->pending_off;
        if (n > len) {
            n = len;
        }
        memcpy(buf, c->pending + c->pending_off, n);
        c->pending_off += n;
        if (c->pending_off >= c->pending_len) {
            c->pending_off = 0;
            c->pending_len = 0;
        }
        return (ssize_t)n;
    }
    uint8_t *rec = NULL;
    size_t rec_len = 0;
    if (ssl2_recv_record(c, &rec, &rec_len) != 0) {
        return -1;
    }
    size_t n = rec_len < len ? rec_len : len;
    memcpy(buf, rec, n);
    if (rec_len > n) {
        size_t rest = rec_len - n;
        if (rest > sizeof(c->pending)) {
            free(rec);
            return -1;
        }
        memcpy(c->pending, rec + n, rest);
        c->pending_len = rest;
        c->pending_off = 0;
    }
    free(rec);
    return (ssize_t)n;
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
    if (len == 0) {
        return 0;
    }
    if (len > (size_t)SSIZE_MAX) {
        return -1;
    }
    const uint8_t *p = (const uint8_t *)buf;
    size_t sent = 0;
    while (sent < len) {
        size_t chunk = len - sent;
        if (chunk > SSL2_APP_RECORD_MAX) {
            chunk = SSL2_APP_RECORD_MAX;
        }
        if (ssl2_send_record(c, p + sent, chunk, 1) != 0) {
            return -1;
        }
        sent += chunk;
    }
    return (ssize_t)sent;
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
