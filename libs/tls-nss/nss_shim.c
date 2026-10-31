/* NSS legacy TLS — SSLv3, TLS 1.0/1.1/1.2, IE6 SSL_ENABLE_V2_COMPATIBLE_HELLO.
 * Expects a relay fd whose peer is bridged to the real TCP socket (Rust side).
 * Peeked ClientHello bytes must already be written to the relay peer before accept.
 *
 * Modern TLS 1.3 / ECH / PQC stay on BoringSSL; this module is the compatibility
 * layer for pre-1.3 clients.
 *
 * Thread model (G-04): the handshake is blocking (the Rust caller runs it in a
 * spawn_blocking slot with a 10s deadline and a 128-concurrency cap), but once
 * it is complete the SSL fd is switched to non-blocking and all further I/O is
 * driven by ONE poll thread in Rust:
 *   - crucible_nss_poll() waits on {SSL fd, pollable event} via PR_Poll;
 *   - crucible_nss_wakeup() (pollable event) wakes that poll when the async
 *     side queued response bytes;
 *   - crucible_nss_read/write() never block and report -2 on would-block.
 * NSS keeps the retry contract itself: PR_Write never consumes plaintext into
 * its internal pending buffer without leaving the last byte unconsumed (see
 * ssl3_SendApplicationData's appDataBuffered), so a caller that advances by the
 * returned count and retries the exact remainder also drives the ciphertext
 * buffer flush. No write thread is needed.
 */

#include "../tls-common/pem_util.h"

#include <cert.h>
#include <keyhi.h>
#include <nss.h>
#include <pk11pub.h>
#include <prerror.h>
#include <prio.h>
#include <secerr.h>
#include <secitem.h>
#include <ssl.h>
#include <sslproto.h>

/* PR_ImportTCPSocket / PROsfd live in the private NSPR API. */
#include <private/pprio.h>

#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Return code shared with the Rust side: distinct from any byte count. */
#define CRUCIBLE_NSS_IO_WOULD_BLOCK (-2)

typedef struct crucible_nss_conn {
    PRFileDesc *ssl;
    /* Pollable event, set by the async (writer) side to interrupt PR_Poll(). */
    PRFileDesc *wake;
} crucible_nss_conn;

static int g_nss_ready = 0;

int crucible_nss_init(const char *config_dir) {
    (void)config_dir;
    if (g_nss_ready) {
        return 0;
    }
    /* No softoken DB — identity is imported per-connection from PEM. */
    if (NSS_NoDB_Init(NULL) != SECSuccess) {
        return -1;
    }
    NSS_SetDomesticPolicy();
    SSL_ConfigServerSessionIDCache(256, 0, 0, NULL);
    g_nss_ready = 1;
    return 0;
}

static SECKEYPrivateKey *import_private_key(const char *key_pem, size_t key_len) {
    if (!key_pem || key_len == 0 || key_len > (size_t)INT_MAX) {
        return NULL;
    }
    size_t der_len = 0;
    uint8_t *der = crucible_pem_to_der(key_pem, key_len, &der_len);
    if (!der || der_len == 0 || der_len > (size_t)UINT_MAX) {
        crucible_pem_free(der);
        return NULL;
    }

    /* If PKCS#1 RSA ("BEGIN RSA PRIVATE KEY"), wrap as PKCS#8 PrivateKeyInfo. */
    uint8_t *pkcs8 = NULL;
    size_t pkcs8_len = 0;
    if (crucible_rsa_pkcs1_to_pkcs8(der, der_len, &pkcs8, &pkcs8_len) == 0 && pkcs8) {
        crucible_pem_free(der);
        der = pkcs8;
        der_len = pkcs8_len;
    }

    SECItem der_item;
    der_item.type = siBuffer;
    der_item.data = der;
    der_item.len = (unsigned int)der_len;

    PK11SlotInfo *slot = PK11_GetInternalKeySlot();
    if (!slot) {
        crucible_pem_free(der);
        return NULL;
    }

    SECKEYPrivateKey *key = NULL;
    SECStatus rv = PK11_ImportDERPrivateKeyInfoAndReturnKey(
        slot, &der_item, NULL, NULL, PR_FALSE, PR_TRUE, KU_ALL, &key, NULL);
    PK11_FreeSlot(slot);
    crucible_pem_free(der);
    if (rv != SECSuccess || !key) {
        return NULL;
    }
    return key;
}

static SECStatus import_identity(PRFileDesc *model, const char *cert_pem, size_t cert_len,
                                 const char *key_pem, size_t key_len) {
    if (!model || !cert_pem || cert_len == 0 || cert_len > (size_t)INT_MAX || !key_pem ||
        key_len == 0) {
        return SECFailure;
    }
    char *mutable_cert = (char *)malloc(cert_len);
    if (!mutable_cert) {
        return SECFailure;
    }
    memcpy(mutable_cert, cert_pem, cert_len);

    CERTCertificate *cert = CERT_DecodeCertFromPackage(mutable_cert, (int)cert_len);
    free(mutable_cert);
    if (!cert) {
        return SECFailure;
    }

    SECKEYPrivateKey *key = import_private_key(key_pem, key_len);
    if (!key) {
        CERT_DestroyCertificate(cert);
        return SECFailure;
    }

    SSLKEAType kea = ssl_kea_rsa;
    /* Prefer KEA inferred from the leaf when NSS provides it. */
    kea = NSS_FindCertKEAType(cert);
    SECStatus rv = SSL_ConfigSecureServer(model, cert, key, kea);
    SECKEY_DestroyPrivateKey(key);
    CERT_DestroyCertificate(cert);
    return rv;
}

crucible_nss_conn *crucible_nss_accept(int relay_fd, const char *cert_pem, size_t cert_len,
                                       const char *key_pem, size_t key_len) {
    /* Soft-fail on bad inputs — never crash the process. */
    if (relay_fd < 0 || !cert_pem || cert_len == 0 || !key_pem || key_len == 0) {
        return NULL;
    }
    if (!g_nss_ready && crucible_nss_init(NULL) != 0) {
        return NULL;
    }

    /* Unix socketpair is SOCK_STREAM — ImportTCPSocket is the portable path. */
    PRFileDesc *tcp = PR_ImportTCPSocket((PROsfd)relay_fd);
    if (!tcp) {
        return NULL;
    }

    PRFileDesc *ssl = SSL_ImportFD(NULL, tcp);
    if (!ssl) {
        PR_Close(tcp);
        return NULL;
    }

    if (SSL_OptionSet(ssl, SSL_SECURITY, PR_TRUE) != SECSuccess
        || SSL_OptionSet(ssl, SSL_ENABLE_SSL2, PR_FALSE) != SECSuccess
        || SSL_OptionSet(ssl, SSL_ENABLE_SSL3, PR_TRUE) != SECSuccess
        || SSL_OptionSet(ssl, SSL_ENABLE_TLS, PR_TRUE) != SECSuccess) {
        PR_Close(ssl);
        return NULL;
    }
    /* IE6-style ClientHello: SSLv2 record framing + SSL 3.0 version field. */
    (void)SSL_OptionSet(ssl, SSL_ENABLE_V2_COMPATIBLE_HELLO, PR_TRUE);
    (void)SSL_OptionSet(ssl, SSL_REQUEST_CERTIFICATE, PR_FALSE);
    (void)SSL_OptionSet(ssl, SSL_REQUIRE_CERTIFICATE, PR_FALSE);

    /* Legacy stack: SSLv3–TLS1.2. TLS1.3 / ECH / PQC remain on BoringSSL. */
    {
        SSLVersionRange range;
        range.min = SSL_LIBRARY_VERSION_3_0;
        range.max = SSL_LIBRARY_VERSION_TLS_1_2;
        if (SSL_VersionRangeSet(ssl, &range) != SECSuccess) {
            range.min = SSL_LIBRARY_VERSION_TLS_1_0;
            range.max = SSL_LIBRARY_VERSION_TLS_1_2;
            if (SSL_VersionRangeSet(ssl, &range) != SECSuccess) {
                PR_Close(ssl);
                return NULL;
            }
        }
    }

    if (import_identity(ssl, cert_pem, cert_len, key_pem, key_len) != SECSuccess) {
        PR_Close(ssl);
        return NULL;
    }

    if (SSL_ResetHandshake(ssl, /*asServer=*/PR_TRUE) != SECSuccess) {
        PR_Close(ssl);
        return NULL;
    }

    if (SSL_ForceHandshake(ssl) != SECSuccess) {
        PR_Close(ssl);
        return NULL;
    }

    crucible_nss_conn *conn = (crucible_nss_conn *)calloc(1, sizeof(crucible_nss_conn));
    if (!conn) {
        PR_Close(ssl);
        return NULL;
    }

    /* Post-handshake I/O is non-blocking and driven by PR_Poll from the single
     * Rust relay thread. PR_SetSocketOption on the layered SSL fd forwards to
     * the underlying TCP fd (NSPR pl_DefSetsocketoption), which is what NSS's
     * ssl_SocketIsBlocking() reads as well. */
    {
        PRSocketOptionData opt;
        opt.option = PR_SockOpt_Nonblocking;
        opt.value.non_blocking = PR_TRUE;
        if (PR_SetSocketOption(ssl, &opt) != PR_SUCCESS) {
            PR_Close(ssl);
            free(conn);
            return NULL;
        }
    }

    conn->wake = PR_NewPollableEvent();
    if (!conn->wake) {
        /* Without a wakeup handle an idle poll could never see queued writes;
         * fail closed instead of serving a connection that stalls responses. */
        PR_Close(ssl);
        free(conn);
        return NULL;
    }
    conn->ssl = ssl;
    return conn;
}

/* Map an NSPR PRInt32 I/O result to the Rust contract:
 *   >= 0  byte count (0 = EOF for reads)
 *   -2    would block (PR_WOULD_BLOCK_ERROR) - caller waits via PR_Poll
 *   -1    error
 */
static ssize_t map_io_result(PRInt32 n) {
    if (n >= 0) {
        return (ssize_t)n;
    }
    if (PR_GetError() == PR_WOULD_BLOCK_ERROR) {
        return CRUCIBLE_NSS_IO_WOULD_BLOCK;
    }
    return -1;
}

ssize_t crucible_nss_read(crucible_nss_conn *c, void *buf, size_t len) {
    if (!c || !c->ssl || !buf || len == 0 || len > (size_t)INT_MAX) {
        return -1;
    }
    return map_io_result(PR_Read(c->ssl, buf, (PRInt32)len));
}

ssize_t crucible_nss_write(crucible_nss_conn *c, const void *buf, size_t len) {
    if (!c || !c->ssl || !buf || len == 0 || len > (size_t)INT_MAX) {
        return -1;
    }
    return map_io_result(PR_Write(c->ssl, buf, (PRInt32)len));
}

/* Wait until the SSL fd is readable / writable or the pollable event is set.
 * Returns a bitmask: 1 = readable, 2 = writable, 4 = wakeup, 0 = timeout,
 * -1 = error. `timeout_ms` < 0 means no timeout. */
int crucible_nss_poll(crucible_nss_conn *c, int want_read, int want_write, int timeout_ms) {
    if (!c || !c->ssl) {
        return -1;
    }
    PRPollDesc pd[2];
    PRInt32 nfds = 0;
    if (want_read || want_write) {
        pd[0].fd = c->ssl;
        pd[0].in_flags = (PRInt16)((want_read ? PR_POLL_READ : 0) |
                                   (want_write ? PR_POLL_WRITE : 0));
        pd[0].out_flags = 0;
        nfds = 1;
    }
    if (c->wake) {
        pd[nfds].fd = c->wake;
        pd[nfds].in_flags = PR_POLL_READ;
        pd[nfds].out_flags = 0;
        nfds++;
    }
    if (nfds == 0) {
        return 0;
    }

    PRIntervalTime timeout = (timeout_ms < 0)
                                 ? PR_INTERVAL_NO_TIMEOUT
                                 : PR_MillisecondsToInterval((PRUint32)timeout_ms);
    PRInt32 rv = PR_Poll(pd, nfds, timeout);
    if (rv < 0) {
        return -1;
    }
    if (rv == 0) {
        return 0;
    }

    int out = 0;
    int ssl_idx = (want_read || want_write) ? 0 : -1;
    int wake_idx = (c->wake) ? ((ssl_idx == 0) ? 1 : 0) : -1;
    if (wake_idx >= 0 &&
        (pd[wake_idx].out_flags & (PR_POLL_READ | PR_POLL_ERR | PR_POLL_HUP))) {
        /* Reset the coalescing event; PR_SetPollableEvent from the writer side
         * is non-blocking, so one reset covers any number of sets. */
        (void)PR_WaitForPollableEvent(c->wake);
        out |= 4;
    }
    if (ssl_idx >= 0) {
        PRInt16 f = pd[ssl_idx].out_flags;
        if (f & PR_POLL_WRITE) {
            out |= 2;
        }
        if (want_read && (f & (PR_POLL_READ | PR_POLL_ERR | PR_POLL_HUP))) {
            out |= 1;
        }
        /* Read side already closed: turn an error/hangup into one write attempt
         * so the caller sees the real socket error instead of spinning. */
        if (!want_read && want_write && (f & (PR_POLL_ERR | PR_POLL_HUP)) &&
            !(f & PR_POLL_WRITE)) {
            out |= 2;
        }
        /* A readable-but-error socket must reach PR_Read/PR_Write so the real
         * error is reported. If only unrequested flags came back, force one
         * attempt on a requested direction instead of spinning in PR_Poll. */
        if (out == 0) {
            out = want_read ? 1 : 2;
        }
    }
    return out;
}

/* Wake a thread blocked in crucible_nss_poll (called from the Rust writer
 * side, i.e. from a different thread). Non-blocking and coalescing. */
int crucible_nss_wakeup(crucible_nss_conn *c) {
    if (!c || !c->wake) {
        return -1;
    }
    return (PR_SetPollableEvent(c->wake) == PR_SUCCESS) ? 0 : -1;
}

void crucible_nss_free(crucible_nss_conn *c) {
    if (!c) {
        return;
    }
    if (c->wake) {
        PR_DestroyPollableEvent(c->wake);
        c->wake = NULL;
    }
    if (c->ssl) {
        PR_Close(c->ssl);
        c->ssl = NULL;
    }
    free(c);
}
