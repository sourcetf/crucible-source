/* NSS legacy TLS — SSLv3, TLS 1.0/1.1/1.2, IE6 SSL_ENABLE_V2_COMPATIBLE_HELLO.
 * Expects a relay fd whose peer is bridged to the real TCP socket (Rust side).
 * Peeked ClientHello bytes must already be written to the relay peer before accept.
 *
 * Modern TLS 1.3 / ECH / PQC stay on BoringSSL; this module is the compatibility
 * layer for pre-1.3 clients.
 */

#include "../tls-common/pem_util.h"

#include <cert.h>
#include <keyhi.h>
#include <nss.h>
#include <pk11pub.h>
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

typedef struct crucible_nss_conn {
    PRFileDesc *ssl;
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
    conn->ssl = ssl;
    return conn;
}

ssize_t crucible_nss_read(crucible_nss_conn *c, void *buf, size_t len) {
    if (!c || !c->ssl || !buf || len == 0 || len > (size_t)INT_MAX) {
        return -1;
    }
    PRInt32 n = PR_Read(c->ssl, buf, (PRInt32)len);
    return (ssize_t)n;
}

ssize_t crucible_nss_write(crucible_nss_conn *c, const void *buf, size_t len) {
    if (!c || !c->ssl || !buf || len == 0 || len > (size_t)INT_MAX) {
        return -1;
    }
    PRInt32 n = PR_Write(c->ssl, buf, (PRInt32)len);
    return (ssize_t)n;
}

void crucible_nss_free(crucible_nss_conn *c) {
    if (!c) {
        return;
    }
    if (c->ssl) {
        PR_Close(c->ssl);
        c->ssl = NULL;
    }
    free(c);
}
