#ifndef CRUCIBLE_PEM_UTIL_H
#define CRUCIBLE_PEM_UTIL_H

#include <stddef.h>
#include <stdint.h>

/* Decode PEM block (with headers) into DER. Returns allocated buffer or NULL. */
uint8_t *crucible_pem_to_der(const char *pem, size_t pem_len, size_t *der_len_out);

void crucible_pem_free(uint8_t *der);

/* Wrap PKCS#1 RSAPrivateKey DER as PKCS#8 PrivateKeyInfo (for NSS PK11 import).
 * Returns 0 on success (*out allocated); 1 if input is already PKCS#8 / not RSA;
 * -1 on allocation failure. When return==1, *out is left NULL.
 */
int crucible_rsa_pkcs1_to_pkcs8(const uint8_t *pkcs1, size_t pkcs1_len,
                                uint8_t **out, size_t *out_len);

#endif
