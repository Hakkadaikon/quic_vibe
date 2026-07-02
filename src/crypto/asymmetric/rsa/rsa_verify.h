#ifndef QUIC_RSA_RSA_VERIFY_H
#define QUIC_RSA_RSA_VERIFY_H

#include "common/platform/sys/syscall.h"

/* RFC 8017: this verifier supports the common public exponent F4 (65537)
 * only. 1 if e (canonical big-endian) is exactly 65537. */
int quic_rsa_e_is_f4(const u8 *e, usz e_len);

/* RFC 8017 8.2.2. RSASSA-PKCS1-v1_5 verification with SHA-256/384/512
 * (selected by hash_len: 32, 48, or 64). n, e and sig are big-endian; e must
 * be F4 (anything else is rejected). Returns 1 if the signature is valid,
 * else 0. */
int quic_rsa_pkcs1_verify(
    const u8 *n,
    usz       n_len,
    const u8 *e,
    usz       e_len,
    const u8 *sig,
    usz       sig_len,
    const u8 *msg_hash,
    usz       hash_len);

#endif
