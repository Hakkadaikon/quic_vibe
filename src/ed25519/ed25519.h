#ifndef QUIC_ED25519_ED25519_H
#define QUIC_ED25519_ED25519_H

#include "sys/syscall.h"

/* RFC 8032 Section 5.1: Ed25519 signature verification (PureEdDSA). */

#define QUIC_ED25519_PUBKEY 32
#define QUIC_ED25519_SIG    64

/* Verify sig (R||S, 64 bytes) over msg under pubkey (32 bytes).
 * Returns 1 if the signature is valid, 0 otherwise. */
int quic_ed25519_verify(const u8 sig[QUIC_ED25519_SIG],
                        const u8 *msg, usz msg_len,
                        const u8 pubkey[QUIC_ED25519_PUBKEY]);

#endif
