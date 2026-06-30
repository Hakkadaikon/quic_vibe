#ifndef QUIC_X509_CHAIN_H
#define QUIC_X509_CHAIN_H

#include "common/platform/sys/syscall.h"

/* RFC 5280 4.1.2.4 / 4.1.2.6. Locate the issuer and subject Name SEQUENCEs
 * inside a tbsCertificate. The view (tag+length header included) points into
 * the caller's buffer. Returns 1 ok, 0 on malformed input. */
int quic_x509_issuer(const u8 *tbs, usz tbs_len, const u8 **issuer, usz *len);
int quic_x509_subject(const u8 *tbs, usz tbs_len, const u8 **subject, usz *len);

/* RFC 5280 4.1.2.4. Byte-equal Name comparison (cert A issuer vs cert B
 * subject). Returns 1 if equal, 0 otherwise. */
int quic_x509_dn_equal(const u8 *a, usz alen, const u8 *b, usz blen);

#endif
