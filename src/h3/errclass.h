#ifndef QUIC_H3_ERRCLASS_H
#define QUIC_H3_ERRCLASS_H

#include "common/platform/sys/syscall.h"

/* RFC 9114 8.1. HTTP/3 error codes 0x0100..0x0110 are defined by this
 * specification ("known"). Values of the form 0x1f*N + 0x21 are reserved for
 * grease and have no semantics. Any other value is left for application or
 * future use. A reserved code is not a known code. */

/* Whether code is an error code defined in RFC 9114 8.1 (0x0100..0x0110). */
int quic_h3_error_is_known(u64 code);

/* Whether code is a reserved (grease) error point, per RFC 9114 8.1. */
int quic_h3_error_is_reserved(u64 code);

#endif
