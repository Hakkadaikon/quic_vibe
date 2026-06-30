#ifndef QUIC_CC_ECN_H
#define QUIC_CC_ECN_H

#include "common/platform/sys/syscall.h"

/* RFC 9002 7.1.2: ECN counts must increase monotonically; a CE increase
 * signals congestion. Counts are cumulative per-path. */

/* 1 if both CE and ECT(0) counts did not decrease, else 0. */
int quic_ecn_counts_valid(u64 prev_ce, u64 new_ce, u64 prev_ect0, u64 new_ect0);

/* 1 if the CE count increased. */
int quic_ecn_ce_increased(u64 prev_ce, u64 new_ce);

#endif
