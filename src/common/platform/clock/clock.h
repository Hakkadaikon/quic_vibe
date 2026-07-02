#ifndef QUIC_CLOCK_H
#define QUIC_CLOCK_H

#include "common/platform/sys/syscall.h"

/* CLOCK_REALTIME (linux clockid). */
#define QUIC_CLOCK_REALTIME 0

typedef struct {
  i64 sec;
  i64 nsec;
} quic_timespec;

/* Civil UTC time as packed decimal YYYYMMDDHHMMSS (the convention of
 * quic_x509_validity_ok) from UNIX epoch seconds. Proleptic Gregorian, no
 * leap seconds. */
u64 quic_clock_epoch_to_ymdhms(u64 secs);

/* The current wall-clock UTC as packed decimal YYYYMMDDHHMMSS, read via
 * clock_gettime(CLOCK_REALTIME). Returns 0 on syscall failure. */
u64 quic_clock_ymdhms(void);

#endif
