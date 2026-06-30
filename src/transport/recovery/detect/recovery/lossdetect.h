#ifndef QUIC_RECOVERY_LOSSDETECT_H
#define QUIC_RECOVERY_LOSSDETECT_H

#include "common/platform/sys/syscall.h"

/* RFC 9002 6.1: a packet is lost by the packet threshold or the time
 * threshold. Times are in microseconds. */

#define QUIC_LOSS_PACKET_THRESHOLD 3 /* kPacketThreshold */
#define QUIC_LOSS_TIME_NUM 9         /* kTimeThreshold = 9/8 */
#define QUIC_LOSS_TIME_DEN 8

/* True when pn is kPacketThreshold or more below largest_acked. */
int quic_loss_by_packet(u64 largest_acked, u64 pn);

/* True when now - sent_time >= 9/8 * max(srtt, latest_rtt). */
int quic_loss_by_time(u64 now, u64 sent_time, u64 srtt, u64 latest_rtt);

#endif
