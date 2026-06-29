#include "connrunner/recv.h"
#include "connrunner/level.h"
#include "udploop/rxloop.h"
#include "sentmeta/on_ack.h"

#define QUIC_CONNRUNNER_MAXPKTS 8 /* coalesced packets per datagram */

/* RFC 9001 5: open and dispatch one packet slice at its protection level,
 * reading back whether it elicited an ACK. Returns 1 if accepted. The dispatch
 * state's ack_eliciting flag is cleared first so it reflects only this packet. */
static int recv_one(quic_connrunner *r, u8 *pkt, usz len, int *elicited)
{
    int level;
    if (!quic_connrunner_packet_level(pkt[0], &level)) return 0;
    r->io.disp.ack_eliciting = 0;
    r->io.disp.has_ack = 0;
    if (!quic_connio_recv(&r->io, level, pkt, len)) return 0;
    *elicited = r->io.disp.ack_eliciting; /* RFC 9000 13.2.1 */
    return 1;
}

/* Feed an accepted packet's ACK obligation into the loop (RFC 9000 13.2.1). */
static void feed_loop(quic_connrunner *r, int elicited)
{
    quic_evloop_on_receive(&r->loop, elicited);
}

usz quic_connrunner_process_datagram(quic_connrunner *r, u8 *dgram, usz len)
{
    const u8 *pkts[QUIC_CONNRUNNER_MAXPKTS];
    usz offs[QUIC_CONNRUNNER_MAXPKTS], lens[QUIC_CONNRUNNER_MAXPKTS], n, i;
    usz accepted = 0;
    n = quic_udploop_split(dgram, len, pkts, offs, lens,
                           QUIC_CONNRUNNER_MAXPKTS);
    for (i = 0; i < n; i++) {
        int elicited = 0;
        if (!recv_one(r, dgram + offs[i], lens[i], &elicited)) continue;
        feed_loop(r, elicited);
        accepted++;
    }
    return accepted;
}

/* RFC 9002 A.2.2: a tracked slot at or below the Largest Acknowledged. */
static int slot_acked(const quic_sentmeta_pkt *p, u64 largest)
{
    return p->used && p->pn <= largest;
}

/* Acknowledge slot i if it is at or below `largest`. */
static void ack_one(quic_sentmeta *m, usz i, u64 largest)
{
    u64 t;
    int e;
    if (slot_acked(&m->pkts[i], largest))
        quic_sentmeta_on_ack(m, m->pkts[i].pn, &t, &e);
}

void quic_connrunner_track_acks(quic_connrunner *r)
{
    if (!r->io.disp.has_ack) return;
    for (usz i = 0; i < QUIC_SENTMETA_CAP; i++)
        ack_one(&r->sent, i, r->io.disp.largest_acked);
}
