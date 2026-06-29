#include "srvloop/dispatch.h"
#include "frame/frame.h"
#include "h3srv/respond.h"
#include "pipeline/framewalk.h"

/* RFC 9000 19.8: STREAM frame types occupy 0x08..0x0f. */
static int is_stream(u64 type)
{
    return type >= QUIC_FRAME_STREAM_BASE && type <= QUIC_FRAME_STREAM_BASE + 7;
}

/* RFC 9114 4.1: hand the whole STREAM frame to the HTTP/3 request decoder. */
static int dispatch_stream(quic_h3srv_state *h3, const u8 *frame, usz len,
                           u8 *scratch, usz scap,
                           int *got_request, quic_h3reqdrive_req *req)
{
    if (!quic_h3srv_on_request(h3, frame, len, scratch, scap, req))
        return 0;
    *got_request = 1;
    return 1;
}

/* RFC 9000 12.4: find the first STREAM frame in the payload (skipping any
 * leading PADDING/ACK). On a hit, point *frame at it and write its remaining
 * length. Returns 1 if found, 0 otherwise. */
static int find_stream(const u8 *payload, usz len, const u8 **frame, usz *rem)
{
    quic_framewalk it;
    u64 type;
    quic_framewalk_init(&it, payload, len);
    while (quic_framewalk_next(&it, &type, frame, rem))
        if (is_stream(type)) return 1;
    return 0;
}

/* 1 if the payload carries at least one walkable frame (i.e. is non-empty and
 * decodes), so a CRYPTO-bearing handshake payload is handed to the server. */
static int has_frame(const u8 *payload, usz len)
{
    quic_framewalk it;
    u64 type;
    const u8 *frame;
    usz rem;
    quic_framewalk_init(&it, payload, len);
    return quic_framewalk_next(&it, &type, &frame, &rem);
}

/* RFC 9000 12.4 / 19.6: a payload may lead with PADDING/ACK before its CRYPTO
 * or STREAM frame (curl/quiche do this). A STREAM frame drives HTTP/3; anything
 * else is handed whole to quic_server_feed, whose crecv walks every CRYPTO
 * frame and reassembles a split ClientHello/Finished. The two paths stay
 * separate: a STREAM payload never re-enters the handshake. */
int quic_srvloop_dispatch(quic_server *s, quic_h3srv_state *h3,
                          const u8 *payload, usz len,
                          u8 *scratch, usz scap,
                          int *got_request, quic_h3reqdrive_req *req)
{
    const u8 *frame;
    usz rem;
    if (find_stream(payload, len, &frame, &rem))
        return dispatch_stream(h3, frame, rem, scratch, scap, got_request, req);
    if (has_frame(payload, len))
        return quic_server_feed(s, payload, len);
    return 0;
}
