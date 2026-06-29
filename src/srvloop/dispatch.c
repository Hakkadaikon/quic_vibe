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

/* RFC 9000 19.6 / 19.8: route one frame by type. CRYPTO drives the handshake;
 * STREAM drives HTTP/3. The crecv reassembly lives inside quic_server_feed, so
 * the whole CRYPTO-bearing payload is handed to it as-is. */
static int dispatch_one(quic_server *s, quic_h3srv_state *h3,
                        u64 type, const u8 *frame, usz len,
                        u8 *scratch, usz scap,
                        int *got_request, quic_h3reqdrive_req *req)
{
    if (type == QUIC_FRAME_CRYPTO)
        return quic_server_feed(s, frame, len);
    if (is_stream(type))
        return dispatch_stream(h3, frame, len, scratch, scap, got_request, req);
    return 0;
}

int quic_srvloop_dispatch(quic_server *s, quic_h3srv_state *h3,
                          const u8 *payload, usz len,
                          u8 *scratch, usz scap,
                          int *got_request, quic_h3reqdrive_req *req)
{
    quic_framewalk it;
    u64 type;
    const u8 *frame;
    usz rem;
    quic_framewalk_init(&it, payload, len);
    if (!quic_framewalk_next(&it, &type, &frame, &rem))
        return 0;
    return dispatch_one(s, h3, type, frame, rem, scratch, scap,
                        got_request, req);
}
