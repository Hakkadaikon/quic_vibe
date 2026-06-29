#include "h3srv/respond.h"
#include "h3conn/response.h"

/* RFC 9114 4.1 */
int quic_h3srv_on_request(quic_h3srv_state *st, const u8 *stream_data, usz len,
                          u8 *scratch, usz scap, quic_h3reqdrive_req *req)
{
    if (!quic_h3reqdrive_recv_get(stream_data, len, scratch, scap, req))
        return 0;
    st->request_seen = 1;
    return 1;
}

/* RFC 9114 4.1 / 6.2.1: own SETTINGS-first and a received request are both
 * preconditions of producing a response. */
static int may_respond(const quic_h3srv_state *st)
{
    return st->settings_sent && st->request_seen;
}

/* RFC 9114 4.1 / 4.3.2 */
int quic_h3srv_build_response(const quic_h3srv_state *st, u64 stream_id,
                              u16 status, const u8 *body, usz body_len,
                              u8 *out, usz cap, usz *len)
{
    if (!may_respond(st))
        return 0;
    return quic_h3conn_send_response(stream_id, status, body, body_len, out,
                                     cap, len);
}
