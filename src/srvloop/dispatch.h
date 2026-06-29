#ifndef QUIC_SRVLOOP_DISPATCH_H
#define QUIC_SRVLOOP_DISPATCH_H

#include "h3reqdrive/request_drive.h"
#include "h3srv/state.h"
#include "server/server.h"

/* RFC 9000 12.4: route an opened payload's frames. CRYPTO frames (handshake)
 * drive the server orchestrator (quic_server_feed); a STREAM frame (1-RTT app
 * data) is decoded as an HTTP/3 request. The two paths are kept separate: a
 * Handshake payload never reaches HTTP/3, a 1-RTT request never re-enters the
 * handshake. Returns 1 if a frame was handled, 0 otherwise. On an HTTP/3
 * request *got_request is set and *req filled. */
int quic_srvloop_dispatch(quic_server *s, quic_h3srv_state *h3,
                          const u8 *payload, usz len,
                          u8 *scratch, usz scap,
                          int *got_request, quic_h3reqdrive_req *req);

#endif
