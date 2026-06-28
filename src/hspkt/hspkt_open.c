#include "hspkt/hspkt_open.h"
#include "hspkt/unprotect.h"
#include "hp/hp.h"

/* RFC 9001 5 / RFC 9000 17.2.4: simplified long header is byte0, 4-byte
 * version, dcid_len, dcid, then a 4-byte packet number. */
int quic_hspkt_open(const quic_initial_keys *hs_keys, const quic_aes128 *hp,
                    u8 *pkt, usz len, u8 dcid_len,
                    const u8 **payload, usz *payload_len)
{
    usz hdr_len = 10u + dcid_len;
    usz pn_off = 6u + dcid_len;
    return quic_hspkt_unprotect(hs_keys, hp, pkt, len, hdr_len, pn_off,
                                QUIC_HP_LONG_MASK, payload, payload_len);
}
