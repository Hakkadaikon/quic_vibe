#include "initpkt/initpkt.h"
#include "initpkt/initkeys.h"
#include "crypto_stream/crypto_tx.h"
#include "pipeline/txpacket.h"
#include "aes/aes.h"

/* RFC 9000 14.1: the protected datagram must reach 1200 bytes. With the
 * simplified long header (10 + dcid_len) and a 16-byte AEAD tag, the plaintext
 * payload is padded with PADDING frames (0x00) to this target. */
static usz pad_target(u8 dcid_len)
{
    usz overhead = 10u + dcid_len + 16u;
    return overhead < 1200u ? 1200u - overhead : 0u;
}

static usz initpkt_min_usz(usz a, usz b) { return a < b ? a : b; }

/* Build the CRYPTO frame for the ClientHello, then PADDING-fill to target. */
static int build_payload(const u8 *crypto_payload, usz payload_len,
                         usz target, u8 *buf, usz cap, usz *plen)
{
    usz n, fill = initpkt_min_usz(target, cap);
    if (!quic_crypto_stream_emit(crypto_payload, payload_len, 0,
                                 payload_len, buf, cap, &n))
        return 0;
    for (; n < fill; n++) buf[n] = 0x00;
    *plen = n;
    return 1;
}

/* ponytail: scid is part of the public API but the pipeline's simplified long
 * header carries no source connection ID; it is accepted and ignored here. Add
 * a full 17.2.2 header (token, length, scid) when wire interop needs it. */
int quic_initpkt_build(const u8 *dcid, u8 dcid_len,
                       const u8 *scid, u8 scid_len,
                       const u8 *crypto_payload, usz payload_len, u64 pn,
                       u8 *out, usz cap, usz *out_len)
{
    quic_initial_keys ck, sk;
    quic_aes128 hp;
    u8 payload[1200];
    usz plen, total;
    (void)scid; (void)scid_len;
    quic_initpkt_derive(dcid, dcid_len, &ck, &sk);
    quic_aes128_init(&hp, ck.hp);
    if (!build_payload(crypto_payload, payload_len, pad_target(dcid_len),
                       payload, sizeof(payload), &plen))
        return 0;
    total = quic_tx_packet(&ck, &hp, 0xc3, dcid, dcid_len, pn,
                           payload, plen, out, cap);
    if (total == 0) return 0;
    *out_len = total;
    return 1;
}
