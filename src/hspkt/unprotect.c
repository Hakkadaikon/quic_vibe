#include "hspkt/unprotect.h"
#include "protect/protect.h"
#include "gcm/gcm.h"
#include "hp/hp.h"

/* RFC 9000 17.1: read the 4-byte packet number from the cleartext header. */
static u64 read_pn4(const u8 *pn)
{
    return ((u64)pn[0] << 24) | ((u64)pn[1] << 16) |
           ((u64)pn[2] << 8) | (u64)pn[3];
}

/* RFC 9001 5.3: AEAD-open ciphertext at pkt+hdr_len using header as AAD. */
static int aead_open(const quic_initial_keys *keys, u8 *pkt, usz hdr_len,
                     usz ct_len, u64 pn)
{
    u8 nonce[QUIC_INITIAL_IV];
    quic_aes128 aead;
    quic_protect_nonce(keys->iv, pn, nonce);
    quic_aes128_init(&aead, keys->key);
    return quic_gcm_open(&aead, nonce, pkt, hdr_len, pkt + hdr_len, ct_len,
                         pkt + hdr_len + ct_len, pkt + hdr_len);
}

/* RFC 9001 5.4/5.3 */
int quic_hspkt_unprotect(const quic_initial_keys *keys, const quic_aes128 *hp,
                         u8 *pkt, usz len, usz hdr_len, usz pn_off,
                         u8 bits_mask, const u8 **payload, usz *payload_len)
{
    u8 mask[5];
    usz ct_len;
    u64 pn;
    if (len <= hdr_len + QUIC_GCM_TAG) return 0;
    quic_hp_mask(hp, pkt + pn_off + 4, mask);
    quic_hp_apply(mask, &pkt[0], &pkt[pn_off], 4, bits_mask);
    pn = read_pn4(pkt + pn_off);
    ct_len = len - hdr_len - QUIC_GCM_TAG;
    if (!aead_open(keys, pkt, hdr_len, ct_len, pn)) return 0;
    *payload = pkt + hdr_len;
    *payload_len = ct_len;
    return 1;
}
