#include "tls/ext_keyshare.h"
#include "util/be.h"

/* RFC 8446 4.2.8: type(2) ext_len(2) shares_len(2) group(2) ke_len(2) key(32). */
usz quic_tls_ext_key_share(u8 *buf, usz cap, const u8 pub[32])
{
    if (cap < 42) return 0;
    quic_put_be16(buf, QUIC_EXT_KEY_SHARE);
    quic_put_be16(buf + 2, 38);             /* ext_data length */
    quic_put_be16(buf + 4, 36);             /* client_shares length */
    quic_put_be16(buf + 6, QUIC_GROUP_X25519);
    quic_put_be16(buf + 8, 32);             /* key_exchange length */
    for (usz i = 0; i < 32; i++) buf[10 + i] = pub[i];
    return 42;
}

/* The entry names x25519 and declares a 32-byte key that fits in n. */
static int entry_ok(const u8 *buf, usz n)
{
    if (n < 36) return 0;
    return ((u16)buf[0] << 8 | buf[1]) == QUIC_GROUP_X25519 &&
           ((u16)buf[2] << 8 | buf[3]) == 32;
}

int quic_tls_ext_key_share_parse(const u8 *buf, usz n, u8 pub[32])
{
    if (!entry_ok(buf, n)) return 0;
    for (usz i = 0; i < 32; i++) pub[i] = buf[4 + i];
    return 1;
}
