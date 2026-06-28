#include "test.h"

static void test_ext_key_share_wire(void)
{
    u8 pub[32], buf[64];
    for (usz i = 0; i < 32; i++) pub[i] = (u8)(i + 1);
    usz w = quic_tls_ext_key_share(buf, sizeof(buf), pub);
    CHECK(w == 42);
    /* RFC 8446 4.2.8 header bytes */
    CHECK(buf[0] == 0x00 && buf[1] == 0x33);     /* type */
    CHECK(buf[2] == 0x00 && buf[3] == 38);       /* ext_len */
    CHECK(buf[4] == 0x00 && buf[5] == 36);       /* shares_len */
    CHECK(buf[6] == 0x00 && buf[7] == 0x1d);     /* x25519 */
    CHECK(buf[8] == 0x00 && buf[9] == 32);       /* key_exchange len */
    CHECK(buf[10] == 1 && buf[41] == 32);        /* key contents */
}

static void test_ext_key_share_roundtrip(void)
{
    u8 pub[32], got[32], buf[64];
    for (usz i = 0; i < 32; i++) pub[i] = (u8)(0xA0 + i);
    quic_tls_ext_key_share(buf, sizeof(buf), pub);
    /* parse the KeyShareEntry that begins at buf+6 (group/ke_len/key) */
    CHECK(quic_tls_ext_key_share_parse(buf + 6, 36, got) == 1);
    for (usz i = 0; i < 32; i++) CHECK(got[i] == pub[i]);
}

static void test_ext_key_share_parse_guards(void)
{
    u8 got[32];
    u8 wrong_group[36] = {0x00, 0x17, 0x00, 32};   /* secp256r1, not x25519 */
    u8 wrong_len[36] = {0x00, 0x1d, 0x00, 31};
    CHECK(quic_tls_ext_key_share_parse(wrong_group, 36, got) == 0);
    CHECK(quic_tls_ext_key_share_parse(wrong_len, 36, got) == 0);
    CHECK(quic_tls_ext_key_share_parse(wrong_group, 35, got) == 0);
}

static void test_ext_key_share_cap_guard(void)
{
    u8 pub[32] = {0}, buf[41];
    CHECK(quic_tls_ext_key_share(buf, sizeof(buf), pub) == 0);
}

void test_ext_keyshare(void)
{
    test_ext_key_share_wire();
    test_ext_key_share_roundtrip();
    test_ext_key_share_parse_guards();
    test_ext_key_share_cap_guard();
}
