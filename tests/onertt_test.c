#include "test.h"

static void onertt_keys(quic_initial_keys *k, quic_aes128 *hp)
{
    const u8 dcid[8] = {0x83,0x94,0xc8,0xf0,0x3e,0x51,0x57,0x08};
    quic_initial_derive(dcid, 8, 1, k);
    quic_aes128_init(hp, k->hp);
}

/* RFC 9000 17.3 / RFC 9001 5: build a 1-RTT packet, then open it with the
 * same keys; the payload comes back byte-for-byte. */
static void test_onertt_roundtrip(void)
{
    quic_initial_keys k;
    quic_aes128 hp;
    const u8 dcid[5] = {0xaa,0xbb,0xcc,0xdd,0xee};
    const u8 frames[] = {0x08, 'd','a','t','a'}; /* STREAM-ish payload */
    onertt_keys(&k, &hp);

    u8 pkt[64];
    usz total = 0;
    CHECK(quic_hspkt_onertt_build(&k, &hp, dcid, 5, 12,
                                  frames, sizeof(frames), pkt, sizeof(pkt),
                                  &total));
    CHECK(total == 5u + 5u + sizeof(frames) + 16u); /* byte0+dcid+pn + ct + tag */

    const u8 *out = 0;
    usz olen = 0;
    CHECK(quic_hspkt_onertt_open(&k, &hp, pkt, total, 5, &out, &olen));
    CHECK(olen == sizeof(frames));
    for (usz i = 0; i < sizeof(frames); i++) CHECK(out[i] == frames[i]);
}

/* RFC 9000 17.3: short-header form has the high bit of byte0 clear. After
 * header protection the low 5 bits are masked, but the high bit stays 0. */
static void test_onertt_byte0(void)
{
    quic_initial_keys k;
    quic_aes128 hp;
    const u8 dcid[4] = {1,2,3,4};
    const u8 frames[] = {0x08, 'X'};
    onertt_keys(&k, &hp);

    u8 pkt[64];
    usz total = 0;
    CHECK(quic_hspkt_onertt_build(&k, &hp, dcid, 4, 1,
                                  frames, sizeof(frames), pkt, sizeof(pkt),
                                  &total));
    CHECK((pkt[0] & 0x80) == 0x00);       /* short header form */
}

/* A tampered ciphertext byte makes open fail (AEAD authentication). */
static void test_onertt_tamper(void)
{
    quic_initial_keys k;
    quic_aes128 hp;
    const u8 dcid[4] = {9,8,7,6};
    const u8 frames[] = {0x08, 'h','i'};
    onertt_keys(&k, &hp);

    u8 pkt[64];
    usz total = 0;
    CHECK(quic_hspkt_onertt_build(&k, &hp, dcid, 4, 5,
                                  frames, sizeof(frames), pkt, sizeof(pkt),
                                  &total));
    pkt[total - 1] ^= 0x01;
    const u8 *out = 0;
    usz olen = 0;
    CHECK(!quic_hspkt_onertt_open(&k, &hp, pkt, total, 4, &out, &olen));
}

void test_onertt(void)
{
    test_onertt_roundtrip();
    test_onertt_byte0();
    test_onertt_tamper();
}
