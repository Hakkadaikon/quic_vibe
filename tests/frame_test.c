#include "test.h"
#include "frame/frame.c"

static void test_frame_simple(void)
{
    u8 buf[4];
    CHECK(quic_frame_put_simple(buf, sizeof(buf), QUIC_FRAME_PING) == 1 &&
          buf[0] == 0x01);
    CHECK(quic_frame_put_simple(buf, sizeof(buf), QUIC_FRAME_PADDING) == 1 &&
          buf[0] == 0x00);
    CHECK(quic_frame_put_simple(buf, 0, QUIC_FRAME_PING) == 0);
}

static void test_frame_crypto_roundtrip(void)
{
    const u8 payload[] = {0x16, 0x03, 0x03, 0xAA, 0xBB};
    quic_crypto_frame in = {.offset = 1000, .length = sizeof(payload),
                            .data = payload};
    u8 buf[32];
    usz w = quic_frame_put_crypto(buf, sizeof(buf), &in);
    CHECK(w != 0 && buf[0] == QUIC_FRAME_CRYPTO);

    quic_crypto_frame out;
    usz r = quic_frame_get_crypto(buf, w, &out);
    CHECK(r == w && out.offset == 1000 && out.length == sizeof(payload));
    CHECK(out.data[0] == 0x16 && out.data[4] == 0xBB);
}

static void test_frame_crypto_truncated(void)
{
    const u8 payload[] = {1, 2, 3};
    quic_crypto_frame in = {.offset = 0, .length = 3, .data = payload};
    u8 buf[32];
    usz w = quic_frame_put_crypto(buf, sizeof(buf), &in);
    quic_crypto_frame out;
    CHECK(quic_frame_get_crypto(buf, w - 1, &out) == 0); /* data cut short */
    CHECK(quic_frame_put_crypto(buf, 2, &in) == 0);      /* header no room */
}

void test_frame(void)
{
    test_frame_simple();
    test_frame_crypto_roundtrip();
    test_frame_crypto_truncated();
}
