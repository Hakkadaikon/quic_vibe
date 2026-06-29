#include "qpack/huffman.h"
#include "qpack/string.h"
#include "test.h"

static int hf_eq(const u8 *a, usz alen, const char *b, usz blen)
{
    if (alen != blen) return 0;
    for (usz i = 0; i < alen; i++)
        if (a[i] != (u8)b[i]) return 0;
    return 1;
}

/* RFC 7541 C.4.1: "www.example.com" Huffman-codes to these 12 octets. */
static void test_huffman_rfc_vector(void)
{
    const u8 enc[] = {0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a,
                      0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff};
    u8 out[32];
    usz olen = 0;
    CHECK(quic_qpack_huffman_decode(enc, sizeof(enc), out, sizeof(out), &olen));
    CHECK(hf_eq(out, olen, "www.example.com", 15));
}

/* A curl/quiche-style user-agent and authority decode back to their text. */
static void test_huffman_curl_headers(void)
{
    const u8 ua[] = {0x25, 0xb6, 0x50, 0xc3, 0xcb, 0xba, 0xb8, 0x7f};
    const u8 host[] = {0x2f, 0x95, 0xc8, 0x7a, 0x7f};
    u8 out[32];
    usz olen = 0;
    CHECK(quic_qpack_huffman_decode(ua, sizeof(ua), out, sizeof(out), &olen));
    CHECK(hf_eq(out, olen, "curl/8.7.1", 10));
    CHECK(quic_qpack_huffman_decode(host, sizeof(host), out, sizeof(out),
                                    &olen));
    CHECK(hf_eq(out, olen, "ex.com", 6));
}

/* RFC 7541 5.2: padding up to 7 bits of the EOS prefix (all ones) is dropped;
 * "/index" pads to a full final octet of 0x3f and decodes cleanly. */
static void test_huffman_padding(void)
{
    const u8 enc[] = {0x60, 0xd5, 0x48, 0x5f, 0x3f};
    u8 out[16];
    usz olen = 0;
    CHECK(quic_qpack_huffman_decode(enc, sizeof(enc), out, sizeof(out), &olen));
    CHECK(hf_eq(out, olen, "/index", 6));
}

/* RFC 7541 5.2: a trailing pad that is not all-ones is a decoding error
 * (0x18 = 'a' code 00011 followed by non-ones padding 000). */
static void test_huffman_bad_padding(void)
{
    const u8 enc[] = {0x18};
    u8 out[8];
    usz olen = 0;
    CHECK(quic_qpack_huffman_decode(enc, sizeof(enc), out, sizeof(out), &olen)
          == 0);
}

/* RFC 7541 5.2: padding of 8 or more bits, or an explicit EOS symbol, is an
 * error. 0xff*4 carries a 30-bit EOS code, never a valid string. */
static void test_huffman_eos_rejected(void)
{
    const u8 enc[] = {0xff, 0xff, 0xff, 0xff};
    u8 out[8];
    usz olen = 0;
    CHECK(quic_qpack_huffman_decode(enc, sizeof(enc), out, sizeof(out), &olen)
          == 0);
}

/* A dst smaller than the decoded length fails rather than overflowing. */
static void test_huffman_overflow(void)
{
    const u8 enc[] = {0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a,
                      0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff};
    u8 out[4];
    usz olen = 0;
    CHECK(quic_qpack_huffman_decode(enc, sizeof(enc), out, sizeof(out), &olen)
          == 0);
}

/* string_decode routes H=1 to the Huffman path; H=0 still copies raw. */
static void test_huffman_string_h1(void)
{
    u8 buf[16] = {0x80 | 12, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a,
                  0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff};
    u8 out[32];
    usz olen = 0;
    usz r = quic_qpack_string_decode(buf, 13, out, sizeof(out), &olen);
    CHECK(r == 13 && hf_eq(out, olen, "www.example.com", 15));

    const u8 raw[] = {'h', 'i'};
    u8 rbuf[8];
    usz w = quic_qpack_string_encode(rbuf, sizeof(rbuf), raw, 2);
    CHECK(w != 0);
    CHECK(quic_qpack_string_decode(rbuf, w, out, sizeof(out), &olen) == w);
    CHECK(hf_eq(out, olen, "hi", 2));
}

void test_qpack_huffman(void)
{
    test_huffman_rfc_vector();
    test_huffman_curl_headers();
    test_huffman_padding();
    test_huffman_bad_padding();
    test_huffman_eos_rejected();
    test_huffman_overflow();
    test_huffman_string_h1();
}
