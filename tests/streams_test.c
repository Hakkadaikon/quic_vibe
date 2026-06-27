#include "test.h"
#include "flow/streams.c"

/* The peer may open streams with indices below the limit; the limit value
 * itself and above are refused (STREAM_LIMIT_ERROR). */
static void test_streams_limit(void)
{
    quic_streams s;
    quic_streams_init(&s, 3);
    CHECK(quic_streams_may_open(&s, 0) == 1);
    CHECK(quic_streams_may_open(&s, 2) == 1);
    CHECK(quic_streams_may_open(&s, 3) == 0); /* index == limit refused */
    CHECK(quic_streams_may_open(&s, 9) == 0);
}

/* MAX_STREAMS only raises the limit; a lower or equal value is ignored. */
static void test_streams_set_max(void)
{
    quic_streams s;
    quic_streams_init(&s, 3);
    CHECK(quic_streams_set_max(&s, 5) == 1); /* raised */
    CHECK(quic_streams_may_open(&s, 4) == 1);
    CHECK(quic_streams_set_max(&s, 5) == 0); /* equal, ignored */
    CHECK(quic_streams_set_max(&s, 2) == 0); /* lower, ignored */
    CHECK(quic_streams_may_open(&s, 4) == 1); /* limit unchanged at 5 */
}

/* Opening advances the count. */
static void test_streams_opened(void)
{
    quic_streams s;
    quic_streams_init(&s, 10);
    quic_streams_opened(&s);
    quic_streams_opened(&s);
    CHECK(s.opened == 2);
}

void test_streams(void)
{
    test_streams_limit();
    test_streams_set_max();
    test_streams_opened();
}
