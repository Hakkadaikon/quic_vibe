#include "test.h"
#include "server/server.h"
#include "tls/clienthello.h"
#include "tls/serverhello.h"
#include "tls/handshake.h"
#include "tls/transcript.h"
#include "tls/schedule.h"
#include "tls/finished.h"
#include "tls/x25519.h"
#include "ed25519/ed25519.h"
#include "crypto_stream/crypto_tx.h"

/* RFC 8446 4 / RFC 9001 4.1.2: drive the server orchestrator through a full
 * handshake by buffer injection (no socket): a real ClientHello, the server
 * flight, then a genuine vs. forged client Finished. The central safety
 * property is that a forged Finished promotes nothing. */

/* RFC 5280 4.1: minimal Ed25519 end-entity cert carrying pub in its SPKI. */
static usz srv_ed_cert(u8 *out, const u8 pub[32])
{
    static const u8 head[] = {
        0x30, 0x48, 0x30, 0x3c, 0xa0, 0x03, 0x02, 0x01, 0x02,
        0x02, 0x01, 0x01, 0x30, 0x00, 0x30, 0x00, 0x30, 0x00, 0x30, 0x00,
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    };
    static const u8 tail[] = {
        0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x01, 0x00,
    };
    usz off = 0, i;
    for (i = 0; i < sizeof(head); i++) out[off++] = head[i];
    for (i = 0; i < 32; i++) out[off++] = pub[i];
    for (i = 0; i < sizeof(tail); i++) out[off++] = tail[i];
    return off;
}

/* Test fixture: the bytes a client needs to forge a genuine Finished. */
struct srv_fix {
    quic_server s;
    u8 ch[512];
    usz ch_len;
    u8 sh[256];
    usz sh_len;
    u8 flight[2048];
    usz flight_len;
    u8 srv_random[32];
    u8 cli_priv[32];
    u8 sh_pub[32];          /* server x25519 public from ServerHello */
    u8 cli_fin[64];         /* genuine client Finished message */
    usz cli_fin_len;
};

/* Build a ClientHello with a real x25519 key_share into f. */
static void make_client_hello(struct srv_fix *f)
{
    static const u8 tp[1] = {0};
    u8 cli_pub[32];
    for (usz i = 0; i < 32; i++) {
        f->cli_priv[i] = (u8)(i + 1);
        f->srv_random[i] = (u8)(0xa0 + i);
    }
    quic_x25519_base(cli_pub, f->cli_priv);
    f->ch_len = quic_tls_client_hello(f->ch, sizeof(f->ch), f->srv_random,
                                      cli_pub, 0, 0, tp, sizeof(tp));
}

/* Bring the server to FLIGHT_SENT and capture the flight bytes. */
static void drive_to_flight(struct srv_fix *f)
{
    u8 srv_priv[32], srv_pub[32], cert_seed[32], cert_pub[32];
    static u8 cert[128];
    usz cert_len;
    for (usz i = 0; i < 32; i++) {
        srv_priv[i] = (u8)(0x40 + i);
        cert_seed[i] = (u8)(0x80 + i);
    }
    quic_x25519_base(srv_pub, srv_priv);
    CHECK(quic_ed25519_keypair(cert_seed, cert_pub));
    cert_len = srv_ed_cert(cert, cert_pub);

    quic_server_init(&f->s, srv_priv, srv_pub, cert_seed, cert, cert_len);
    CHECK(quic_server_recv_initial(&f->s, f->ch, f->ch_len) == 1);
    CHECK(f->s.phase == QUIC_SERVER_HS_CH_RECVD);
    CHECK(quic_server_build_flight(&f->s, f->srv_random,
                                   f->sh, sizeof(f->sh), &f->sh_len,
                                   f->flight, sizeof(f->flight),
                                   &f->flight_len) == 1);
    CHECK(f->s.phase == QUIC_SERVER_HS_FLIGHT_SENT);
}

/* RFC 8446 4.4.4: compute the genuine client Finished the way the client does:
 * base key = client hs traffic secret over the transcript through ServerHello;
 * verify_data over the transcript hash through the server Finished. */
static void make_client_finished(struct srv_fix *f)
{
    u16 cipher, version;
    u8 hs[32], c_traffic[32], th[32];
    quic_transcript tr;
    usz off;
    CHECK(quic_tls_parse_server_hello(f->sh, f->sh_len, f->sh_pub,
                                      &cipher, &version));
    {
        u8 shared[32];
        quic_x25519(shared, f->cli_priv, f->sh_pub);
        quic_tls_handshake_secret(shared, hs);
    }
    quic_transcript_init(&tr);
    quic_transcript_add(&tr, f->ch, f->ch_len);
    quic_transcript_add(&tr, f->sh, f->sh_len);
    quic_transcript_hash(&tr, th);                    /* through ServerHello */
    quic_hkdf_expand_label(hs, "c hs traffic", 12, th, 32, c_traffic, 32);
    quic_transcript_add(&tr, f->flight, f->flight_len);
    quic_transcript_hash(&tr, th);                    /* through server Finished */

    off = quic_hs_begin(f->cli_fin, sizeof(f->cli_fin), QUIC_HS_FINISHED);
    quic_tls_finished_verify_data(c_traffic, th, f->cli_fin + off);
    f->cli_fin_len = off + QUIC_TLS_VERIFY_DATA;
    quic_hs_finish(f->cli_fin, f->cli_fin_len);
}

/* Wrap a TLS message as a CRYPTO-frame payload for quic_server_feed. */
static usz srv_wrap_crypto(const u8 *msg, usz len, u8 *out, usz cap)
{
    usz n;
    if (!quic_crypto_stream_emit(msg, len, 0, 256, out, cap, &n)) return 0;
    return n;
}

/* Happy path: CH -> flight -> good Finished -> confirmed -> HANDSHAKE_DONE. */
static void test_server_happy(void)
{
    struct srv_fix f;
    u8 payload[256], hsdone[4];
    usz plen, dlen;
    make_client_hello(&f);
    drive_to_flight(&f);

    /* 1-RTT not armed, not confirmed at flight time. */
    CHECK(quic_server_is_confirmed(&f.s) == 0);
    {
        const quic_initial_keys *k;
        CHECK(quic_keyset_for_level(&f.s.keys, QUIC_LEVEL_ONERTT, &k) == 0);
        CHECK(quic_keyset_for_level(&f.s.keys, QUIC_LEVEL_HANDSHAKE, &k) == 1);
    }

    make_client_finished(&f);
    plen = srv_wrap_crypto(f.cli_fin, f.cli_fin_len, payload, sizeof(payload));
    CHECK(plen != 0);
    CHECK(quic_server_feed(&f.s, payload, plen) == 1);
    CHECK(quic_server_is_confirmed(&f.s) == 1);
    CHECK(f.s.phase == QUIC_SERVER_HS_CONFIRMED);
    {
        const quic_initial_keys *k;
        CHECK(quic_keyset_for_level(&f.s.keys, QUIC_LEVEL_ONERTT, &k) == 1);
    }

    /* HANDSHAKE_DONE exactly once. */
    CHECK(quic_server_handshake_done(&f.s, hsdone, sizeof(hsdone), &dlen) == 1);
    CHECK(dlen == 1 && hsdone[0] == 0x1e);
    CHECK(quic_server_handshake_done(&f.s, hsdone, sizeof(hsdone), &dlen) == 0);
}

/* CENTRAL SAFETY: a forged client Finished promotes nothing. */
static void test_server_forged_finished(void)
{
    struct srv_fix f;
    u8 payload[256], hsdone[4];
    usz plen, dlen;
    make_client_hello(&f);
    drive_to_flight(&f);
    make_client_finished(&f);
    f.cli_fin[4] ^= 0x01;                  /* tamper verify_data */

    plen = srv_wrap_crypto(f.cli_fin, f.cli_fin_len, payload, sizeof(payload));
    CHECK(quic_server_feed(&f.s, payload, plen) == 0);
    CHECK(quic_server_is_confirmed(&f.s) == 0);
    CHECK(f.s.phase == QUIC_SERVER_HS_FLIGHT_SENT);
    {
        const quic_initial_keys *k;
        CHECK(quic_keyset_for_level(&f.s.keys, QUIC_LEVEL_ONERTT, &k) == 0);
    }
    CHECK(quic_server_handshake_done(&f.s, hsdone, sizeof(hsdone), &dlen) == 0);
}

/* Forbidden order: flight before the ClientHello is refused, no Handshake key. */
static void test_server_flight_before_ch(void)
{
    struct srv_fix f;
    u8 srv_priv[32], srv_pub[32], cert_seed[32];
    static u8 cert[1] = {0};
    u8 sh[256], flight[2048], rnd[32];
    usz sl, fl;
    for (usz i = 0; i < 32; i++) {
        srv_priv[i] = (u8)(0x40 + i);
        rnd[i] = (u8)i;
    }
    quic_x25519_base(srv_pub, srv_priv);
    quic_server_init(&f.s, srv_priv, srv_pub, cert_seed, cert, sizeof(cert));
    CHECK(quic_server_build_flight(&f.s, rnd, sh, sizeof(sh), &sl,
                                   flight, sizeof(flight), &fl) == 0);
    {
        const quic_initial_keys *k;
        CHECK(quic_keyset_for_level(&f.s.keys, QUIC_LEVEL_HANDSHAKE, &k) == 0);
    }
}

/* Forbidden order: a client Finished before the flight is rejected. */
static void test_server_fin_before_flight(void)
{
    struct srv_fix f;
    u8 payload[256];
    usz plen;
    make_client_hello(&f);
    {
        u8 srv_priv[32], srv_pub[32], cert_seed[32];
        static u8 cert[1] = {0};
        for (usz i = 0; i < 32; i++) srv_priv[i] = (u8)(0x40 + i);
        quic_x25519_base(srv_pub, srv_priv);
        quic_server_init(&f.s, srv_priv, srv_pub, cert_seed, cert, sizeof(cert));
        CHECK(quic_server_recv_initial(&f.s, f.ch, f.ch_len) == 1);
    }
    /* still CH_RECVD: any Finished-like payload must not promote */
    {
        u8 fin[40];
        usz off = quic_hs_begin(fin, sizeof(fin), QUIC_HS_FINISHED);
        for (usz i = 0; i < 32; i++) fin[off + i] = 0;
        quic_hs_finish(fin, off + 32);
        plen = srv_wrap_crypto(fin, off + 32, payload, sizeof(payload));
    }
    CHECK(quic_server_feed(&f.s, payload, plen) == 0);
    CHECK(quic_server_is_confirmed(&f.s) == 0);
    CHECK(f.s.phase == QUIC_SERVER_HS_CH_RECVD);
}

void test_server(void)
{
    test_server_happy();
    test_server_forged_finished();
    test_server_flight_before_ch();
    test_server_fin_before_flight();
}
