#include "test.h"
#include "sdrv/sdrv.h"
#include "tls/clienthello.h"
#include "tls/serverhello.h"
#include "tls/cert.h"
#include "tls/certverify.h"
#include "tls/finished.h"
#include "tls/handshake.h"
#include "tls/schedule.h"
#include "tls/x25519.h"

/* RFC 8446 4 / RFC 9001 4: a client emits a ClientHello, the server driver
 * builds the real server flight, and the client reaches the same ECDHE shared
 * secret, verifies the CertificateVerify ECDSA P-256 signature against the
 * server's self-built P-256 certificate, and checks the Finished. */

/* Split the server flight (EE || Cert || CertVerify || Finished) into its four
 * messages by walking the 4-byte handshake headers. */
static int next_hs(const u8 *b, usz n, usz *p, const u8 **msg, usz *len)
{
    usz body;
    u8 type;
    if (*p + 4 > n) return 0;
    if (quic_hs_parse(b + *p, n - *p, &type, &body) != 4) return 0;
    *msg = b + *p;
    *len = 4 + body;
    *p += *len;
    return 1;
}

void test_sdrv(void)
{
    u8 cli_priv[32], cli_pub[32], srv_priv[32], srv_pub[32];
    u8 cert_priv[32];
    u8 ch[512], sh[256], flight[2048];
    u8 srv_random[32], shared_cli[32], hs[32], s_traffic[32], th[32];
    u8 sh_pub[32];
    u16 cipher, version;
    usz ch_len, sh_len, hs_len, p = 0;
    const u8 *ee, *cm, *cv, *fin, *srv_hs_secret;
    usz eel, cml, cvl, finl;
    u16 cv_scheme, cv_siglen;
    const u8 *cv_sig;
    quic_sdrv s;

    for (usz i = 0; i < 32; i++) {
        cli_priv[i] = (u8)(i + 1);
        srv_priv[i] = (u8)(0x40 + i);
        cert_priv[i] = (u8)(0x80 + i);
        srv_random[i] = (u8)(0xa0 + i);
    }
    quic_x25519_base(cli_pub, cli_priv);
    quic_x25519_base(srv_pub, srv_priv);

    /* client: emit a ClientHello carrying its x25519 key_share. */
    {
        static const u8 tp[1] = {0};
        ch_len = quic_tls_client_hello(ch, sizeof(ch), srv_random, cli_pub,
                                       0, 0, tp, sizeof(tp));
    }
    CHECK(ch_len != 0);

    /* server: drive the flight (the driver builds its own P-256 cert). */
    quic_sdrv_init(&s, srv_priv, srv_pub, cert_priv, 0, 0);
    CHECK(quic_sdrv_recv_client_hello(&s, ch, ch_len));
    CHECK(quic_sdrv_build_server_flight(&s, srv_random, sh, sizeof(sh), &sh_len,
                                        flight, sizeof(flight), &hs_len));

    /* client: parse ServerHello and reach the same ECDHE shared secret. */
    CHECK(quic_tls_parse_server_hello(sh, sh_len, sh_pub, &cipher, &version));
    CHECK(cipher == 0x1301);
    CHECK(version == 0x0304);
    quic_x25519(shared_cli, cli_priv, sh_pub);

    /* both derive the same handshake secret from the shared ECDHE. */
    quic_tls_handshake_secret(shared_cli, hs);
    CHECK(quic_sdrv_handshake_secret(&s, &srv_hs_secret));
    for (usz i = 0; i < 32; i++) CHECK(hs[i] == srv_hs_secret[i]);

    /* split the flight into its four messages. */
    CHECK(next_hs(flight, hs_len, &p, &ee, &eel));
    CHECK(next_hs(flight, hs_len, &p, &cm, &cml));
    CHECK(next_hs(flight, hs_len, &p, &cv, &cvl));
    CHECK(next_hs(flight, hs_len, &p, &fin, &finl));
    CHECK(ee[0] == 0x08 && cm[0] == 0x0b && cv[0] == 0x0f && fin[0] == 0x14);

    /* CertificateVerify verifies against the server's self-built P-256
     * certificate over the transcript through Certificate. */
    {
        quic_transcript tr;
        quic_transcript_init(&tr);
        quic_transcript_add(&tr, ch, ch_len);
        quic_transcript_add(&tr, sh, sh_len);
        quic_transcript_add(&tr, ee, eel);
        quic_transcript_add(&tr, cm, cml);
        quic_transcript_hash(&tr, th);
    }
    CHECK(quic_tls_certverify_parse(cv + 4, cvl - 4, &cv_scheme, &cv_sig,
                                    &cv_siglen));
    CHECK(cv_scheme == 0x0403);
    CHECK(quic_tls_verify_cert_signature(0x0403, s.cert_der, s.cert_len, cv_sig,
                                         cv_siglen, th));

    /* Finished verifies under the server handshake traffic secret (derived
     * over the transcript through ServerHello) at the transcript hash through
     * CertificateVerify. */
    {
        quic_transcript tr;
        u8 fin_th[32];
        quic_transcript_init(&tr);
        quic_transcript_add(&tr, ch, ch_len);
        quic_transcript_add(&tr, sh, sh_len);
        quic_transcript_hash(&tr, fin_th); /* through ServerHello */
        quic_hkdf_expand_label(hs, "s hs traffic", 12, fin_th, 32, s_traffic, 32);
        quic_transcript_add(&tr, ee, eel);
        quic_transcript_add(&tr, cm, cml);
        quic_transcript_add(&tr, cv, cvl);
        quic_transcript_hash(&tr, fin_th); /* through CertificateVerify */
        CHECK(quic_tls_finished_check(s_traffic, fin_th, fin + 4));
    }
}
