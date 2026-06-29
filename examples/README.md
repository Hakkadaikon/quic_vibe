# Real-UDP HTTP/3 server sample

`quic_server.c` is a minimal HTTP/3 server that drives the in-tree server
orchestrator (`quic_server_*`) from a real client `Initial` over a real UDP
socket: it recovers the ClientHello, builds the server flight, and seals and
sends it. It also builds the HTTP/3 `:status 200` answer to a `GET` (logged at
startup). It is libc-free, x86_64-linux only, and runs on direct syscalls with
its own `_start` (a static, freestanding binary).

The wire path it owns is: client `Initial` → ServerHello (Initial packet) →
server flight (Handshake packet). Receiving the client Finished over the wire,
confirming, and sending the `HANDSHAKE_DONE` / HTTP/3 response under 1-RTT AEAD
route through `connio` and are **not wired in this sample** (see "What is
verified" below); the in-tree loopback test exercises confirmation and the
`GET → 200` round trip by buffer injection.

## Overview

The server drives one client `Initial` toward the server flight, and builds the
HTTP/3 answer the response layer would send once confirmed:

1. Accept the client `Initial`, derive Initial keys from the DCID, decrypt, and
   recover the ClientHello (`quic_server_recv_initial`).
2. Negotiate ALPN `h3`, build the server flight — ServerHello / EncryptedExtensions
   (ALPN `h3` + QUIC transport parameters) / Certificate / CertificateVerify /
   Finished — and install the Handshake key (`quic_server_build_flight`), then
   seal and send the ServerHello (Initial packet) and flight (Handshake packet).
3. Build the HTTP/3 answer the server sends once confirmed — server SETTINGS
   first, decode a `GET`, build `:status 200` + body (`quic_h3srv_open_control`
   → `quic_h3srv_on_request` → `quic_h3srv_build_response`) — logged at startup.

The remaining steps — reassembling and **verifying** the client Finished
(`quic_server_feed` → confirm, install 1-RTT), emitting `HANDSHAKE_DONE`, and
sending the HTTP/3 bytes under 1-RTT AEAD — need the `connio` 1-RTT path and are
not wired in this sample. The in-tree loopback test drives them by buffer
injection, including the **forged-Finished** safety check (a forged Finished
promotes nothing).

The end-entity certificate is a runtime self-signed **ECDSA P-256** certificate
(secp256r1 SPKI, `ecdsa-with-SHA256`, `CN=localhost`), and CertificateVerify is
signed with ECDSA scheme `0x0403` (`ecdsa_secp256r1_sha256`, RFC 8446 4.4.3).
This is deliberate: curl's HTTP/3 backend (quiche, which uses BoringSSL) does
**not** verify Ed25519 server certificates with its default configuration, so an
Ed25519 leaf — which the earlier handshake-only sample used — would be rejected
during certificate verification. The ECDHE `key_share` is X25519; P-256 is used
for the certificate and CertificateVerify only.

## Connection flow

```mermaid
sequenceDiagram
    participant C as Client (curl --http3 / in-tree client)
    participant S as quic_server (0.0.0.0:4433)

    Note over S: listen_udp() — udp socket / bind, await ClientHello
    C->>S: Initial (long header, ClientHello in CRYPTO; ALPN h3, X25519 key_share)
    Note over S: quic_server_recv_initial() — derive Initial keys from DCID,<br/>decrypt, fold ClientHello into the transcript
    Note over S: quic_server_build_flight()<br/>SH / EE(ALPN h3 + transport params) /<br/>Cert(ECDSA P-256) / CertVerify(0x0403) / Finished<br/>+ install Handshake key
    S-->>C: ServerHello (Initial packet)
    S-->>C: server flight (Handshake packet)
    Note over S,C: below this line routes through connio (not wired in this sample);<br/>the in-tree loopback test exercises it by buffer injection
    C->>S: client Finished (Handshake CRYPTO)
    Note over S: quic_server_feed() — verify client Finished;<br/>only on a match: Master secret + 1-RTT keys + confirm
    S-->>C: HANDSHAKE_DONE (1-RTT)
    Note over S,C: 1-RTT confirmed
    S-->>C: SETTINGS (server control stream, sent first)
    C->>S: SETTINGS + HEADERS (GET /)
    Note over S: quic_h3srv_on_request() — decode the request<br/>quic_h3srv_build_response() — :status 200 + body
    S-->>C: HEADERS (:status 200) + DATA (body)
```

The handshake is gated on a verified client Finished: a forged Finished promotes
nothing (the server stays unconfirmed and never installs 1-RTT keys). SETTINGS is
sent before any response, and a response is built only after a request HEADERS
has been decoded (RFC 9114 6.2.1 / 4.1). The sample itself sends through the
server flight; everything below the dividing line is driven by the in-tree
loopback test rather than over the sample's own socket.

## Build and run

```sh
cd examples
nix develop          # provides clang / just / tcpdump
just run             # builds and starts on 0.0.0.0:4433
```

`just build` alone produces the `examples/quic_server` binary (libc-free, own
`_start`). On startup the server prints `listening on 0.0.0.0:4433` and waits for
the ClientHello. Stop it with Ctrl-C.

## Connecting with `curl --http3` (honest)

```sh
curl --http3 --insecure https://127.0.0.1:4433/
```

The server is **designed to** complete a handshake and return `:status 200` to an
HTTP/3 curl, but a real `curl --http3` round trip is **not verified in this
environment**, and completion against curl is **not guaranteed**:

- **HTTP/3-capable curl required.** The curl in this sandbox is built **without**
  HTTP/3 (`curl --version` lists no `http3` under Protocols/Features), so it
  cannot be exercised here. You need a curl linked against an HTTP/3 backend
  (quiche or ngtcp2).
- **Targeted at the quiche (BoringSSL) backend.** The certificate and signature
  choices above are tuned for quiche/BoringSSL. curl built on ngtcp2 (GnuTLS or
  OpenSSL) applies a different set of MTI algorithms and extension checks and may
  reject this server's flight; completion against ngtcp2 is **not guaranteed**.
- **ECDSA P-256, not Ed25519.** The P-256 leaf + `0x0403` CertificateVerify is the
  workaround for BoringSSL's default-off Ed25519 verification (see Overview).
- **Sandbox network limits.** `tcpdump -i lo -n udp port 4433` would show the
  exchange, but packet capture needs `CAP_NET_RAW`, which is **not available**
  here, so it was not run.

So "external HTTP/3 clients (curl/quiche/ngtcp2/Chrome) complete a handshake and
get a 200" is **not** verified in this environment.

## First-choice verification: the in-tree client over loopback

The positive, in-environment check is the repository's own client
(`src/client/`) driving this server over a real UDP loopback socket
(`127.0.0.1`), end to end:

```sh
cd ..
just test
```

The `h3_loopback` test checks three things without any external HTTP/3 tooling
and without `CAP_NET_RAW` (it gracefully skips the socket leg when the sandbox
forbids sockets):

1. the client's real Initial datagram crosses a loopback UDP socket and arrives
   padded to 1200 bytes (RFC 9000 14.1);
2. the server orchestrator reaches confirmation and emits `HANDSHAKE_DONE`, fed
   a real ClientHello, the server flight, and a genuine client Finished by
   buffer injection (the forged-Finished safety check lives in `server_test`);
3. the HTTP/3 response layer answers a `GET /` with `:status 200` + body, which
   the client's response decoder recovers.

## What is verified / what is not

**Verified (demonstrated):**

- **Build**: `cd examples && just build` produces the `quic_server` binary
  (libc-free, own `_start`).
- **Bind + listen**: `./quic_server` prints `listening on 0.0.0.0:4433` and waits
  for the ClientHello (bind succeeds, no crash).
- **Sample wire path**: the sample recovers the ClientHello from a client
  `Initial`, builds the server flight, and seals + sends the ServerHello (Initial
  packet) and flight (Handshake packet).
- **Loopback datagram delivery**: the in-tree client's real Initial crosses a
  loopback UDP socket and arrives padded to 1200 (`h3_loopback`, check 1).
- **Handshake confirmation (injection)**: the server orchestrator reaches
  CONFIRMED and emits `HANDSHAKE_DONE` from a real ClientHello + flight + genuine
  client Finished (`h3_loopback`, check 2; `server_test` for the full phase
  machine).
- **HTTP/3 GET → 200**: the server sends SETTINGS first, decodes the `GET`, and
  the client recovers `:status 200` and the body (`h3_loopback`, check 3; built
  and logged by the sample at startup).
- **Forged-Finished safety**: a forged client Finished promotes nothing; the
  server stays unconfirmed and installs no 1-RTT keys (`server_test`).
- **Wire format**: the long header conforms to RFC 9000 17.2, the TLS flight to
  RFC 8446 4.4, and the in-tree tests confirm the bytes match the RFC 9001 A.2
  vector.

**Not verified (out of scope or environment-limited):**

- **The 1-RTT wire round trip in the sample itself**: receiving the client
  Finished over the wire, confirming, and sending `HANDSHAKE_DONE` / the HTTP/3
  response under 1-RTT AEAD route through `connio` and are not wired into the
  sample — it sends through the server flight and (separately) builds the HTTP/3
  200 bytes at startup. Confirmation and the `GET → 200` round trip are verified
  by `h3_loopback` via buffer injection, not over the sample's socket.
- A completed handshake against an **external** HTTP/3 client
  (curl / quiche / ngtcp2 / Chrome) — the local curl lacks HTTP/3, and ngtcp2
  completion is not guaranteed.
- A `tcpdump` packet capture — no `CAP_NET_RAW` in this environment.
- More than one connection or request stream; methods other than `GET`
  (e.g. `POST` with a request body).

## Scope

One connection, one request: a single `GET` answered with `:status 200` and a
fixed body. The ECDHE `key_share` is X25519 (P-256 is the certificate/signature
algorithm only). No Retry, Version Negotiation, 0-RTT, or connection migration.
The handshake keys use fixed seeds for reproducibility (see the `ponytail:`
comment in the source); a production server would derive per-run keys.
