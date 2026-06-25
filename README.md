# quic_vibe

A libc-free QUIC SDK in C, built directly on x86_64 Linux syscalls.

This is the wire-format and state-machine core of QUIC ([RFC 9000]): packet
and frame codecs plus the stream and connection state machines. The
cryptographic handshake (RFC 9001) and loss/congestion control (RFC 9002)
are out of scope for now (see [Scope](#scope)).

[RFC 9000]: https://www.rfc-editor.org/rfc/rfc9000.html

## Design

- **No libc, no CRT.** Every domain compiles `-ffreestanding -nostdlib`.
  System calls go straight through inline assembly (`src/sys/syscall.h`),
  and the entry point is a freestanding `_start`.
- **x86_64 Linux only.** No portability layer.
- **One domain per directory.** Each is independently testable.
- **Cyclomatic complexity ≤ 3** for every function, enforced by `lizard`.
  Branch-heavy logic (header parsing, packet-number recovery, state
  transitions) is factored into small helpers and driven by tables.

## Layout

```
src/
  sys/      x86_64 direct syscalls, freestanding entry, base types
  varint/   variable-length integer codec + TLV cursor helpers   (RFC 9000 §16)
  packet/   long/short header parse/build; packet number          (RFC 9000 §17,
            truncation and recovery                                A.2/A.3)
  tparam/   transport parameter TLV codec                          (RFC 9000 §18)
  frame/    PADDING/PING/CRYPTO/STREAM/CONNECTION_CLOSE codec      (RFC 9000 §19)
  fsm/      shared table-driven finite state machine engine
  stream/   sending/receiving stream state machines               (RFC 9000 §3)
  conn/     handshake lifecycle + per-space packet numbers         (RFC 9000 §12)
  hash/     SHA-256 and HMAC-SHA-256                          (FIPS 180-4/198-1)
  hkdf/     HKDF and HKDF-Expand-Label                         (RFC 5869/8446)
  aes/      AES-128 block cipher (also AES-ECB)                    (FIPS 197)
  gcm/      AES-128-GCM AEAD                              (NIST SP 800-38D)
  chacha/   ChaCha20, Poly1305, ChaCha20-Poly1305 AEAD             (RFC 8439)
  hp/       AES header protection                              (RFC 9001 §5.4)
  tls/      Initial packet protection key derivation           (RFC 9001 §5.2)
  recovery/ RTT estimation, PTO, sent-packet & loss detection      (RFC 9002)
  cc/       NewReno congestion control                            (RFC 9002 §7)
  flow/     flow-control accounting + stream reassembly      (RFC 9000 §2.2/4)
  io/       UDP sockets (direct syscalls) + retransmission queue
  util/     shared inline helpers (constant-time compare, scalars)
tests/      hosted assert-based test harness, one file per domain
```

## Build

A Nix flake provides the toolchain (`clang`, `just`, `lizard`):

```sh
nix develop
```

Then use `just`:

```sh
just build   # compile every domain freestanding into build/*.o
just test    # build and run the hosted test suite
just ccn     # fail if any function exceeds CCN 3
just check   # ccn + test
```

`just build` proves libc independence: all domains compile under
`-ffreestanding -nostdlib`. `just test` builds the same sources in a hosted
configuration so they can be exercised with assertions.

## Correctness

Every codec is checked against official test vectors and has round-trip and
truncated-input tests:

- Transport codecs against the RFC 9000 Appendix A sample vectors. The
  packet-number recovery window boundary is pinned, including the case at
  exactly half a window where recovery deliberately does not match.
- Cryptography against the published vectors for each primitive: SHA-256
  (NIST), HMAC (RFC 4231), HKDF (RFC 5869), AES-128 (FIPS 197), AES-GCM
  (NIST SP 800-38D), ChaCha20/Poly1305 (RFC 8439). The AEADs reject tampered
  ciphertext, AAD, or tags and leave the plaintext buffer untouched.
- The **RFC 9001 Appendix A** Initial keys (`quic key`/`iv`/`hp` for both
  client and server) and the §5.4.2 header-protection mask match byte for
  byte, which exercises the whole HKDF→AEAD→header-protection stack together.
- Recovery and congestion control against the RFC 9002 formulas, with the
  packet-loss threshold boundary and the `cwnd >= kMinimumWindow` floor
  pinned by tests. The UDP layer is verified by a real send/recv round-trip
  over loopback.

## Scope

Implemented: the transport wire format (variable-length integers, headers,
packet numbers, transport parameters, frames) and stream/connection state
machines; the cryptography (SHA-256, HMAC, HKDF, AES-128, AES-128-GCM,
ChaCha20-Poly1305, header protection) and RFC 9001 Initial key derivation;
loss recovery and NewReno congestion control; flow control and reassembly;
and a direct-syscall UDP layer with a retransmission queue.

Not yet wired into a single driver: the full TLS 1.3 handshake message
exchange and a top-level event loop tying these layers together end to end.
The pieces each layer needs are in place and individually verified.
