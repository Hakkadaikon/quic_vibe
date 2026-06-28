# 実 UDP QUIC サーバサンプル

`quic_server.c` は、実際の UDP ソケットで QUIC の Initial パケットを受信し、
リポジトリ本体の部品で TLS 1.3 のサーバフライトを組み立てて応答を返す最小サーバである。
libc 非依存・x86_64-linux・直接 syscall で動く（自前の `_start` を持つ静的バイナリ）。

何をするか。

- `0.0.0.0:4433` に bind する。
- datagram を受信し、簡易ロングヘッダから DCID を取り出す。
- 取り出した DCID から Initial 鍵を導出して Initial を復号し（RFC 9001 5.2）、
  CRYPTO フレームから ClientHello を取り出す。
- ALPN `h3` のオファーを確認し、実行時に自己署名 Ed25519 証明書を組み立てる。
- サーバドライバ（`sdrv`）で、**本物の TLS バイト列**のサーバフライトを生成する。
  ServerHello、EncryptedExtensions、Certificate、CertificateVerify、Finished
  （RFC 8446 4.4）である。
- ServerHello をサーバ Initial パケットに封入し（RFC 9000 17.2.2）、
  残りを Handshake パケットに封入して（RFC 9000 17.2.4、導出した handshake 鍵で保護）、
  両方を送信元へ返す。
- 各ステップを stderr に出力する。

## ビルドと起動

```sh
cd examples
nix develop          # clang / just / tcpdump が入る
just run             # ビルドして 0.0.0.0:4433 で起動
```

`just build` だけでも `examples/quic_server` バイナリが生成される。

## 実地検証で確認できたこと

別プロセスのクライアントから実 UDP（ループバック）で 1 往復させ、サーバの
受信・応答経路を端から端まで通した。観測できた事実は次のとおり。

- クライアントが、本物の ClientHello を載せた AEAD + ヘッダ保護つきの
  client Initial を `127.0.0.1:4433` へ送る。
- サーバが Initial を受信・復号し（`Initial received and opened`）、
  ALPN `h3` を選択し（`ALPN: h3 selected`）、自己署名証明書を組み立て
  （`certificate built`）、サーバフライトを生成し（`server flight built`）、
  ServerHello（Initial）とフライト（Handshake）の 2 つの datagram を送り返す。
- クライアントが、サーバ Initial 鍵で ServerHello を復号して取り出し、
  同じ ECDHE 共有秘密に到達し、Handshake パケットを復号してフライトを取り出し、
  **CertificateVerify 署名をサーバ証明書に対して検証し、Finished の MAC を検証する**。

つまり「実 UDP ソケットで QUIC Initial を受信し、本物のサーバフライトを生成して返し、
クライアントがそれを復号して暗号的に検証できる」ところまでを、ワイヤ越しに確認している。
これはバイト列の単なる往復ではなく、署名と鍵スケジュールの検証を伴う。

## 正直な制約

- このサーバは**完全な HTTP/3 を返さない**。リクエストへのレスポンス生成は含まない。
  1-RTT 鍵の設置やクライアント Finished の受理も、このサンプルの範囲外である。
- 本体のパケットコーデックは**簡易ロングヘッダ**（SCID・token・length フィールドを持たない）
  を使う。このため**`curl --http3` とはワイヤ互換でなく、curl では完走しない**。
  curl 自体もこの環境のサンドボックスでは実行できなかった。検証は上記のとおり、
  ワイヤ互換のクライアントを同じコーデックで動かして行った。
- `tcpdump` でのパケットキャプチャは、この環境では権限（CAP_NET_RAW）が無く実行できなかった。
  代わりに、実ソケットで往復するクライアントの復号・検証成功をもって往復を実証している。
- 鍵は再現性のため固定シードである（`ponytail:` コメント参照）。本番では per-run 鍵にする。

本体のドライバテストは、同じハンドシェイクが 1-RTT 鍵設置まで完走することをメモリ上で実証している。

```sh
cd ..
just test
```
