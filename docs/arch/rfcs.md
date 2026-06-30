# 実装した仕様と、それが必要な理由

QUIC は単一の RFC では完結しない。
トランスポート本体、暗号化のための TLS 1.3、その下で動く暗号プリミティブ、上で話す HTTP/3、さらに土台となる IP と UDP まで、複数の標準が積み重なって初めて1本の接続が成立する。
ここでは実装した仕様を6つのグループに分け、各グループがなぜ要るのか、各仕様が何のためにあるのかを示す。

## QUIC コア

QUIC の最小核は、トランスポート、その暗号化、損失回復という3つの責務に分かれている。
パケットの形と接続の状態遷移を定める本体に、TLS 1.3 を QUIC の鍵スケジュールへ結びつける層と、UDP には無い再送と輻輳制御を足す層が重なる。
不変条件の文書は、これらをまたぐ前提を1か所に集めたものである。

| 仕様 | 正式タイトル | リンク | なぜ要るか |
|------|------------|--------|-----------|
| RFC 9000 | QUIC: A UDP-Based Multiplexed and Secure Transport | https://www.rfc-editor.org/rfc/rfc9000 | パケットとフレームの形式、ストリーム、接続の状態遷移を定める本体。 |
| RFC 9001 | Using TLS to Secure QUIC | https://www.rfc-editor.org/rfc/rfc9001 | TLS 1.3 ハンドシェイクを QUIC の鍵導出とパケット保護へ結びつける。 |
| RFC 9002 | QUIC Loss Detection and Congestion Control | https://www.rfc-editor.org/rfc/rfc9002 | UDP が持たない損失検知と輻輳制御を、送信側が自前で行うための規定。 |
| RFC 8999 | Version-Independent Properties of QUIC | https://www.rfc-editor.org/rfc/rfc8999 | バージョンに依らず固定なヘッダの性質を定め、バージョンネゴシエーションの土台になる。 |

## QUIC 拡張

コアだけでは運用に足りない部分を、後続の拡張が補う。
経路の到達性確認、観測可能性、新しい輻輳制御、より長い接続 ID、能動的な経路探索といった要件は、いずれもコアの外で標準化されている。
実運用に近い挙動を出すには、これらを取り込む必要がある。

| 仕様 | 正式タイトル | リンク | なぜ要るか |
|------|------------|--------|-----------|
| RFC 9221 | An Unreliable Datagram Extension to QUIC | https://www.rfc-editor.org/rfc/rfc9221 | 信頼性を捨てて低遅延を取る DATAGRAM フレームを追加する。 |
| RFC 9287 | Greasing the QUIC Bit | https://www.rfc-editor.org/rfc/rfc9287 | 固定ビットを意図的に揺らし、中間装置が値を硬直化させるのを防ぐ。 |
| RFC 9368 | Compatible Version Negotiation for QUIC | https://www.rfc-editor.org/rfc/rfc9368 | 追加の往復なしで互換バージョンへ移行する手順を定める。 |
| RFC 9369 | QUIC Version 2 | https://www.rfc-editor.org/rfc/rfc9369 | バージョン固定化を避けるための第2版。塩やラベルが版ごとに異なる。 |
| RFC 9308 | Applicability of the QUIC Transport Protocol | https://www.rfc-editor.org/rfc/rfc9308 | QUIC をどう使うべきか、運用上の前提と注意を示す。 |
| RFC 9312 | Manageability of the QUIC Transport Protocol | https://www.rfc-editor.org/rfc/rfc9312 | 経路上から観測できる情報と、できない情報の境界を定める。 |
| RFC 8899 | Packetization Layer Path MTU Discovery for Datagram Transport Protocols | https://www.rfc-editor.org/rfc/rfc8899 | ICMP に頼らず、データグラム経路の MTU を探索する。 |

## TLS と PKI

QUIC のパケット保護鍵は TLS 1.3 ハンドシェイクが作る。
鍵交換と認証を行うハンドシェイク本体に、サーバを証明する証明書の構文と検証、署名アルゴリズム、拡張がぶら下がる。
鍵が無ければ最初の1バイトも暗号化できないため、この群は QUIC の前提そのものである。

| 仕様 | 正式タイトル | リンク | なぜ要るか |
|------|------------|--------|-----------|
| RFC 8446 | The Transport Layer Security (TLS) Protocol Version 1.3 | https://www.rfc-editor.org/rfc/rfc8446 | 鍵交換と認証を行うハンドシェイクと鍵スケジュールの本体。 |
| RFC 5280 | Internet X.509 Public Key Infrastructure Certificate and CRL Profile | https://www.rfc-editor.org/rfc/rfc5280 | 証明書の構文と、検証時に守るべき制約を定める。 |
| RFC 5480 | Elliptic Curve Cryptography Subject Public Key Information | https://www.rfc-editor.org/rfc/rfc5480 | 証明書中の楕円曲線公開鍵の表現を定める。 |
| RFC 5758 | Internet X.509 PKI: Additional Algorithms and Identifiers for DSA and ECDSA | https://www.rfc-editor.org/rfc/rfc5758 | ECDSA の署名アルゴリズム識別子を証明書に対応づける。 |
| RFC 8410 | Algorithm Identifiers for Ed25519, Ed448, X25519, and X448 | https://www.rfc-editor.org/rfc/rfc8410 | Ed25519 と X25519 を証明書と鍵情報で扱うための識別子。 |
| RFC 6066 | Transport Layer Security (TLS) Extensions: Extension Definitions | https://www.rfc-editor.org/rfc/rfc6066 | SNI など TLS 拡張の基本を定める。接続先ホスト名の伝達に要る。 |
| RFC 6125 | Representation and Verification of Domain-Based Application Service Identity | https://www.rfc-editor.org/rfc/rfc6125 | 証明書の名前と接続先ホスト名の照合規則を定める。 |
| RFC 7301 | Transport Layer Security (TLS) Application-Layer Protocol Negotiation Extension | https://www.rfc-editor.org/rfc/rfc7301 | ALPN により、ハンドシェイク中に HTTP/3 を選ぶ。 |
| RFC 8017 | PKCS #1: RSA Cryptography Specifications Version 2.2 | https://www.rfc-editor.org/rfc/rfc8017 | RSA 署名と RSASSA-PSS の検証手順を定める。RSA 証明書の検証に要る。 |

## 暗号プリミティブ

TLS と QUIC の鍵スケジュールは、より下の暗号関数を組み合わせて成り立つ。
パケットを保護する AEAD、鍵を導出する HKDF、相手を認証する署名と、その土台となるハッシュや楕円曲線がここに集まる。
これらは QUIC を知らない純粋な関数であり、公式テストベクタで単独に検証できる。

| 仕様 | 正式タイトル | リンク | なぜ要るか |
|------|------------|--------|-----------|
| RFC 8439 | ChaCha20 and Poly1305 for IETF Protocols | https://www.rfc-editor.org/rfc/rfc8439 | AES が無い環境でも使える AEAD 暗号方式。 |
| FIPS 197 | Advanced Encryption Standard (AES) | https://csrc.nist.gov/pubs/fips/197/final | AES ブロック暗号の本体。AES-GCM の土台。 |
| SP 800-38D | Recommendation for Block Cipher Modes of Operation: GCM and GMAC | https://csrc.nist.gov/pubs/sp/800/38/d/final | AES を AEAD にする GCM モード。既定のパケット保護方式。 |
| RFC 7748 | Elliptic Curves for Security | https://www.rfc-editor.org/rfc/rfc7748 | X25519 鍵交換の曲線演算を定める。ECDHE の共有秘密を作る。 |
| RFC 8032 | Edwards-Curve Digital Signature Algorithm (EdDSA) | https://www.rfc-editor.org/rfc/rfc8032 | Ed25519 署名の検証手順。証明書の署名検証に要る。 |
| RFC 6979 | Deterministic Usage of DSA and ECDSA | https://www.rfc-editor.org/rfc/rfc6979 | ECDSA のノンスを決定的に導き、乱数源の事故を避ける。 |
| RFC 6090 | Fundamental Elliptic Curve Cryptography Algorithms | https://www.rfc-editor.org/rfc/rfc6090 | 楕円曲線上の基本演算を定める。P-256 実装の土台。 |
| FIPS 186-4 | Digital Signature Standard (DSS) | https://csrc.nist.gov/pubs/fips/186/4/final | ECDSA P-256 署名検証の規定と曲線パラメータ。 |
| FIPS 180-4 | Secure Hash Standard (SHS) | https://csrc.nist.gov/pubs/fips/180/4/final | SHA-256 と SHA-512。ハンドシェイクのトランスクリプトと鍵導出の土台。 |
| FIPS 198-1 | The Keyed-Hash Message Authentication Code (HMAC) | https://csrc.nist.gov/pubs/fips/198/1/final | HMAC。HKDF と Finished 検証の土台。 |
| RFC 5869 | HMAC-based Extract-and-Expand Key Derivation Function (HKDF) | https://www.rfc-editor.org/rfc/rfc5869 | TLS 1.3 の鍵スケジュール全体を駆動する鍵導出関数。 |

## HTTP/3 と QPACK

QUIC の上で HTTP を話すには、HTTP の意味論を QUIC のストリームへ写し替える層が要る。
ヘッダ圧縮は HTTP/2 の HPACK をそのまま使えない。
QUIC のストリームは互いに独立して到達するため、順序に依存する HPACK ではヘッダブロック先頭行のブロッキングが再発する。
QPACK はエンコーダとデコーダの命令を別ストリームに分け、Required Insert Count で同期を取ることでこれを避ける。

| 仕様 | 正式タイトル | リンク | なぜ要るか |
|------|------------|--------|-----------|
| RFC 9114 | HTTP/3 | https://www.rfc-editor.org/rfc/rfc9114 | HTTP の意味論を QUIC ストリーム上のフレームへ写す本体。 |
| RFC 9110 | HTTP Semantics | https://www.rfc-editor.org/rfc/rfc9110 | メソッド、ステータス、ヘッダといった版に依らない HTTP の意味論。 |
| RFC 9204 | QPACK: Field Compression for HTTP/3 | https://www.rfc-editor.org/rfc/rfc9204 | ストリーム独立性のもとでヘッダブロッキングを避けるヘッダ圧縮。 |
| RFC 7541 | HPACK: Header Compression for HTTP/2 | https://www.rfc-editor.org/rfc/rfc7541 | QPACK が再利用する静的表とハフマン符号、整数符号化を定める。 |
| RFC 9218 | Extensible Prioritization Scheme for HTTP | https://www.rfc-editor.org/rfc/rfc9218 | リクエストの優先度を伝える仕組みを定める。 |

## 下位プロトコル

QUIC のパケットは、最終的に IP データグラムとして UDP に載って運ばれる。
この SDK はカーネルの IP / UDP スタックに頼らず、IPv4 ヘッダと UDP ヘッダ、そしてチェックサムまで自前で組み立てる場面があるため、これらの土台も実装範囲に入る。

| 仕様 | 正式タイトル | リンク | なぜ要るか |
|------|------------|--------|-----------|
| RFC 768 | User Datagram Protocol | https://www.rfc-editor.org/rfc/rfc768 | QUIC が載る UDP のヘッダ形式とチェックサム。 |
| RFC 791 | Internet Protocol | https://www.rfc-editor.org/rfc/rfc791 | UDP データグラムを運ぶ IPv4 ヘッダの形式。 |
| RFC 1071 | Computing the Internet Checksum | https://www.rfc-editor.org/rfc/rfc1071 | IP と UDP のチェックサム計算手順。 |
