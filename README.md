# quic_vibe

quic_vibe は、libc に依存しない QUIC / TLS 1.3 / HTTP/3 の SDK である。
x86_64 Linux の syscall を直接呼び、独自の `_start` を持ち、標準ライブラリも外部依存も使わない。
カーネルに任せるのは生の UDP 入出力だけで、パケット整形、暗号化、損失回復、輻輳制御、ストリーム、HTTP/3 はすべてユーザー空間で自前に実装する。

## ドキュメント

- [docs/arch/overview.md](docs/arch/overview.md)：ユーザー空間とカーネルの境界、5層構成、送信と受信とハンドシェイクのデータフロー。
- [docs/arch/layers.md](docs/arch/layers.md)：common / crypto / transport / tls / app の各層が解く問題と設計の勘所。
- [docs/arch/rfcs.md](docs/arch/rfcs.md)：実装した RFC と FIPS の一覧、各仕様が必要な理由。
- [docs/usage.md](docs/usage.md)：ビルドと `just` ターゲット、ソース構成、ライブラリの使い方。
- [docs/development.md](docs/development.md)：開発上の制約とワークフロー、ドメインの追加手順。

## Quick start

```sh
just build    # 各ドメインを freestanding でコンパイルする
just ninja    # 差分・並列ビルド
just test     # テストスイートを実行する
just check    # CCN ゲートとテストスイート
```

## License

MIT — see [LICENSE](LICENSE).
