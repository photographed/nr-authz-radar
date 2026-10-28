# nr-authz-radar

**New Relic を使って API の認可攻撃（IDOR / BOLA・SQLi など）に気づき、ソースコードの認可の抜けを監査する Claude Code プラグイン。**

アプリに起きている「他人のデータを返してしまった」ような攻撃は、ログを見ても普通のアクセスと区別がつきません。このプラグインは、New Relic に入っているデータとソースコードの両方を Claude に読ませて、**危ない API を見つけ・優先順位を付け・調査の手がかりを出す**のを手伝います。

> コミュニティプロジェクトです。New Relic 社の公式・提携ではありません。
> **English: [README.en.md](README.en.md)**

## 何ができるの？

- **コードの認可監査** — ソースを読んで「所有者チェックが抜けている API（IDOR）」「スコープ不備」「SQLi になりそうな箇所」などを洗い出し、危険度で並べます。New Relic が無くても動きます。
- **攻撃の検知** — New Relic の APM データから、認可の失敗・SQLi や RCE の兆候・認証攻撃・自動化された不審なアクセスを拾います。
- **IDOR 成功の「証拠」** — アプリに2つの属性を送るようにすると、「実際に他人のデータを返した」ことを証拠として捕まえられます（ログだけでは不可能）。
- **アラートと通知の下ごしらえ** — New Relic のアラート・Slack 通知・調査用ランブックを、そのまま使える形で生成します（適用は人が行います）。
- **調査の手伝い** — 何かあったとき、対象ユーザー・API・時間帯を起点に「何をされたか」を追います。

誤検知を増やさないことを重視しています。ログを総当たりで攻撃文字列検索するような SIEM 的なやり方は**あえてしません**（理由は [docs/concepts.md](docs/concepts.md)）。

## 使ってみる

### インストール

```
/plugin marketplace add photographed/nr-authz-radar
/plugin install nr-authz-radar
```

### 頼んでみる

Claude にふつうの言葉で頼むだけです。

- `New Relic で攻撃の兆候を調べて`
- `このリポジトリの API の認可をレビューして`
- `IDOR を検知できる状態になっているか確認して`

**最初に読むなら [はじめに（インストールと使い方）](docs/getting-started.md)** — 何が自動で何を人がやるか、頼み方の例、サンプルのレポートがあります。

## 含まれるもの

| Skill | 役割 |
|---|---|
| `nr-appsec-guard` | 実行時: 前提の確認、利用実態、攻撃検知、調査、計装の推奨、アラート・Slack 通知の生成 |
| `api-authz-review` | コード: エンドポイントとスコープの洗い出し、IDOR/BOLA・BFLA・SQLi などの検出、実トラフィックで補正したランキング |

## ドキュメント

| 読みたいこと | ドキュメント |
|---|---|
| インストールと使い方、よくある質問 | [docs/getting-started.md](docs/getting-started.md) |
| 考え方（4つの目的・いつ使うか・方針） | [docs/concepts.md](docs/concepts.md) |
| 仕組み（IDOR などをどう判定するか） | [docs/how-it-works.md](docs/how-it-works.md) |
| リファレンス（必要なデータ・計装・アラート・ログ） | [docs/reference.md](docs/reference.md) |
| 対応範囲（OWASP・CWE・ATT&CK など、何をカバーするか） | [docs/coverage.md](docs/coverage.md) |
| **今できること / まだできないこと**（実装の現状） | [docs/status.md](docs/status.md) |
| 変更履歴・ロードマップ | [CHANGELOG.md](CHANGELOG.md) |

## 状態

**コード監査・ランキング・計装・補助スクリプトは今すぐ使えます（テスト済み）。** 一方、New Relic の検知クエリ・アラート・MCP 連携は「生成と設計」はできていますが、**実アカウントでの検証はこれから（Phase 5）** です。どこまで検証済みかは [docs/status.md](docs/status.md) に1枚でまとめています。バージョン 1.0.0 はリリースの判断をした時点で付けます。

## License

MIT
