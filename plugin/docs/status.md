# 現状: 今できること / まだできないこと

**このツールは「コードとローカルで完結する部分」はテスト済みで今すぐ使えます。一方、「New Relic の実アカウントに依存する部分」（検知クエリ・アラート・MCP 連携）は、まだ実データで検証していません（Phase 5）。** 混同しないよう、ここで切り分けます。

区分: ✅ 検証済み（自動テストまたは実動作で確認） / ⚠️ コードはあるが実環境で未検証 / ❌ 未実装（設計のみ） / 🔜 今後

## ✅ 今すぐ使える（検証済み）

| 機能 | 状態 | 根拠 |
|---|---|---|
| **コードの認可監査**（IDOR・SQLi・BFLA 等の候補出し） | ✅ | `inventory_{java,php,python,node,ruby,go}.py` に単体テスト。New Relic 不要 |
| **危険度ランキング** | ✅ | `risk_score.py`（決定的・テストあり） |
| **リポジトリ→appName の特定** | ✅ | `find_appname.py`（テストあり） |
| **不審 IP の照合**（ローカル・AbuseIPDB） | ✅ | `ip_reputation.py`（テストあり。New Relic には送らない） |
| **アラート条件の生成（Terraform ファイル）** | ✅ 生成まで | `gen_alerts.py`。段階・データソースで出し分け。**ただし適用・検証は未**（下記 ⚠️） |
| **ATT&CK Navigator レイヤーの生成** | ✅ | `attack_layer.py`（テストあり） |
| **計装ライブラリ: Java** | ✅ | Spring Boot 3.5 / 4.1 で単体＋結合テスト |
| **計装ライブラリ: PHP（Laravel 12 / 素の PHP）** | ✅ | 単体テスト＋脆弱デモを **PHP 8.5.11** で実動作確認 |
| **計装ヘルパー: Next.js（App Router）** | ✅ | 単体テスト＋脆弱デモを **Next.js 15** で実動作確認 |
| **計装ファイル: Python・Node.js・Ruby・Go** | ✅ | 単体テスト（API は実パッケージで確認） |
| **手元で試せる脆弱デモ** | ✅ | `examples/php-vuln-site`・`examples/nextjs-vuln-site`（ローカル専用） |

テスト件数: Python 118 件 / Node.js 13 件（すべてパス）。

## ⚠️ コードはあるが、実アカウント・実環境で未検証（Phase 5）

| 機能 | 状態 | 残っていること |
|---|---|---|
| **攻撃検知の NRQL（D01〜D25）** | ⚠️ 要検証 | クエリは書いてあるが、**New Relic の実アカウントでは未実行**。属性名・イベント名の読み替えが要る可能性 |
| **New Relic MCP（Ground Truth）接続** | ⚠️ 未接続 | 設定はあるが、この開発環境では接続できていない（プロキシが 403）。OAuth の実接続は利用者側で要確認 |
| **Terraform の適用** | ⚠️ `fmt` のみ | provider を使った `terraform validate` / `apply` は未実施 |
| **Workflow Automation（`security-triage.yaml`）** | ⚠️ 下書き | 一部のアクション名・入出力を公式テンプレートと要照合 |
| **Autopilot / iRCA 連携** | ⚠️ 下書き | Workflow から呼ぶ形の下書き。未検証 |
| **計装が New Relic に実際に属性を届けること** | ⚠️ 未確認 | ライブラリの動作はテスト済みだが、実エージェント経由で属性が届くかは Phase 5。導入時に R02 で確認する前提 |

## ❌ 未実装（設計はある）

| 機能 | 状態 |
|---|---|
| **計装: .NET** | ファイルはあるが**未コンパイル**（この環境に .NET SDK が無い） |
| **Errors Inbox の状態連携**（未対応／解決済みの反映） | 設計のみ（[`shared/inbox-integration.md`](../shared/inbox-integration.md)）。元データ `TransactionError` は使用済み |
| **Performance Risks Inbox の取り込み** | 設計のみ。実データでの取り出し方を確認してから |

## 🔜 今後（ロードマップ）

- **Phase 5: 実アカウントでの検証**（上の ⚠️ を順に潰す）。これが済んで初めて 1.0.0。
- 各言語のフレームワーク統合（Django / Rails / Express / Symfony など「入れるだけ」の形）。
- 無人の定期実行テンプレート（スケジュール実行・GitHub Actions）。

変更履歴は [CHANGELOG.md](../CHANGELOG.md)。

---

**一言でいうと**: コード監査・ランキング・計装・補助スクリプトは**今すぐ使えます**。New Relic の検知・アラート・自動化は**「生成と設計」はできていて、実アカウントでの検証がこれから**です。
