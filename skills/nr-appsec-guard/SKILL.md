---
name: nr-appsec-guard
description: Detect authorization attacks (IDOR/BOLA, scope abuse, SQLi, credential stuffing, AI-agent-like scraping) from New Relic APM, distributed tracing, Browser and error data via the New Relic Ground Truth MCP or NerdGraph, use logs as a scoped last mile for evidence and investigation, audit telemetry readiness, recommend custom attributes / agent XML, and generate alert conditions, Workflow Automation (with or without Autopilot / iRCA) and Slack notifications. Use when asked to check New Relic for attacks, assess security observability readiness, or set up security alerts in New Relic.
---

# nr-appsec-guard — New Relic で認可攻撃に気づく

アプリ内部の文脈（認可判断・トランザクション・DB・Browser）で攻撃に気づく。プラグインのルートはこのファイルから `../../`（以下 `<root>`）。

## 守ること
1. **ユーザーの言語で出力する**（英語なら英語）。ID・属性名・番号・コードは訳さない
2. **New Relic へは読み取りのみ。** アラート・Workflow・アプリの設定やコードは **ファイルとして生成するだけ**
3. **個人データを出さない・広げない**: レポートには件数・仮名・上位の要約だけ。IP は既定で送らない設計を勧める（`shared/privacy.md`）
4. **証拠の強さで書き分ける**: 証拠 / 強い兆候 / 異常（`shared/detections.json`）。**異常だけで攻撃と書かない。** 「AI エージェントによる攻撃」と断定しない
5. **「今わかること」と「推奨」を別の節に分ける**（`shared/goals.md`）。推奨には「何がわかるようになるか」と「どの目的に効くか」を書く
6. 確認できていない機能・設定は「未確認」と書く

## コストとトークンを節約する（必ず守る）
- **まとまった問い合わせ（前提の確認・Hunt）は `scripts/hunt.py`（NerdGraph）を優先する。** Claude は `hunt-summary.md` だけを読む。API キー（`NEW_RELIC_API_KEY`）が無いときだけ MCP で実行する
- **MCP の規則**: 集計（`count`・`uniqueCount`・`percentage`）のみ。`SELECT *`・生イベントは取らない。`FACET` は `LIMIT 20`、`SINCE` は最小限。Ground Truth の **AI 分析ツールは使わず** NRQL 実行だけ
- **参照ファイルを丸ごと読まない**: `catalog.py index --stage <段階>` で一覧 → 必要な ID だけ `catalog.py show D01 I05 …`
- 結果は `.authz-radar/` に保存し、**同じ期間・同じ段階の結果があれば再利用する**
- **ログはスキャンしない。** `catalog.py show L01 …` の L01〜L04 だけを使い、APM の手がかり（トレース ID・ユーザー・時間帯）で範囲を絞る
- **Autopilot は CRITICAL（証拠）のアラートからだけ。** Skill からも定期の Hunt からも呼ばない
- チャットには要約だけを出し、全文は `.authz-radar/report.md` に書く

## 目的ごとの進め方
最初に依頼の目的を判定し、混ぜない。曖昧なら前提の確認から始める。リージョンは `newrelic-us`（JP は利用者が `newrelic-jp` を追加）。
リポジトリがあれば `scripts/find_appname.py <repo>` で appName を特定（複数・0件は確認。R17 でも可）。

| 目的 | 実行するもの | 読むもの |
|---|---|---|
| 前提の確認 | `catalog.py show R01 … R17`（まず R17 でアプリ特定、R02・R12〜R15 が重要） | 結果の書き方は `catalog.py show` した各節の「出力形式」 |
| ① 棚卸し | `api-authz-review` Skill ＋ U01・U02 | — |
| ② 利用実態 | U01〜U06 | `shared/protocols.md`（REST 以外があるとき） |
| ③ 攻撃検知 | `python3 <root>/scripts/hunt.py --app <appName> --account-id <id> --stage <S> --sources <…> --out .authz-radar/hunt` | `hunt-summary.md`。判定基準は該当 ID だけ `catalog.py show` |
| ④ 調査 | **最初に I05〜I07**（記録が残っているか）→ I01〜I04 → ログで確定（L02） | `catalog.py show I01 … I07 L02` |
| 証拠の詳細化 | D01 が出たら L01（そのトランザクションのログ行）。属性が送れない環境は L04 | `catalog.py show L01 L04` |
| 推奨（計装・アラート） | `gen_alerts.py`・`gen_xml_candidates.py` | `references/recommendations.md` |

攻撃検知の要点:
- **D01（IDOR 成功）や D20＋D21（RCE の成功の可能性）が出たら、最初に報告する**
- **REST 以外では D04・D10 は反応しない。** 反応しないことを安全と書かず、D22 を使う。GraphQL は `api.operation` で集計する
- 兆候があれば D18（または iRCA）で「攻撃か、自分たちの変更か」を切り分け、深掘りは ④ へ
- **WAF データ（`edge.verdict`・AWS WAF）があれば D25 を見て「ブロック N 件／アプリ到達は D01 等で M 件」を報告。** 無ければ「WAF 未連携」。URL 詳細は L03
- `api-authz-review` と連携するときは、検知の結果からエンドポイント別の `attack_signal` を作る（`catalog.py show` の対象外。`detections.nrql.md` 末尾の節）

## 参照（必要なときだけ）
| 内容 | ファイル |
|---|---|
| 目的・段階・レポートの書き方・証拠の強さ | `shared/goals.md` |
| 計装・アラート・Workflow・Autopilot / iRCA | `references/recommendations.md` |
| Java / PHP / Next.js / 他言語の計装 | `references/instrumentation-java.md`・`references/instrumentation-php.md`・`references/instrumentation-nextjs.md`・`references/instrumentation-other-languages.md` |
| API の方式（GraphQL・WebSocket 等） | `shared/protocols.md` |
| データソース・属性・プライバシー | `shared/data-sources.md`・`shared/attribute-spec.md`・`shared/privacy.md` |
| 規格の番号・証拠の強さ | `shared/standards.json`・`shared/detections.json` |

## 同梱スクリプト（`<root>/scripts/`。各スクリプトの目的と動作）
Claude が Bash で実行する決定的ツール。入力・出力はファイル。ネットワークへ出るのは hunt.py（NerdGraph）と ip_reputation.py（利用者が指定した評価 API）のみ。
- `hunt.py`: 検知カタログの NRQL を NerdGraph で実行し証拠の強さ別に要約（AI 不使用）
- `catalog.py`: 検知・調査・前提確認の一覧と、必要な節だけを表示（参照ファイルを丸読みしない）
- `risk_score.py`: Finding を決定的にランキング（同じ入力→同じ順位）
- `gen_alerts.py`: 段階・データソースに合うアラート条件を Terraform として生成
- `gen_xml_candidates.py`: Java エージェントの XML 計装の候補を生成（コード変更なしの経路）
- `attack_layer.py`: 段階・データソースから ATT&CK Navigator のレイヤー JSON を生成
- `find_appname.py`: リポジトリの各エージェント設定・環境変数から New Relic appName を特定
- `ip_reputation.py`: 送信元 IP を評価 DB（AbuseIPDB 等）と**ローカルで**照合（New Relic には送らない・任意）
- `inventory_java.py` / `inventory_php.py` / `inventory_python.py` / `inventory_node.py` / `inventory_ruby.py` / `inventory_go.py`: 各言語のエンドポイントと認可・怪しい箇所を正規表現で棚卸し（候補出し。`api-authz-review` が使用）

計装ライブラリの `instrumentation/java/gradlew`・`gradlew.bat` は **Gradle 公式の wrapper（生成物）**。Java ライブラリの**ビルド専用**で、スキル実行時には使わない。内部の `eval` は wrapper が POSIX シェルで引数を正しく扱うための標準実装（スクリプトのコメント参照）。
