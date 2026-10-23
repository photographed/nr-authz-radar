---
name: nr-appsec-guard
description: Detect authorization attacks (IDOR/BOLA, scope abuse, SQLi, credential stuffing, AI-agent-like scraping) from New Relic APM, Logs, Browser, Errors Inbox and Performance Risks Inbox via the New Relic Ground Truth MCP or NerdGraph, audit telemetry readiness, recommend custom attributes / agent XML, and generate alert conditions, Workflow Automation (with or without Autopilot / iRCA) and Slack notifications. Use when asked to check New Relic for attacks, assess security observability readiness, or set up security alerts in New Relic.
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
- **MCP で問い合わせるときの規則**: 集計（`count`・`uniqueCount`・`percentage`）だけを使い、`SELECT *` や生のイベントを取らない。`FACET` は `LIMIT 20` まで。`SINCE` は必要最小限。Ground Truth の **AI を使う分析系ツールは使わず**、NRQL の実行だけに使う
- **参照ファイルを丸ごと読まない**: まず `python3 <root>/scripts/catalog.py index --stage <段階>` で一覧を見て、必要な ID だけ `catalog.py show D01 I05 …` で読む
- 結果は `.authz-radar/` に保存し、**同じ期間・同じ段階の結果があれば再利用する**
- **Autopilot は CRITICAL（証拠）のアラートからだけ。** Skill からも定期の Hunt からも呼ばない
- チャットには要約だけを出し、全文は `.authz-radar/report.md` に書く

## 目的ごとの進め方
最初に依頼の目的を判定し、混ぜない。曖昧なら前提の確認から始める。リージョンは `newrelic-us`（JP は利用者が `newrelic-jp` を追加）。

| 目的 | 実行するもの | 読むもの |
|---|---|---|
| 前提の確認 | `catalog.py show R01 … R15` の NRQL（R02・R12・R13・R14・R15 が重要） | 結果の書き方は `catalog.py show` した各節の「出力形式」 |
| ① 棚卸し | `api-authz-review` Skill ＋ U01・U02 | — |
| ② 利用実態 | U01〜U06 | `shared/protocols.md`（REST 以外があるとき） |
| ③ 攻撃検知 | `python3 <root>/scripts/hunt.py --app <appName> --account-id <id> --stage <S> --sources <…> --out .authz-radar/hunt` | `hunt-summary.md`。判定基準は該当 ID だけ `catalog.py show` |
| ④ 調査 | **最初に I05〜I07**（記録が残っているか）→ I01〜I04 | `catalog.py show I01 … I07` |
| 推奨（計装・アラート） | `gen_alerts.py`・`gen_xml_candidates.py` | `references/recommendations.md` |

攻撃検知の要点:
- **D01（IDOR 成功）や D20＋D21（RCE の成功の可能性）が出たら、最初に報告する**
- **REST 以外では D04・D10 は反応しない。** 反応しないことを安全と書かず、D22 を使う。GraphQL は `api.operation` で集計する
- 兆候があれば D18（または iRCA）で「攻撃か、自分たちの変更か」を切り分け、深掘りは ④ へ
- `api-authz-review` と連携するときは、検知の結果からエンドポイント別の `attack_signal` を作る（`catalog.py show` の対象外。`detections.nrql.md` 末尾の節）

## 参照（必要なときだけ）
| 内容 | ファイル |
|---|---|
| 目的・段階・レポートの書き方・証拠の強さ | `shared/goals.md` |
| 計装・アラート・Workflow・Autopilot / iRCA | `references/recommendations.md` |
| Java / 他言語の計装 | `references/instrumentation-java.md`・`references/instrumentation-other-languages.md` |
| API の方式（GraphQL・WebSocket 等） | `shared/protocols.md` |
| データソース・属性・プライバシー | `shared/data-sources.md`・`shared/attribute-spec.md`・`shared/privacy.md` |
| 規格の番号・証拠の強さ | `shared/standards.json`・`shared/detections.json` |
