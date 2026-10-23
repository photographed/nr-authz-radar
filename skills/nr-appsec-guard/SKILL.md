---
name: nr-appsec-guard
description: Detect authorization attacks (IDOR/BOLA, scope abuse, SQLi, credential stuffing, AI-agent-like scraping) from New Relic APM, Logs, Browser, Errors Inbox and Performance Risks Inbox via the New Relic Ground Truth MCP, audit telemetry readiness, recommend custom attributes / agent XML, and generate alert conditions, Workflow Automation (with or without Autopilot / iRCA) and Slack notifications. Use when asked to check New Relic for attacks, assess security observability readiness, or set up security alerts in New Relic.
---

# nr-appsec-guard — New Relic で認可攻撃に気づく

SIEM でログを相関するのではなく、アプリ内部の文脈（認可判断・トランザクション・DB・Browser）で攻撃に気づく。

プラグインのルートはこのファイルから `../../`。共通仕様:
- `shared/attribute-spec.md` — 検知の前提となる属性
- `shared/owasp-mapping.md` — 脅威とシグナルの対応
- `shared/threat-model-2026-jp.md` — 日本国内の最新の手口
- `shared/risk-scoring.md` — 優先度の計算

## 守ること

1. **New Relic へは読み取りのみ**。アラート・Workflow・Slack 設定は **ファイルとして生成するだけ**で、適用はユーザーが行う。
2. **アプリ側の変更（`newrelic.yml`・XML・コード）も生成のみ**。再起動を伴うため本番反映は人間が判断する。
3. **PII を出力に含めない**。クエリ結果にユーザーIDや IP が含まれる場合は、レポートでは件数・ハッシュ・上位N件の要約にとどめる。
4. **断定しない**。「AI エージェントによる攻撃」は兆候として報告し、確定とは書かない。
5. 不確実な機能（iRCA の提供状況、MCP ツールの書き込み可否、JP エンドポイント URL 等）は、実際に確認できるまで「未確認」と書く。

## リージョンの選択

`.mcp.json` に `newrelic-us` と `newrelic-jp` を登録している。ユーザーの指定、またはアカウントのリージョンに応じて使い分ける。
認証は OAuth が標準（一部ツールは OAuth 専用）。API Key で接続している場合は、使えないツールがあることを最初に伝える。

## モード

ユーザーの依頼から判定する。曖昧な場合は ① から始める。

### ① Readiness 監査（何が検知できる状態か）
確認項目（Phase 2 で `references/readiness-checks.md` に NRQL を整備）:
- `shared/attribute-spec.md` の属性が届いているか（`SELECT keyset() FROM Transaction` 等）
- High-security mode の有無（有効なら属性ベース検知は不可 → Logs 経由の代替を提示）
- Browser が同じアプリに入っているか（APM と Browser の突合ができるか）
- Logs in context が有効か
- Errors Inbox / Performance Risks Inbox が使えるか
- **Autopilot / iRCA のオン・オフ**（下表の動作を切り替える）
- 計装漏れ（トランザクション名に未知のものが多い、`traffic_rpm: null` が多い）

結果は「検知できる脅威 / できない脅威」の表と、できない理由・必要な対応（属性・設定）で出す。

### ② Hunt（今起きていることを調べる）
`shared/owasp-mapping.md` のシグナルを NRQL で実行する（Phase 2 で `references/detections.nrql.md` に整備）。
結果は脅威ごとに「兆候あり / なし / 判定不能（データ不足）」で報告する。

### ③ Harden（計装の推奨）
`shared/attribute-spec.md` の3段階（yml → XML → API）で、最も手軽に済む手段を推奨する。
コードの監査と組み合わせる場合は `api-authz-review` Skill を使う。
（Phase 3 で `references/instrumentation-java.md` を整備。以降、APM エージェント対応の各言語を追加）

### ④ 生成（アラート・Workflow・Slack）
アラート条件、Alert Workflow、Workflow Automation、Slack 通知のテンプレートを **ファイルとして** 出力する（Phase 4 で `templates/` に整備）。

## Autopilot / iRCA のオン・オフによる動作

Workflow Automation は1本の定義の中で分岐させる（機能を有効にしてもテンプレートの差し替えが不要）。

| 状態 | 有事の流れ | 「攻撃か、自分たちの不具合か」の判定 |
|---|---|---|
| 両方オン | Workflow → `newrelic.autopilot.run`（iRCA の結果を含む）→ Slack スレッドで対話 | iRCA |
| Autopilot のみ | Workflow → `newrelic.autopilot.run` → Slack | Autopilot + 自前の変更相関 |
| iRCA のみ | Workflow → NRQL で情報付与 → Slack（iRCA へのリンク） | iRCA |
| 両方オフ | Workflow → NRQL で情報付与 → Slack（固定ランブック） | 自前の変更相関 |

- **自前の変更相関**: デプロイ記録（Change Tracking / Deployment）と異常の開始時刻を NRQL で突き合わせ、直前のデプロイの有無を判定する。
- **iRCA の読み方**: 内部に原因（デプロイ・資源上限）がある → 自分たちの不具合の可能性が高い。内部に原因が無い → 外部入力（攻撃）の可能性が高い。
  認可属性の挙動が変わった直前にデプロイがある → 認可チェックの欠落（IDOR の作り込み）を疑う。
- **Autopilot の上限**（1組織あたり1時間100リクエスト）を守るため、Autopilot に渡すのは Critical / High のみ。同一 Issue は1回にまとめる。
- Autopilot は推奨のみで操作を実行しない。ブロックやトークン失効は Slack の承認を経由させる。
