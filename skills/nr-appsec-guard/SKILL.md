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
- `shared/privacy.md` — データ最小化・IP の扱い
- `shared/standards.json` — 検知ごとの CWE・ASVS・OWASP・OAT・IPA

## 守ること

1. **New Relic へは読み取りのみ**。アラート・Workflow・Slack 設定は **ファイルとして生成するだけ**で、適用はユーザーが行う。
2. **アプリ側の変更（`newrelic.yml`・XML・コード）も生成のみ**。再起動を伴うため本番反映は人間が判断する。
3. **データは最小限に**。IP アドレスは既定で送らない設計を推奨する（`shared/privacy.md`）。IP の利用を提案するときは、必ず法務確認が必要な旨を添える。
4. **PII を出力に含めない**。クエリ結果にユーザーIDや IP が含まれる場合は、レポートでは件数・ハッシュ・上位N件の要約にとどめる。
5. **断定しない**。「AI エージェントによる攻撃」は兆候として報告し、確定とは書かない。
6. 不確実な機能（iRCA の提供状況、MCP ツールの書き込み可否、JP エンドポイント URL 等）は、実際に確認できるまで「未確認」と書く。

## リージョンの選択

`.mcp.json` に `newrelic-us` と `newrelic-jp` を登録している。ユーザーの指定、またはアカウントのリージョンに応じて使い分ける。
認証は OAuth が標準（一部ツールは OAuth 専用）。API Key で接続している場合は、使えないツールがあることを最初に伝える。

## モード

ユーザーの依頼から判定する。曖昧な場合は ① から始める。

### ① Readiness 監査（何が検知できる状態か）
`references/readiness-checks.md` の R01〜R11 を順に実行する（R11 はプライバシー監査）。主な確認項目:
- 認可属性が届いているか、全エンドポイントに付いているか（計装漏れ）
- High-security mode の有無（推定 + ユーザーに確認）
- Browser / Mobile との分散トレーシング、Span の SQL 文、デプロイ記録
- Errors Inbox / Performance Risks Inbox を MCP で扱えるか
- **Autopilot / iRCA のオン・オフ**（下表の動作を切り替える）

結果は同ファイルの「出力形式」に従い、「検知できる脅威 / できない脅威」と改善項目（効果の大きい順）で出す。

### ② Hunt（今起きていることを調べる）
`references/detections.nrql.md` の D01〜D18 のうち、Readiness 監査で前提を満たしたものだけを実行する。
- 実行順: D01（IDOR 成功）→ A 認可 → B SQLi → C 認証・AI エージェント → D インベントリ・変更相関
- **D01 で1件でも見つかったら、他の検知より先にユーザーへ報告する。**
- 「要検証」のクエリがエラーになったら、簡略化して再試行し、その旨を報告する。
- 結果は脅威ごとに `strong` / `weak` / `none` / 判定不能（理由）で報告する。
- 兆候がある場合は D18（または iRCA）で「攻撃か、自分たちの変更か」を切り分ける。
- `api-authz-review` と連携する場合は、同ファイル末尾のルールでエンドポイント別の `attack_signal` を作る。

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
