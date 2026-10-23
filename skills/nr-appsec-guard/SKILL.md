---
name: nr-appsec-guard
description: Detect authorization attacks (IDOR/BOLA, scope abuse, SQLi, credential stuffing, AI-agent-like scraping) from New Relic APM, Logs, Browser, Errors Inbox and Performance Risks Inbox via the New Relic Ground Truth MCP, audit telemetry readiness, recommend custom attributes / agent XML, and generate alert conditions, Workflow Automation (with or without Autopilot / iRCA) and Slack notifications. Use when asked to check New Relic for attacks, assess security observability readiness, or set up security alerts in New Relic.
---

# nr-appsec-guard — New Relic で認可攻撃に気づく

SIEM でログを相関するのではなく、アプリ内部の文脈（認可判断・トランザクション・DB・Browser）で攻撃に気づく。

プラグインのルートはこのファイルから `../../`。共通仕様:
- `references/instrumentation-java.md` — Java の計装（S2 への最短経路）
- `shared/goals.md` — **4つの目的・段階（S0〜S3）・レポートの書き方**（最初に読む）
- `shared/data-sources.md` — 必要なデータソース、トランザクション名の品質、API 設計の突き合わせ
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

プラグインは `newrelic-us` を登録している。JP リージョンのアカウントでは、ユーザーが `newrelic-jp` を追加する（README 参照）。
接続できているサーバーを確認し、ユーザーの指定またはアカウントのリージョンに応じて使い分ける。`newrelic-jp` が無いのに JP のアカウントを指定された場合は、追加方法を案内する。
認証は OAuth が標準（一部ツールは OAuth 専用）。API Key で接続している場合は、使えないツールがあることを最初に伝える。

## 目的とモード

扱う問題は4つの別々の目的に分かれる（`shared/goals.md`）。ユーザーの依頼がどの目的かを最初に判定し、**混ぜない**。

| 目的 | 使うもの |
|---|---|
| ① 棚卸し | `api-authz-review` Skill（コード）＋ `references/usage.nrql.md` の U01・U02 |
| ② 利用実態 | `references/usage.nrql.md`（U01〜U05） |
| ③ 攻撃検知 | `references/detections.nrql.md`（D01〜D21） |
| ④ 調査 | `references/investigation.nrql.md`（I01〜I07） |

どの目的でも、最初に **前提の確認**（Readiness）を行う。依頼が曖昧なら Readiness から始める。

### 前提の確認（Readiness）
`references/readiness-checks.md` の R01〜R14 を順に実行し、**現在の段階（S0〜S3）とデータソース**を判定する。
- 認可属性が届いているか、全エンドポイントに付いているか（計装漏れ）
- High-security mode の有無（推定 + ユーザーに確認）
- Browser / Mobile との分散トレーシング、Span の SQL 文、デプロイ記録
- トランザクション名の品質（R12）、プライバシー（R11）
- サンプリングと保存期間（R13・R14。④ 調査の前提）
- Errors Inbox / Performance Risks Inbox を MCP で扱えるか、**Autopilot / iRCA のオン・オフ**

### ② 利用実態
`references/usage.nrql.md` を実行する。攻撃かどうかは判定しない。結果は ① 棚卸しの突き合わせと、優先度の `traffic_rpm` に使う。

### ③ 攻撃検知（Hunt）
`references/detections.nrql.md` のうち、**現在の段階とデータソースで実行できるものだけ**を実行する。
- 実行順: D01（IDOR 成功）→ A 認可 → B SQLi → E RCE → C 認証・AI エージェント → D 例外・変更相関
- **D01 で1件でも見つかったら、他の検知より先にユーザーへ報告する。D20 と D21 が同じ時間帯に出たときも同様**（RCE の可能性が高い）。
- 「要検証」のクエリがエラーになったら、簡略化して再試行し、その旨を報告する。
- 結果は脅威ごとに `strong` / `weak` / `none` / 判定不能（理由）で報告する。
- 兆候がある場合は D18（または iRCA）で「攻撃か、自分たちの変更か」を切り分ける。兆候の対象を深掘りするなら ④ 調査に進む。
- `api-authz-review` と連携する場合は、同ファイル末尾のルールでエンドポイント別の `attack_signal` を作る。

### ④ 調査
`references/investigation.nrql.md` の手順に従う。**最初に I05〜I07 で記録が残っているかを確かめ**、APM は手がかり、ログで確定させる。
「取得された可能性がある」と「取得された（ログで確認済み）」を区別して書く。

### 推奨の作成（計装・アラート）
- 計装: `shared/attribute-spec.md` の **計装の手段**（yml → XML → API）から、最も手軽に済むものを推奨する。次の段階（S1〜S3）に進むために必要な作業として示す。
  コードの監査と組み合わせる場合は `api-authz-review` Skill を使う。
  - Java（Spring Boot / Spring Security）: `references/instrumentation-java.md`。計装ライブラリ（`instrumentation/java/`）で **S2 に最短で到達**できる。まず OBSERVE モードを推奨する。
  - 他の言語: 未整備。`shared/attribute-spec.md` の属性名を守って、各言語のエージェント API で実装するよう推奨する。
- アラート条件・Alert Workflow・Workflow Automation・Slack 通知: テンプレートを **ファイルとして** 出力する（今後追加予定）。

## レポートの書き方（必ず守る）

`shared/goals.md` の「レポートの書き方」に従い、**「今のデータでわかること・できること」と「推奨（段階的に）」を別の節に分ける。**
- 前者には、現在の段階・データソース・実行した確認の結果だけを書く。できなかったものは「判定不能（理由）」と書く。
- 後者の各項目には、**それをやると何がわかるようになるか**と**どの目的に効くか**を書く。
- 推測で「今わかること」を埋めない。

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
