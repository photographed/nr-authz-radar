# 推奨の作り方（計装・アラート・Autopilot / iRCA）

`SKILL.md` から、推奨を作るときに読む。

## 計装とアラート
- 計装: `shared/attribute-spec.md` の **計装の手段**（yml → XML → API）から、最も手軽に済むものを推奨する。次の段階（S1〜S3）に進むために必要な作業として示す。
  コードの監査と組み合わせる場合は `api-authz-review` Skill を使う。
  - Java（Spring Boot / Spring Security）: `references/instrumentation-java.md`。計装ライブラリ（`instrumentation/java/`）で **S2 に最短で到達**できる。まず OBSERVE モードを推奨する。
  - Python・Node.js・Ruby・Go・PHP・.NET: `references/instrumentation-other-languages.md`（`instrumentation/<言語>/` のファイルを取り込む。PHP は API 名が未確認、.NET は未コンパイル）。
  - XML（コード変更なし）: `scripts/gen_xml_candidates.py <src>` で認可チェックのメソッドを探し、XML の候補とレポートを出す。値の比較はできないので S2 にはならない。
- アラート条件・Alert Workflow・Slack 通知: **前提の確認で判定した段階とデータソース**を使って、ファイルとして生成する（適用はユーザーが行う）。
  ```bash
  python3 <plugin-root>/scripts/gen_alerts.py --stage S2 --sources spans,browser_dt --out <出力先>
  ```
  - 生成されるのは、今の段階とデータソースで動くアラートだけ（定義は `shared/alerts.json`）。生成しなかったものは `SKIPPED.md` に「何があれば追加できるか」付きで出るので、レポートの「推奨」に使う。
  - Slack の Destination は New Relic の画面で作成する必要がある（OAuth のため）。その ID を変数で渡す。
  - **証拠の強さで振り分ける**: 証拠 → CRITICAL（通知・Autopilot）、強い兆候 → HIGH（静かなチャンネル。`learning_mode` の間は通知しない）、異常 → 既定では生成しない（`--include-anomaly` で通知しないポリシーに入れる）。
- Workflow Automation: `templates/workflow-automation/security-triage.yaml`（**下書き・未検証**）。Autopilot / iRCA のオン・オフは入力値で切り替える。プロンプトの説明は `templates/autopilot/security-prompt.md`。
- Knowledge: `templates/knowledge-runbooks/` を New Relic Knowledge に登録するよう推奨する（Autopilot が調査中に参照する。アラート条件の `runbook_url` からもリンクされる）。
- Slack の通知形式: `templates/slack/security-alert.md`（「今わかること」と「推奨」を分ける）。


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
- **Autopilot の上限**（1組織あたり1時間100リクエスト）を守るため、Autopilot に渡すのは **CRITICAL（証拠の強さが「証拠」の検知）だけ**。同一 Issue は1回にまとめる。定期の Hunt からは呼ばない。
- Autopilot は推奨のみで操作を実行しない。ブロックやトークン失効は Slack の承認を経由させる。
