# Slack 通知の形式

Workflow Automation（`security-triage.yaml` の `notify`）と、手動で投稿する場合の共通の形式。
**「今のデータでわかること」と「推奨」を分ける**（`shared/goals.md`）。

```
*[authz-radar] CRITICAL* D01 IDOR 成功の証拠 / order-api

*今のデータでわかること*
• 発火した条件: D01（段階 S2）。`GET /api/v1/orders/{id}` で owner_match=false かつ allow が 12 件（直近5分）
• 対象: 仮名化ユーザー 1 件（u_3f9a…）
• 直近2時間のデプロイ: v2.14.0（38 分前）
• Autopilot: 「デプロイ直後から発生。認可チェックの欠落の可能性」／ iRCA: デプロイが有力な原因
• 判定不能: 影響したレコードの全件（Transaction はサンプリングあり。ログで確認が必要）

*推奨*
1. ランブック: idor.md の「最初の15分」
2. 影響範囲の確認: ④ 調査 I02・I03・I04（ログで全件確定）
3. 封じ込め（承認が必要）: 該当バージョンのロールバック、または該当 API の一時停止
```

## ルール
- 生のユーザー ID・IP・メールアドレスを書かない。
- 判定できなかったことは「判定不能（理由）」として必ず書く。
- CRITICAL はメンション付きのチャンネル、HIGH（warning）は静かなチャンネルに分ける（`templates/terraform/workflows.tf`）。
