# 脅威モデル: 日本国内の不正アクセス（2026年10月時点）

> 最終確認: 2026-10-23。情報は随時更新されるため、JPCERT/CC の原文を必ず確認すること。

## JPCERT/CC 注意喚起 JPCERT-AT-2026-0030（2026-10-08）

国内組織への不正アクセスについて、以下の3つの手口が挙げられている。

1. **既知の脆弱性・管理不備の探索**
2. **API を経由した不正操作**
   - 一般公開されているスマートフォンアプリを解析し、API エンドポイントやキーを特定する
   - 内部 API への攻撃
   - 他システムの侵害で窃取した API キーの利用
3. **Metabase の SQL インジェクション脆弱性（CVE-2026-72898）の悪用**（2026-08-14 にも別途注意喚起）

推奨対策として、API の単位時間あたりリクエスト数制限、API トークンの適切な有効期限、
可能ならアクセス元地域の制限が挙げられている。

JPCERT/CC 自身が「情報は限定的かつ断片的で、すべての事案が同じ手口とは限らない」と述べている点に注意。

## AI エージェントの関与

- 民間（サイバーセキュリティクラウド, 2026-10-09）が「約40分で326のIPアドレスを使い分け、1,200件超のアクセス」
  という、AI エージェントによる攻撃の可能性を示す挙動を観測・公表。
- 一方、同時点で **個別事案で AI 使用が公式に確認された例はない** と整理する報道もある。
- 本プラグインでは「AI エージェント**らしい**挙動」として検知し、断定はしない。

## 本プラグインへの反映

| 手口 | 対応 |
|---|---|
| アプリ解析 → API 直叩き | `client.type` 属性、Browser と APM の突合、モバイル向け API の露出度を優先度に加算 |
| 内部 API への攻撃 | シャドー/ゾンビ API の検出、トラフィック0でも重大なら上位（`risk-scoring.md`） |
| 窃取 API キー | `api.key_id` × IP/地域の異常 |
| SQLi（Metabase 型） | Errors Inbox の DB 構文エラー、Vulnerability Management |
| 長寿命トークン | `auth.token_age_sec` |
| レート制限なし | F8（無制限 `size`）、API4 シグナル |

## 出典

- [ScanNetSecurity: JPCERT/CC、国内組織への不正アクセスに関する注意喚起を公開](https://scan.netsecurity.ne.jp/article/2026/10/13/56428.html)
- [SmartScope: JPCERT 注意喚起と API](https://smartscope.blog/blog/jpcert-domestic-unauthorized-access-alert-api-2026/)
- [ASCII: JPCERT/CC、3つの攻撃手法を公表](https://news.infoseek.co.jp/article/asciijp_4441170/)
- [不正アクセスと AI エージェント攻撃](https://book.st-hakky.com/news/unauthorized-access-ai-agent-attacks)
