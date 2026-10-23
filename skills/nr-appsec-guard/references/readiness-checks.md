# Readiness 監査

「今の New Relic のデータで、どの攻撃に気づけるか」を判定する。
**監視が欠けていること自体がリスク（OWASP A09）** なので、検知できない脅威はその理由と対応とあわせて報告する。

表記は `detections.nrql.md` と同じ（`{appName}`、要検証 など）。

## チェック項目

### R01 データが届いているか — 要検証

確認するデータソースと、その優先順位は `shared/data-sources.md` §1 に従う（必須 → 推奨 → 任意の順）。
```sql
SELECT count(*) FROM Transaction, TransactionError, Span, PageView, AjaxRequest, Log
WHERE appName = '{appName}' OR entity.name = '{appName}'
FACET eventType() SINCE 1 day ago
```
- 0件のイベント種別は、その種別に依存する検知を「判定不能」にする。
- `Log` が0件でも、Logs in context を使わずに別名で送っている場合がある。ユーザーに確認する。

### R02 認可属性が届いているか
```sql
SELECT keyset() FROM Transaction WHERE appName = '{appName}' SINCE 1 day ago
```
結果に以下が含まれるかを確認する（`shared/attribute-spec.md`）。

| 属性 | 無い場合に判定不能になる検知 |
|---|---|
| `authz.decision`, `resource.owner_match`, `resource.type` | D01, D02, D05 |
| `authz.required_scope`, `authz.deny_reason` | D05 |
| `enduser.id` | D02, D03, D11, D13 |
| `client.asn`, `client.country` | D11, D14（L0） |
| `edge.verdict` | D11 の補助 |
| `api.key_id` | D14 |
| `auth.token_age_sec` | D15 |
| `request.uri` | D03 |

属性はあるが、一部のトランザクションにしか付いていない場合（計装漏れ）を確認する:
```sql
SELECT percentage(count(*), WHERE authz.decision IS NOT NULL) AS coverage
FROM Transaction WHERE appName = '{appName}' AND transactionType = 'Web'
FACET name SINCE 1 day ago LIMIT MAX
```
`coverage` が 100% 未満のエンドポイントは「計装漏れ」として一覧にする（認証不要で公開しているものは除く）。

### R03 ステータスコード属性の名前
`keyset()` の結果に `http.statusCode` があれば新形式、`httpResponseCode` だけなら旧形式（文字列）。
以降の検知クエリをこれに合わせて読み替える。

### R04 High-security mode（推定）
NRQL では直接判定できない。次の状況から推定し、**ユーザーに確認する**。
- custom attribute が1つも無い、`enduser.id` が無い、`TransactionError` の `error.message` が空
- 有効なら: 属性ベースの検知（D01, D02, D05, D11, D13–D15）は不可。代替として、アプリのログに認可判断を出力し、Logs で集計する案を示す。

### R05 Browser との突き合わせ
```sql
SELECT percentage(count(*), WHERE parent.type = 'Browser') AS from_browser,
       percentage(count(*), WHERE parent.type = 'Mobile') AS from_mobile,
       percentage(count(*), WHERE parent.type IS NULL) AS no_parent
FROM Transaction WHERE appName = '{appName}' AND transactionType = 'Web' SINCE 1 day ago
```
- `from_browser` と `from_mobile` が両方 0% → Browser・Mobile の分散トレーシングが無効か、別オリジンで止まっている。D12 は判定不能。

### R06 Span の SQL 文
```sql
SELECT count(*) FROM Span
WHERE entity.name = '{appName}' AND db.statement IS NOT NULL SINCE 1 day ago
```
- 0件 → 分散トレーシングが無効、または SQL 文の記録が off。D07・D08 は判定不能。
- `record_sql` が `raw` になっていないかをユーザーに確認する（**生 SQL は個人情報を含み得るため `obfuscated` を推奨**）。

### R07 デプロイ記録（Change Tracking）— 要検証
```sql
SELECT count(*) FROM Deployment WHERE entity.name = '{appName}' SINCE 30 days ago
```
- 0件 → D18（変更相関）は判定不能。CI/CD からデプロイ記録を送るよう推奨する。iRCA の精度にも影響する。

### R08 Errors Inbox / Performance Risks Inbox
- Ground Truth MCP のツール一覧に、Errors Inbox・Performance Risks を扱うツールがあるかを確認する。
- 無い場合は、D06・D09 の NRQL で代替し、UI での確認手順を案内する。

### R09 Autopilot / iRCA のオン・オフ
NRQL では判定できない。次の順で判定する。
1. Ground Truth MCP のツール一覧に Autopilot / RCA 系のツールがあるか
2. 無ければユーザーに確認する（必要条件: Pro / Enterprise、Advanced Compute アドオン、Autopilot と Workflow の FCM）
3. 判定結果を `SKILL.md` の「Autopilot / iRCA のオン・オフによる動作」の4状態のどれかに当てはめる

### R10 MCP の認証方式
API Key で接続している場合、OAuth 専用のツールは使えない。使えなかったツールを一覧にして報告する。

### R12 トランザクション名の品質（API エンドポイントとして使えるか）
`shared/data-sources.md` §2 の基準で判定する。
```sql
SELECT count(*) FROM Transaction
WHERE appName = '{appName}' AND transactionType = 'Web'
FACET name SINCE 1 day ago LIMIT MAX
```
- 名前が数種類しかなく、`dispatcherServlet` 等にまとめられている → **まとめられすぎ**。エンドポイント別の検知（D03〜D05、D12）とコード監査との突き合わせが不可
- 数字だけのパス要素（`/12345`）や UUID を含む名前が多い → **細かすぎ**。metric grouping issue の恐れ
- パスや HTTP メソッドを含まない（`OrderController/getOrder`）→ 突き合わせはハンドラ名で行う。パスベースの命名を推奨
- GraphQL・SOAP・JSON-RPC・WebSocket は、トランザクション名ではなく `api.operation` を API の単位として使う（`shared/protocols.md`）。GraphQL のトランザクション名はクライアントが偽装できる
- 判定結果は改善項目の上位に置く（**ここが崩れていると、他の検知の多くが API 単位で機能しない**）

### R15 API の方式 — 要検証
`shared/protocols.md` の盲点を確認する。
```sql
SELECT count(*) FROM Transaction WHERE appName = '{appName}'
FACET cases(
  WHERE name LIKE '%GraphQL%' OR request.uri LIKE '%graphql%' AS 'graphql',
  WHERE http.statusCode = 101 AS 'websocket-handshake',
  WHERE name LIKE '%WebSocket%' AS 'websocket-message',
  WHERE name LIKE '%SOAP%' OR name LIKE '%Spring-WS%' OR request.uri LIKE '%soap%' AS 'soap',
  WHERE name LIKE '%gRPC%' OR name LIKE '%grpc%' AS 'grpc'
) SINCE 1 day ago
```
```sql
SELECT count(*) FROM Transaction WHERE appName = '{appName}' FACET api.protocol SINCE 1 day ago
```
- `websocket-handshake` があるのに `websocket-message` が無い → **WebSocket のメッセージが計装されていない。S2 の属性は送っても捨てられている。** 改善項目の上位に挙げる（重大度 High）
- GraphQL・SOAP・JSON-RPC があるのに `api.protocol` / `api.operation` が無い → D04・D10 は反応しない。D22 が使えるように計装を推奨する
- GraphQL があるなら、トランザクション名はクライアントの operation 名から作られる（偽装できる）ことを報告に書く
- 名前のパターンはエージェントや設定によって異なる。結果が 0 件でも方式が無いとは限らないので、ユーザーに確認する

### R11 送ってしまっている個人データ（プライバシー監査）
`shared/privacy.md` に基づき、**検知のために送る必要のない個人データ**が入っていないかを確認する。
`R02` の `keyset()` の結果から、次のような属性名を探す。
- IP: `request.headers.x-forwarded-for`、`request.headers.x-real-ip`、`client.ip`、`remote_addr`
- 連絡先: `request.parameters.email`、`email`、`phone`、`tel`
- 認証情報: `request.headers.authorization`、`request.headers.cookie`、`password`、`token`

値の形式も確認する（**値そのものはレポートに載せず、件数だけを示す**）:
```sql
SELECT count(*) FROM Transaction
WHERE appName = '{appName}' AND enduser.id RLIKE '.*@.*'
SINCE 1 day ago
```
（`enduser.id` にメールアドレスが入っていないか。同様に IP 形式 `[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+` も確認する）

- Span の `db.statement` が生 SQL（`record_sql: raw`）になっていないか（R06）
- Log に IP やメールアドレスがそのまま入っていないか。入っていれば、ログの難読化ルール・drop rules を推奨する
- 見つかったものは「削除・難読化の推奨」として報告し、重大度は **High** とする（漏えい時の影響が大きいため）

### R13 サンプリング（④ 調査の前提）
`investigation.nrql.md` の I05 を、直近1日で実行する。イベントがメトリクスより大幅に少なければ、
APM の `Transaction` はサンプリングされている。**④ 調査で全件を答えるにはログが必要**と判定する。

### R14 保存期間（④ 調査の前提）
`investigation.nrql.md` の I06・I07 を実行し、APM とログの実質的な保存期間を記録する。
期間が短い場合（例: 攻撃に気づくまでの時間より短い）は、推奨に保存期間の延長または定期的なエクスポートを挙げる。

## 出力形式

`shared/goals.md` の「レポートの書き方」に従い、2つの節に分ける。

### 節1: 今のデータでわかること・できること

**現在の段階とデータソース**
- 段階: S0 / S1 / S2 / S3（R02 の属性の有無から判定）
- データソース: APM、分散トレーシング、Browser、Logs、Change Tracking、…（R01・R05〜R07）

**目的ごとの状況**
| 目的 | 状況 | 理由 |
|---|---|---|
| ① 棚卸し | ⚠️ 一部 | トランザクション名がまとめられすぎ（R12）。コード監査との突き合わせはハンドラ名で行う |
| ② 利用実態 | ✅ できる | APM と Browser あり |
| ③ 攻撃検知 | ⚠️ 一部 | S0 のため D01（IDOR 成功）は判定不能。D04・D06〜D10 等は可能 |
| ④ 調査 | ⚠️ 一部 | ログが無く（R14）、Transaction はサンプリングあり（R13）。全件での確定は不可 |

**検知ごとの状況**
| 脅威 | 検知 | 状態 | 理由 |
|---|---|---|---|
| IDOR 成功 | D01 | ❌ 判定不能 | `resource.owner_match` が無い（段階 S2 未満） |
| ID 列挙 | D03 | ✅ 可能 | `request.uri` と `enduser.id` あり |
| SQLi（エラー） | D06 | ⚠️ 一部 | High-security mode のため `error.class` のみで判定 |

### 節2: 推奨（段階的に）

効果の大きい順に並べる。各項目に次の3つを書く。
- **作業**（計装の手段: yml / XML / API / 設定 / データソースの追加）
- **これでわかるようになること**（有効になる検知・調査）
- **効く目的**（①〜④）

**D01（IDOR 成功）が判定不能なら、S2 の2属性の導入を必ず最上位に挙げる。**
