# 認可テレメトリ属性仕様

> **スキーマバージョン: 0.3**（プラグイン本体とは別に管理する。アプリ側が実装する約束事のため、属性の追加・名前変更・削除のたびに上げ、`CHANGELOG.md` に記録する）

`nr-appsec-guard`（実行時検知）と `api-authz-review`（コード監査）の両方がこの仕様を前提にする。
**属性名は全言語共通**。同じ NRQL / アラートが言語を問わず動くようにするため、勝手に名前を変えないこと。

## なぜ必要か

IDOR / BOLA は攻撃が成功すると **200 OK** で返る。エラーにもレイテンシ悪化にもならないため、
Errors Inbox・Performance Risks Inbox・既定のアラートでは原理的に検知できない。
「認可の判断結果」をアプリが自分で送らない限り、New Relic からは見えない。

## 段階ごとの最小セット

| 段階 | 属性 |
|---|---|
| S1 | `enduser.id` |
| **S2（最小限のコード）** | **`resource.owner_match`、`authz.decision`**（＋ `enduser.id`）。これだけで D01（IDOR 成功の証拠）が使える。**REST 以外の方式では ＋ `api.protocol`・`api.operation`**（`shared/protocols.md`） |
| S3 | 下表の残り（`resource.check_count` など） |

S2 以外の属性には代わりの手段がある（`shared/goals.md`）。**まず S2 から入れる。**

## 属性一覧

送信先はすべて **Transaction（および同トランザクション内の TransactionError / Span）** の custom attribute。

| 属性 | 型 | 例 | 必須度 | 説明 |
|---|---|---|---|---|
| `enduser.id` | string | `u_9f3a…`（ハッシュ） | **必須** | 要求者。New Relic 標準のユーザー属性。**生ID・メールは送らない** |
| `tenant.id` | string | `t_123` | 推奨 | マルチテナントの場合のテナント |
| `authz.required_scope` | string | `orders:read` | **必須** | このエンドポイントが要求するスコープ / 権限 |
| `authz.granted_scopes` | string | `orders:read,profile` | 推奨 | トークンが持つスコープ（カンマ区切り・ソート済み）。過剰付与の発見用 |
| `authz.decision` | string | `allow` / `deny` | **必須** | 認可判断の結果 |
| `authz.deny_reason` | string | `owner_mismatch` / `scope_missing` / `role_missing` / `tenant_mismatch` / `unauthenticated` | deny時必須 | 拒否理由（列挙値のみ） |
| `resource.type` | string | `order` | **必須** | アクセス対象リソースの種別 |
| `resource.owner_match` | boolean | `true` / `false` | **必須（IDOR検知の核）** | データ取得層で「要求者 = 所有者 / 同テナントか」を判定した結果 |
| `api.protocol` | string | `rest` / `graphql` / `soap` / `grpc` / `websocket` / `jsonrpc` | REST 以外は必須 | API の方式。ステータスコードを使う検知が使えるかの判断に使う（`shared/protocols.md`） |
| `api.operation` | string | `Query.order` / `getOrder` / `/topic/orders/{id}` | REST 以外は必須 | **サーバー側で決まる**操作の名前（GraphQL のフィールド、SOAP の操作、WebSocket の宛先のテンプレート）。**クライアントが付ける GraphQL の operation 名は使わない**（偽装できるため） |
| `resource.check_count` | int | `37` | 任意（S3） | 1つのトランザクションで行った所有者照合の回数。GraphQL のエイリアスや WebSocket での一括列挙の検知（D23） |
| `client.type` | string | `web` / `mobile` / `api_key` / `service` / `unknown` | 推奨 | 呼び出し元の種別。アプリ解析による API 直叩きの検出用 |
| `client.asn` | string | `AS2516` | 推奨 | 送信元の AS 番号（エッジや GeoIP で判定）。**IP を送らずに**分散アクセスを粗く検知するため |
| `client.country` | string | `JP` | 推奨 | 送信元の国。API キーの異常利用・地域制限の検討用 |
| `edge.verdict` | string | `allow` / `challenge` / `block` / `bot` | 推奨 | WAF / CDN の判定結果。IP 粒度の分析はエッジに任せ、結果だけを受け取る |
| `client.ip_hmac` | string | `ip_7c1e…` | **オプトイン（L1）** | 送信元 IP の秘密鍵付き HMAC（鍵は日次で入れ替え）。**既定では送らない。** 送る前に `shared/privacy.md` を確認し法務と合意すること |
| `api.key_id` | string | `k_1a2b3c4d`（ハッシュ先頭8文字） | api_key時推奨 | 窃取キーの使い回し検出用 |
| `auth.token_age_sec` | int | `86400` | 任意 | トークン発行からの経過秒。長寿命トークンの検出用 |

### 最重要シグナル

```
resource.owner_match = false AND authz.decision = 'allow'
```

これは「他人のデータを返した」ことを意味する。**1件でも Critical**。誤検知になるのは「管理者や
サポート担当が正当に他人のデータを見る」場合だけなので、その経路では `authz.required_scope` に
`admin:*` 等を入れて除外できるようにする。

## 設計ルール

1. **PII を送らない**: `enduser.id`・`api.key_id` は秘密鍵付き HMAC（単純なハッシュは総当たりで戻せる）。
   **IP アドレスは既定で送らない**（GDPR では個人データ、日本法でも個人関連情報に当たり得る）。詳細は `shared/privacy.md`。
2. **カーディナリティを抑える**: リソースID・URL のクエリ文字列・自由文は属性にしない。
   `authz.deny_reason` と `client.type` は上表の列挙値のみ。
3. **deny は expected error として記録**: 例外を `noticeError(…, expected=true)` で送ると Errors Inbox で
   グルーピングされつつ、エラー率・Apdex を汚さない。
4. **High-security mode との関係**: HSM 有効時は custom attribute / user 属性が送れない。
   その場合は Readiness 監査で「属性ベース検知は不可」と判定し、代替（Logs 経由）を提示する。
5. **上限**: エージェントには custom attribute 数・値長の上限がある（目安: 1イベント64個、値255文字。
   エージェント・バージョンごとに要確認）。本仕様は最大18個に収めている。

## 計装の手段（Java の場合）

| 手段 | 方法 | コード変更 | 取れる属性 |
|---|---|---|---|
| ① 設定のみ | `newrelic.yml`（servlet-user 計装、`attributes.include`） | 不要 | `enduser.id`（ハッシュ化はできない点に注意） |
| ② XML | `extensions/*.xml` の `<type attributeName="…">` / Custom Instrumentation Editor | 不要 | 引数をそのまま記録できるもののみ（`resource.type` 等）。**比較が要る `owner_match` は不可** |
| ③ API | `NewRelic.addCustomParameter` / `setUserId` / `noticeError` | 必要 | **全属性** |

Skill は ①→②→③ の順に「最も手軽に済む手段」を推奨し、③が必要な理由を明示する。
「手段」はどう入れるか、`shared/goals.md` の「段階（S0〜S3）」はどこまで入れるか、という別の軸。
言語別の実装: Java は `skills/nr-appsec-guard/references/instrumentation-java.md` と計装ライブラリ `instrumentation/java/`（S2 は既定の `attributes: MINIMAL`、S3 は `FULL`）。他の言語は未整備。
