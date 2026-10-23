# 検知 NRQL カタログ (v0.2)

Hunt モードで実行するクエリ集。各検知は **前提条件**（`readiness-checks.md` の判定結果）を満たすものだけ実行し、
満たさないものは「判定不能（理由）」として報告する。

## 表記

- `{appName}`: 対象アプリ名。`{since}`: 既定は `1 day ago`。`{baseline}`: 既定は `7 days ago`。
- **要検証**: 構文・挙動を実アカウントで未確認のクエリ。Phase 5 で検証する。結果がエラーになった場合はクエリを簡略化して再試行し、その旨を報告する。
- 判定は `strong` / `weak` / `none` / `unknown`（データ不足）。`api-authz-review` の `attack_signal` にそのまま渡せる。
- ステータスコード属性は、エージェントのバージョンによって `http.statusCode`（新）か `httpResponseCode`（旧・文字列）になる。
  Readiness 監査 R03 の結果に合わせて読み替える。以下は `http.statusCode` で記載。

## 前提の凡例

| 記号 | 前提 |
|---|---|
| ATTR | `shared/attribute-spec.md` の認可属性（コード計装が必要） |
| UID | `enduser.id`（yml 設定でも可） |
| URI | `request.uri`（Java エージェントは既定で送信） |
| SPAN | 分散トレーシングの Span（`db.statement` を含む） |
| BRW | Browser エージェント + 分散トレーシング |
| IP | `client.ip_hash`（APM は既定でクライアント IP を送らないため計装が必要）または IP を含むアクセスログ |
| DEP | Change Tracking（デプロイ記録） |

---

## A. 認可（IDOR / BOLA / スコープ）

### D01 IDOR 成功の証拠 — 前提 ATTR — **最重要**
```sql
SELECT count(*) FROM Transaction
WHERE appName = '{appName}' AND resource.owner_match IS FALSE AND authz.decision = 'allow'
FACET name, resource.type SINCE {since}
```
- 判定: 1件以上 → `strong`
- アラート候補: **Critical**（静的しきい値 > 0）
- 誤検知: 管理者・サポートの正当なアクセス。`authz.required_scope LIKE 'admin:%'` 等で除外する。

### D02 他人のリソースへのアクセス試行（拒否された分）— 前提 ATTR, UID
```sql
SELECT count(*) FROM Transaction
WHERE appName = '{appName}' AND authz.decision = 'deny' AND authz.deny_reason = 'owner_mismatch'
FACET enduser.id SINCE {since} LIMIT 20
```
- 判定: 1ユーザーが 20件以上 → `strong`、5件以上 → `weak`（しきい値は平常時の分布を見て調整）
- 意味: 攻撃が**防げている**状態だが、同じ攻撃者が守られていない別の API を探している可能性が高い。

### D03 ID 列挙（コード変更なしで使える）— 前提 URI, UID
```sql
SELECT uniqueCount(request.uri) AS distinct_ids, count(*) AS requests
FROM Transaction
WHERE appName = '{appName}' AND name LIKE '%{%}%'
FACET enduser.id, name SINCE 1 hour ago LIMIT 20
```
- `name LIKE '%{%}%'` はパス変数を含むトランザクション名（例: `.../orders/{id} (GET)`）。命名形式が違う環境では対象の `name` を列挙して指定する。
- 判定: 1ユーザーが1時間に 100 以上の異なる ID → `strong`、30 以上 → `weak`
- 誤検知: 一覧画面からの詳細の連続表示。Browser のセッションと突き合わせる（D12）。

### D04 404 / 403 比率の急上昇 — 前提なし
```sql
SELECT percentage(count(*), WHERE http.statusCode IN (403, 404)) AS deny_or_notfound
FROM Transaction WHERE appName = '{appName}'
FACET name SINCE {since} COMPARE WITH {baseline}
```
- 判定: 平常時の5倍以上 → `strong`、2倍以上 → `weak`
- 意味: 属性が無くても使える、列挙・探索の汎用シグナル。

### D05 スコープ不足・管理系への到達 — 前提 ATTR
```sql
SELECT count(*) FROM Transaction
WHERE appName = '{appName}' AND authz.decision = 'deny' AND authz.deny_reason IN ('scope_missing', 'role_missing')
FACET authz.required_scope, enduser.id SINCE {since} LIMIT 20
```
- 判定: `admin:` 系スコープへの拒否が同一ユーザーから 10件以上 → `strong`

---

## B. SQL インジェクション

### D06 DB 構文エラー（Errors Inbox と同じデータ）— 前提なし
```sql
SELECT count(*) FROM TransactionError
WHERE appName = '{appName}' AND (
  error.class IN ('java.sql.SQLSyntaxErrorException',
                  'org.springframework.jdbc.BadSqlGrammarException',
                  'org.hibernate.exception.SQLGrammarException',
                  'org.springframework.dao.InvalidDataAccessResourceUsageException')
  OR error.message LIKE '%syntax error%'
  OR error.message LIKE '%You have an error in your SQL syntax%'
  OR error.message LIKE '%unterminated quoted string%'
  OR error.message LIKE '%Unclosed quotation mark%'
  OR error.message LIKE '%ORA-00933%' OR error.message LIKE '%ORA-01756%'
)
FACET transactionName, error.class SINCE {since}
```
- 判定: 平常時0件のトランザクションで発生 → `weak`、同一トランザクションで10件以上 → `strong`
- **Errors Inbox との関係**: 同じエラーが Errors Inbox で新しいエラーグループとして現れる。Hunt では、
  直近で**初めて出現したグループ**かどうかを `SINCE {baseline}` の結果と比べて判定する。
- 注意: High-security mode では `error.message` が送られないため、`error.class` だけで判定する。

### D07 注入らしい SQL 文 — 前提 SPAN — 要検証
```sql
SELECT count(*) FROM Span
WHERE entity.name = '{appName}' AND db.statement IS NOT NULL
  AND db.statement RLIKE '(?i).*(sleep|pg_sleep|waitfor delay|benchmark|information_schema|union select|union all select).*'
FACET name, db.statement SINCE {since} LIMIT 20
```
- 着眼点: `db.statement` は値が `?` に置き換えられて送られる（obfuscated）が、**関数名や構文は残る**。
  文字列連結で組み立てた SQL に攻撃文字列が混ざると、`SLEEP(?)` や `UNION SELECT` のような形がそのまま見える。
- 判定: 1件以上 → `strong`（ただし、アプリが正当に `information_schema` を参照していないか確認する）
- 注意: Span はサンプリングされるため、0件でも攻撃が無いとは言えない。

### D08 SQL の形のばらつき（文字列連結の兆候）— 前提 SPAN — 要検証
```sql
SELECT uniqueCount(db.statement) FROM Span
WHERE entity.name = '{appName}' AND db.statement IS NOT NULL
FACET name SINCE {since} COMPARE WITH {baseline}
```
- 意味: プレースホルダを使った SQL は形が一定。文字列連結の SQL に攻撃が来ると、形の種類が急増する。
- 判定: 平常時の3倍以上 → `weak`（D07 と同時なら `strong`）

### D09 時間差を使う Blind SQLi — 前提なし
```sql
SELECT percentile(databaseDuration, 50, 99), max(databaseDuration)
FROM Transaction WHERE appName = '{appName}' AND databaseDuration IS NOT NULL
FACET name SINCE {since}
```
- 着眼点: `SLEEP(5)` 型の攻撃では、DB 時間が「普段の値」と「ちょうど数秒」の二山に分かれる。
- 判定: p99 または max が p50 の 50 倍以上で、かつ 3〜10 秒付近に集中 → `weak`
- Performance Risks Inbox（slow SQL・クエリ過多）にも同じ兆候が出るので、あわせて確認する。

---

## C. 認証攻撃・AI エージェントらしい挙動

### D10 認証失敗の急増 — 前提なし
```sql
SELECT count(*) FROM Transaction
WHERE appName = '{appName}' AND http.statusCode = 401
FACET name SINCE 1 hour ago COMPARE WITH 1 week ago TIMESERIES 5 minutes
```
- 判定: 先週同時刻の5倍以上 → `strong`、2倍以上 → `weak`

### D11 分散アクセス（少数アカウント × 多数 IP）— 前提 IP, UID
```sql
SELECT uniqueCount(client.ip_hash) AS ips, count(*) AS requests
FROM Transaction WHERE appName = '{appName}'
FACET enduser.id SINCE 1 hour ago LIMIT 20
```
- 判定: 1アカウントで1時間に 50 IP 以上 → `strong`、10 IP 以上 → `weak`
  （参考: 40分で326 IP・1,200件超という観測報告がある。`shared/threat-model-2026-jp.md`）
- `client.ip_hash` が無い場合: アクセスログ（ALB / CloudFront / nginx）を Logs に送っていれば、同じ集計を `Log` に対して行う。

### D12 ブラウザを経由しない API 直叩き — 前提 BRW — 要検証
```sql
SELECT percentage(count(*), WHERE parent.type IS NULL) AS no_trace_parent
FROM Transaction WHERE appName = '{appName}' AND transactionType = 'Web'
FACET name SINCE {since} COMPARE WITH {baseline}
```
- 着眼点: Browser から分散トレーシング付きで呼ばれた API は `parent.type = 'Browser'` になる（モバイルなら `'Mobile'`）。
  親が無い呼び出しが急に増えたら、アプリを経由しない直接呼び出し（スクリプト・エージェント）の可能性がある。
- 前提の確認: Browser の分散トレーシングが有効で、クロスオリジンの場合は送信先の許可設定がされていること。満たさない場合は判定不能。
- 判定: 平常時から 30 ポイント以上上昇 → `weak`

### D13 機械的に一定の間隔 — 前提 UID — 要検証
```sql
SELECT average(c) AS avg_per_min, stddev(c) AS sd_per_min
FROM (SELECT count(*) AS c FROM Transaction WHERE appName = '{appName}'
      FACET enduser.id TIMESERIES 1 minute SINCE 1 hour ago LIMIT 50)
FACET enduser.id
```
- 判定: 平均 20件/分以上 かつ 標準偏差が平均の 10% 未満 → `weak`
- 人間の操作は間隔がばらつく。一定すぎるアクセスは自動化の兆候（AI エージェントとは断定しない）。

### D14 API キーの異常な使われ方 — 前提 ATTR（`api.key_id`）, IP
```sql
SELECT uniqueCount(client.ip_hash) AS ips, uniqueCount(client.country) AS countries, count(*)
FROM Transaction WHERE appName = '{appName}' AND api.key_id IS NOT NULL
FACET api.key_id SINCE 1 day ago COMPARE WITH 1 week ago
```
- 判定: 1つのキーで国の数が増えた、または IP 数が平常時の5倍以上 → `strong`

### D15 有効期限の長すぎるトークン — 前提 ATTR（`auth.token_age_sec`）
```sql
SELECT percentile(auth.token_age_sec, 50, 95, 99), max(auth.token_age_sec)
FROM Transaction WHERE appName = '{appName}' AND auth.token_age_sec IS NOT NULL
FACET client.type SINCE {since}
```
- 判定: p95 が 24時間（86400秒）超 → 対策推奨（攻撃兆候ではなく設定リスクとして報告）

---

## D. インベントリ・変更相関

### D16 観測されているエンドポイント一覧（シャドー / ゾンビ API の突合用）— 前提なし
```sql
SELECT count(*), latest(timestamp) FROM Transaction
WHERE appName = '{appName}' AND transactionType = 'Web'
FACET name SINCE 30 days ago LIMIT MAX
```
- `api-authz-review` のエンドポイント一覧と突き合わせる。

### D17 新しい種類の例外（A10）— 前提なし
```sql
SELECT count(*), earliest(timestamp) FROM TransactionError
WHERE appName = '{appName}' FACET error.class SINCE {baseline}
```
- `earliest(timestamp)` が直近 `{since}` 以内の `error.class` = 新しく出現した例外。

### D18 変更相関（iRCA が無い場合の代替）— 前提 DEP — 要検証
```sql
SELECT timestamp, version, changelog, user FROM Deployment
WHERE entity.name = '{appName}' SINCE {baseline} LIMIT 20
```
- 異常（D01〜D17 のいずれか）の開始時刻の直前 2時間以内にデプロイがあるか判定する。
- 直前にデプロイがある → 自分たちの変更が原因の可能性（**認可属性の挙動が変わった場合は、認可チェックの欠落を疑う**）。
- デプロイが無い → 外部要因（攻撃）の可能性が高い。

---

## エンドポイント別 `attack_signal` の決め方（api-authz-review 連携）

トランザクション名ごとに、上の検知結果の最大値を採用する。

| attack_signal | 条件 |
|---|---|
| `strong` | D01・D07 が1件以上、または D02〜D06・D10・D11・D14 のいずれかが `strong` |
| `weak` | いずれかの検知が `weak` |
| `none` | 実行できた検知がすべて `none` |
| `unknown` → `none` として渡す | 前提不足で実行できなかった。**レポートに「判定不能」と明記する**（`none` と同じ扱いにするのはスコア上だけ） |
