# ③ 攻撃検知 NRQL カタログ

**目的**: 今、攻撃を受けているかを判定する。API の一覧や利用状況は `usage.nrql.md`（② 利用実態）、何をされたかの調査は `investigation.nrql.md`（④ 調査）。
各検知の見出しの「段階」は、その検知に必要なアプリ側の計装の段階（`shared/goals.md`）。続く「証拠 / 強い兆候 / 異常 / リスク / 参考」は **証拠の強さ**（`shared/detections.json`）。
**異常は攻撃と呼ばない。** 報告では証拠の強さごとに分け、異常だけで「攻撃を受けている」と書かない。

Hunt モードで実行するクエリ集。各検知は **前提条件**（`readiness-checks.md` の判定結果）を満たすものだけ実行し、
満たさないものは「判定不能（理由）」として報告する。

## 表記

- 各検知の CWE・ASVS・OWASP・OAT・IPA の対応は `shared/standards.json` の `detections` にある。報告時は必ず併記する。

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
| NET | `client.asn` / `client.country`（L0・既定）。IP 粒度が必要なら `client.ip_hmac`（L1・オプトイン）。`shared/privacy.md` 参照 |
| DEP | Change Tracking（デプロイ記録） |

---

## A. 認可（IDOR / BOLA / スコープ）

### D01 IDOR 成功の証拠 — 段階 S2 — 証拠 — 前提 ATTR — **最重要**
```sql
SELECT count(*) FROM Transaction
WHERE appName = '{appName}' AND resource.owner_match IS FALSE AND authz.decision = 'allow'
FACET name, resource.type SINCE {since}
```
- 判定: 1件以上 → `strong`
- アラート候補: **Critical**（静的しきい値 > 0）
- 誤検知: 管理者・サポートの正当なアクセス。`authz.required_scope LIKE 'admin:%'` 等で除外する。

### D02 他人のリソースへのアクセス試行（拒否された分）— 前提 ATTR, UID — 段階 S2 — 強い兆候
```sql
SELECT count(*) FROM Transaction
WHERE appName = '{appName}' AND authz.decision = 'deny' AND authz.deny_reason = 'owner_mismatch'
FACET enduser.id SINCE {since} LIMIT 20
```
- 判定: 1ユーザーが 20件以上 → `strong`、5件以上 → `weak`（しきい値は平常時の分布を見て調整）
- 意味: 攻撃が**防げている**状態だが、同じ攻撃者が守られていない別の API を探している可能性が高い。

### D03 ID 列挙（コード変更なしで使える）— 前提 URI, UID — 段階 S1 — 異常
```sql
SELECT uniqueCount(request.uri) AS distinct_ids, count(*) AS requests
FROM Transaction
WHERE appName = '{appName}' AND name LIKE '%{%}%'
FACET enduser.id, name SINCE 1 hour ago LIMIT 20
```
- `name LIKE '%{%}%'` はパス変数を含むトランザクション名（例: `.../orders/{id} (GET)`）。命名形式が違う環境では対象の `name` を列挙して指定する。
- 判定: 1ユーザーが1時間に 100 以上の異なる ID → `strong`、30 以上 → `weak`
- 誤検知: 一覧画面からの詳細の連続表示。Browser のセッションと突き合わせる（D12）。

### D04 404 / 403 比率の急上昇 — 段階 S0 — 異常 — 前提なし — REST 専用
```sql
SELECT percentage(count(*), WHERE http.statusCode IN (403, 404)) AS deny_or_notfound
FROM Transaction WHERE appName = '{appName}'
FACET name SINCE {since} COMPARE WITH {baseline}
```
- 判定: 平常時の5倍以上 → `strong`、2倍以上 → `weak`
- 意味: 属性が無くても使える、列挙・探索の汎用シグナル。
- **REST 専用**: GraphQL・JSON-RPC は拒否しても 200、SOAP は 500 を返すことが多く、WebSocket はメッセージが見えないため反応しない。**反応しないことを「安全」と読まない。** REST 以外は D22 を使う（`shared/protocols.md`）。

### D05 スコープ不足・管理系への到達 — 段階 S3 — 強い兆候 — 前提 ATTR
```sql
SELECT count(*) FROM Transaction
WHERE appName = '{appName}' AND authz.decision = 'deny' AND authz.deny_reason IN ('scope_missing', 'role_missing')
FACET authz.required_scope, enduser.id SINCE {since} LIMIT 20
```
- 判定: `admin:` 系スコープへの拒否が同一ユーザーから 10件以上 → `strong`

---

### D22 認可拒否の急増（方式に依存しない）— 段階 S2 — 異常
```sql
SELECT count(*) FROM Transaction
WHERE appName = '{appName}' AND authz.decision = 'deny'
FACET api.protocol, api.operation, name SINCE {since} COMPARE WITH {baseline}
```
- D04・D10 の **方式に依存しない版**。ステータスコードではなくアプリ自身の認可判断を数えるので、GraphQL（200）・SOAP（500）・WebSocket でも使える。
- REST 以外は `api.operation` で集計する（GraphQL のトランザクション名はクライアントが偽装できるため）。
- 判定: 平常時の5倍以上 → `strong`、2倍以上 → `weak`

### D23 1リクエストで大量の所有者照合 — 段階 S3 — 強い兆候
```sql
SELECT max(resource.check_count) AS max_checks, average(resource.check_count) AS avg_checks, count(*)
FROM Transaction WHERE appName = '{appName}' AND resource.check_count IS NOT NULL
FACET api.operation, enduser.id SINCE 1 hour ago LIMIT 20
```
- GraphQL のエイリアス（`a1: order(id:1) a2: order(id:2) …`）や、WebSocket の1つのメッセージでの大量取得のように、**1回のリクエストで多数のリソースに触れる列挙**を見る。リクエスト数で数える D02・D03 には1件にしか見えない。
- 判定: `max_checks` が 50 以上 → `strong`、20 以上 → `weak`（一覧取得の API は平常時の値を見て調整する）
- 攻撃が成功した分は、所有者照合が1件でも一致しなければ `owner_match = false` のまま残るので D01 でも見える。

## B. SQL インジェクション

### D06 DB 構文エラー（Errors Inbox と同じデータ）— 前提なし — 段階 S0 — 強い兆候
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

### D07 注入らしい SQL 文 — 段階 S0 — 証拠 — 前提 SPAN — 要検証
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

### D08 SQL の形のばらつき（文字列連結の兆候）— 前提 SPAN — 段階 S0 — 異常 — 要検証
```sql
SELECT uniqueCount(db.statement) FROM Span
WHERE entity.name = '{appName}' AND db.statement IS NOT NULL
FACET name SINCE {since} COMPARE WITH {baseline}
```
- 意味: プレースホルダを使った SQL は形が一定。文字列連結の SQL に攻撃が来ると、形の種類が急増する。
- 判定: 平常時の3倍以上 → `weak`（D07 と同時なら `strong`）

### D09 時間差を使う Blind SQLi — 段階 S0 — 異常 — 前提なし
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

### D10 認証失敗の急増 — 段階 S0 — 異常 — 前提なし — REST 専用（gRPC は `response.status` で読み替え）
```sql
SELECT count(*) FROM Transaction
WHERE appName = '{appName}' AND http.statusCode = 401
FACET name SINCE 1 hour ago COMPARE WITH 1 week ago TIMESERIES 5 minutes
```
- 判定: 先週同時刻の5倍以上 → `strong`、2倍以上 → `weak`
- **REST 専用**: gRPC は `http.statusCode = 401` の代わりに `response.status = '16'`（UNAUTHENTICATED）で数える（属性の型は要検証）。GraphQL・SOAP・WebSocket では D22 を使う。

### D11 分散アクセス（少数アカウント × 多数のネットワーク）— 前提 NET, UID — 段階 S3 — 異常
```sql
-- L0（既定）: ASN と国の粒度
SELECT uniqueCount(client.asn) AS asns, uniqueCount(client.country) AS countries, count(*) AS requests
FROM Transaction WHERE appName = '{appName}'
FACET enduser.id SINCE 1 hour ago LIMIT 20
```
```sql
-- L1（オプトイン時のみ）: IP の粒度
SELECT uniqueCount(client.ip_hmac) AS ips, count(*) AS requests
FROM Transaction WHERE appName = '{appName}'
FACET enduser.id SINCE 1 hour ago LIMIT 20
```
- 判定（L0）: 1アカウントで1時間に 10 ASN 以上、または 3か国以上 → `strong`、5 ASN 以上 → `weak`
- 判定（L1）: 1アカウントで1時間に 50 IP 以上 → `strong`、10 IP 以上 → `weak`
  （参考: 40分で326 IP・1,200件超という観測報告がある。`shared/threat-model-2026-jp.md`）
- L0 は精度が下がる（同じ ASN 内で IP を変える攻撃は見えない）。**IP 粒度の判定は WAF / CDN に任せ、`edge.verdict` を併用する**のが推奨。
  ```sql
  SELECT count(*) FROM Transaction WHERE appName = '{appName}' AND edge.verdict IN ('challenge', 'bot')
  FACET enduser.id, name SINCE 1 hour ago LIMIT 20
  ```

### D12 ブラウザを経由しない API 直叩き — 段階 S0 — 異常 — 前提 BRW — 要検証
```sql
SELECT percentage(count(*), WHERE parent.type IS NULL) AS no_trace_parent
FROM Transaction WHERE appName = '{appName}' AND transactionType = 'Web'
FACET name SINCE {since} COMPARE WITH {baseline}
```
- 着眼点: Browser から分散トレーシング付きで呼ばれた API は `parent.type = 'Browser'` になる（モバイルなら `'Mobile'`）。
  親が無い呼び出しが急に増えたら、アプリを経由しない直接呼び出し（スクリプト・エージェント）の可能性がある。
- 前提の確認: Browser の分散トレーシングが有効で、クロスオリジンの場合は送信先の許可設定がされていること。満たさない場合は判定不能。
- 判定: 平常時から 30 ポイント以上上昇 → `weak`

### D13 機械的に一定の間隔 — 段階 S1 — 異常 — 前提 UID — 要検証
```sql
SELECT average(c) AS avg_per_min, stddev(c) AS sd_per_min
FROM (SELECT count(*) AS c FROM Transaction WHERE appName = '{appName}'
      FACET enduser.id TIMESERIES 1 minute SINCE 1 hour ago LIMIT 50)
FACET enduser.id
```
- 判定: 平均 20件/分以上 かつ 標準偏差が平均の 10% 未満 → `weak`
- 人間の操作は間隔がばらつく。一定すぎるアクセスは自動化の兆候（AI エージェントとは断定しない）。

### D24 ブラウザのセッションが無いユーザーの API 呼び出し — 段階 S1 — 異常 — 前提 UID, BRW（Browser に `enduser.id`）
```sql
-- 1. API を多く呼んでいるユーザー（モバイル・サービス間の呼び出しは除く）
SELECT count(*) AS api_calls FROM Transaction
WHERE appName = '{appName}' AND transactionType = 'Web' AND enduser.id IS NOT NULL
  AND (parent.type IS NULL OR parent.type = 'Browser')
FACET enduser.id SINCE {since} LIMIT 100
```
```sql
-- 2. そのユーザーのブラウザのセッション数（{users} は 1 の結果のユーザー）
SELECT uniqueCount(session) AS sessions FROM PageView
WHERE appName = '{browserAppName}' AND enduser.id IN ({users})
FACET enduser.id SINCE {since} LIMIT 100
```
- **1 に出て 2 に出ないユーザー**（API を `api_calls` 100 回以上呼んでいるのに、ブラウザのセッションが一度も無い）= 画面を経由せず API を直接呼んでいる。D12（割合の変化）を **ユーザー単位の事実** に強めたもの。
- NRQL では2種類のイベントを突き合わせにくいので、`hunt.py` が2つのクエリを順に実行し、差を計算する。
- 前提: Browser 側でも **同じ仮名の** `enduser.id` を送っていること。**HMAC の鍵をブラウザの JavaScript に置いてはいけない。** サーバーが仮名を計算して画面に渡し、画面は Browser エージェントの `setUserId` にその値を渡す（API 名は Browser エージェントの版で要確認）。
- 誤検知: 外部連携用のアカウント、CLI やスクリプトを正当に使う利用者。アカウントの種類で除外する。
- アラートにはしない（2つのクエリが必要なため）。Hunt で確認する。

### D14 API キーの異常な使われ方 — 段階 S3 — 異常 — 前提 ATTR（`api.key_id`）, NET
```sql
SELECT uniqueCount(client.asn) AS asns, uniqueCount(client.country) AS countries, count(*)
FROM Transaction WHERE appName = '{appName}' AND api.key_id IS NOT NULL
FACET api.key_id SINCE 1 day ago COMPARE WITH 1 week ago
```
- 判定: 1つのキーで国の数が増えた、または ASN 数が平常時の5倍以上 → `strong`（L1 なら `client.ip_hmac` で同様に集計できる）

### D15 有効期限の長すぎるトークン — 段階 S3 — リスク — 前提 ATTR（`auth.token_age_sec`）
```sql
SELECT percentile(auth.token_age_sec, 50, 95, 99), max(auth.token_age_sec)
FROM Transaction WHERE appName = '{appName}' AND auth.token_age_sec IS NOT NULL
FACET client.type SINCE {since}
```
- 判定: p95 が 24時間（86400秒）超 → 対策推奨（攻撃兆候ではなく設定リスクとして報告）

---

## D. 例外・変更相関

### D17 新しい種類の例外（A10）— 前提なし — 段階 S0 — 異常
```sql
SELECT count(*), earliest(timestamp) FROM TransactionError
WHERE appName = '{appName}' FACET error.class SINCE {baseline}
```
- `earliest(timestamp)` が直近 `{since}` 以内の `error.class` = 新しく出現した例外。

### D18 変更相関（iRCA が無い場合の代替）— 前提 DEP — 段階 S0 — 参考 — 要検証
```sql
SELECT timestamp, version, changelog, user FROM Deployment
WHERE entity.name = '{appName}' SINCE {baseline} LIMIT 20
```
- 異常（D01〜D17 のいずれか）の開始時刻の直前 2時間以内にデプロイがあるか判定する。
- 直前にデプロイがある → 自分たちの変更が原因の可能性（**認可属性の挙動が変わった場合は、認可チェックの欠落を疑う**）。
- デプロイが無い → 外部要因（攻撃）の可能性が高い。

---

## E. RCE（リモートコード実行）

RCE は「コードが実行された瞬間」を APM で確実に見ることはできない。ここでは **攻撃の試み（D21）** と **成功後の不審な外部通信（D20）** で気づく。
両方が同じ時間帯・同じアプリで出た場合は、RCE の可能性が高い。

### D20 見たことのない外部への通信 — 段階 S0 — 異常 — 前提 SPAN — 要検証
```sql
SELECT count(*), earliest(timestamp) AS first_seen FROM Span
WHERE entity.name = '{appName}' AND span.kind = 'client' AND category = 'http'
FACET peer.hostname SINCE 30 days ago LIMIT 200
```
- `first_seen` が直近 `{since}` 以内の宛先 = **新しい外部の宛先**。
- Span を30日分見るため、カタログで最も重いクエリ。宛先は 200 件までに絞っている（コストの節を参照）。
- 宛先の属性名はエージェントのバージョンで異なる可能性がある（`peer.hostname` / `server.address` / `http.url`）。結果が空なら読み替えて再実行する。
- 判定:
  - `strong`: 新しい宛先が、D21 と同じ時間帯（前後1時間）に出現した。または、攻撃の確認によく使われるサービス（`oast.` / `interact.sh` / `burpcollaborator` / `ngrok` / `requestbin` 等）や IP アドレス直指定の宛先
  - `weak`: 新しい宛先だけが出現した（正当な連携の追加でも起きるので、D18 で直前のデプロイを確認する）
- **見えないもの**: APM の外部呼び出しの計測は主に HTTP。**JNDI の LDAP / RMI 接続や DNS による確認は Span に出ない可能性が高い**。
  それらを見るには、Network Performance Monitoring・ファイアウォールのログ・Infrastructure の `NetworkSample` が必要（`shared/data-sources.md`）。

### D21 RCE の試みで出る例外 — 段階 S0 — 強い兆候 — 前提なし
```sql
SELECT count(*), earliest(timestamp) AS first_seen FROM TransactionError
WHERE appName = '{appName}' AND (
  error.class IN ('java.io.InvalidClassException',
                  'java.io.StreamCorruptedException',
                  'com.fasterxml.jackson.databind.exc.InvalidTypeIdException',
                  'com.thoughtworks.xstream.converters.ConversionException',
                  'org.springframework.expression.spel.SpelEvaluationException',
                  'org.springframework.expression.spel.SpelParseException',
                  'ognl.OgnlException',
                  'javax.naming.NamingException',
                  'javax.naming.CommunicationException',
                  'freemarker.core.InvalidReferenceException',
                  'org.apache.velocity.exception.ParseErrorException')
  OR error.message LIKE '%Cannot run program%'
  OR error.message LIKE '%jndi:%'
  OR error.message LIKE '%java.lang.Runtime%'
  OR error.message LIKE '%commons.collections%'
  OR error.message LIKE '%ysoserial%'
)
FACET transactionName, error.class SINCE {baseline}
```
- 着眼点: RCE の攻撃は、**失敗した試み**のときに特有の例外を残す（不正なデータの読み込み・式言語の解釈・JNDI の名前解決・コマンドの起動の失敗）。
  Errors Inbox では新しいエラーグループとして現れる。
- 判定:
  - `strong`: 同じトランザクションで1時間に5件以上、または異なる種類の例外が2つ以上、または D20 と同時
  - `weak`: `first_seen` が直近 `{since}` 以内（初めて出た）
- 誤検知: 正当な入力ミスでも `SpelEvaluationException` 等は出る。平常時の件数（`{baseline}`）と比べる。
- 注意: High-security mode では `error.message` が送られないため、`error.class` だけで判定する。

## エンドポイント別 `attack_signal` の決め方（api-authz-review 連携）

トランザクション名ごとに、上の検知結果の最大値を採用する。

| attack_signal | 条件 |
|---|---|
| `strong` | D01・D07 が1件以上、または D02〜D06・D10・D11・D14・D20〜D23 のいずれかが `strong` |
| `weak` | いずれかの検知が `weak` |
| `none` | 実行できた検知がすべて `none` |
| `unknown` → `none` として渡す | 前提不足で実行できなかった。**レポートに「判定不能」と明記する**（`none` と同じ扱いにするのはスコア上だけ） |
