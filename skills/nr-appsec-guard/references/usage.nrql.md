# ② 利用実態 NRQL（と ① 棚卸しの補助）

**目的**: どの API が、どこから、誰に、どれだけ使われているかを知る。攻撃かどうかは判定しない（それは `detections.nrql.md`）。
ここでの結果は、① 棚卸し（コードとの突き合わせ）と、優先度の `traffic_rpm` に使う。

表記は `detections.nrql.md` と同じ（`{appName}`、要検証 など）。段階の意味は `shared/goals.md`。

### U01 観測されているエンドポイント一覧 — 段階 S0
```sql
SELECT count(*) AS requests, rate(count(*), 1 minute) AS rpm, latest(timestamp) AS last_seen
FROM Transaction
WHERE appName = '{appName}' AND transactionType = 'Web'
FACET name SINCE 30 days ago LIMIT MAX
```
- `api-authz-review` のエンドポイント一覧と突き合わせる（シャドー API / ゾンビ API。`shared/data-sources.md` §3）。
- `rpm` を優先度スクリプトの `traffic_rpm` に使う。一致しないエンドポイントは `null`（未観測）。
- トランザクション名の品質（R12）が悪いと、この一覧は API 単位にならない。

### U02 画面から呼ばれている API（Ajax）— 段階 S0 ＋ Browser
```sql
SELECT count(*) FROM AjaxRequest
WHERE appName = '{browserAppName}'
FACET httpMethod, groupedRequestUrl SINCE 7 days ago LIMIT MAX
```
- U01・コード監査の一覧と突き合わせる。**サーバーでは呼ばれているのに画面からは呼ばれていない API** は、モバイル・外部連携向けか、アプリを経由しない直接呼び出しの可能性がある。
  用途を確認し、不明なら露出度を `mobile` または `external` として優先度に反映する。

### U03 呼び出し元の内訳（画面 / モバイル / 直接）— 段階 S0 ＋ 分散トレーシング — 要検証
```sql
SELECT percentage(count(*), WHERE parent.type = 'Browser') AS browser,
       percentage(count(*), WHERE parent.type = 'Mobile') AS mobile,
       percentage(count(*), WHERE parent.type = 'App') AS service,
       percentage(count(*), WHERE parent.type IS NULL) AS no_parent
FROM Transaction WHERE appName = '{appName}' AND transactionType = 'Web'
FACET name SINCE 7 days ago LIMIT MAX
```
- API ごとの「いつもの呼ばれ方」を知る。D12（直接呼び出しの急増）の平常時の値になる。
- Browser / Mobile の分散トレーシングが無効だと、すべて `no_parent` になる（R05）。

### U04 API ごとの利用者数 — 段階 S1
```sql
SELECT uniqueCount(enduser.id) AS users, count(*) AS requests
FROM Transaction WHERE appName = '{appName}' AND transactionType = 'Web'
FACET name SINCE 7 days ago LIMIT MAX
```
- 利用者が極端に少ないのに件数が多い API は、特定の利用者（または自動化）に偏って使われている。

### U05 API ごとのステータスコードの内訳 — 段階 S0
```sql
SELECT count(*) FROM Transaction
WHERE appName = '{appName}' AND transactionType = 'Web'
FACET name, http.statusCode SINCE 7 days ago LIMIT MAX
```
- 平常時の 401 / 403 / 404 の割合を知る。D04・D10 の平常時の値になる。

### U06 方式ごとの利用状況 — 段階 S2（REST 以外）
```sql
SELECT count(*), uniqueCount(enduser.id) AS users FROM Transaction
WHERE appName = '{appName}' AND api.protocol IS NOT NULL
FACET api.protocol, api.operation SINCE 7 days ago LIMIT MAX
```
- GraphQL・SOAP・JSON-RPC・WebSocket の **操作単位** の一覧。U01（トランザクション名の一覧）の代わりに、コード監査の棚卸しと突き合わせる。
- `api.protocol` が無い場合は R15 で方式を推定する。
