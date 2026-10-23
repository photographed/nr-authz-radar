# ④ 調査 NRQL（フォレンジック）

**目的**: 攻撃の兆候や通報を起点に、**何をされたか・どのデータが取られたか**を明らかにする。200 で返ったアクセスも対象にする。

表記は `detections.nrql.md` と同じ。`{subject}` は調査対象（ユーザー・API キー・ASN のいずれか）、`{from}` / `{to}` は調査期間。

## 調査の原則

1. **最初に「記録が残っているか」を確かめる**（I05〜I07）。サンプリングされていたり、保存期間が過ぎていたりすると、APM の結果は「一部」でしかない。
2. **APM は手がかり、ログで確定**。APM で対象と時間帯を絞り込み、トレース ID でログに移って全件を洗い出す。
3. **保全する**。結果は保存期間が切れる前にエクスポートする。調査で使ったクエリと実行時刻も記録する。
4. **断定しない**。「取得された可能性がある」と「取得された（ログで確認済み）」を区別して書く。
5. **個人データを広げない**。調査結果は必要な関係者だけに渡す。レポートの本文にはユーザー ID や IP の生の値を書かない（`shared/privacy.md`）。

## A. 記録が残っているか（最初に実行）

### I05 サンプリングの有無 — 段階 S0 — 要検証
```sql
-- イベント（サンプリングされ得る）の件数
SELECT count(*) FROM Transaction WHERE appName = '{appName}' SINCE {from} UNTIL {to}
```
```sql
-- メトリクス（集計値。サンプリングされない）の件数
SELECT count(apm.service.transaction.duration) FROM Metric
WHERE appName = '{appName}' SINCE {from} UNTIL {to}
```
- 1つ目 ÷ 2つ目 が 1 に近ければ、ほぼ全件が残っている。小さければ **APM の調査結果は一部**であり、全件はログで確認する必要がある。

### I06 APM の保存期間 — 段階 S0
```sql
SELECT earliest(timestamp) FROM Transaction WHERE appName = '{appName}' SINCE 13 months ago
```
- 最も古いデータの日時 = 実質的な保存期間。調査期間 `{from}` がこれより前なら、APM では調べられない。

### I07 ログの有無と保存期間 — データソース Logs
```sql
SELECT count(*), earliest(timestamp) FROM Log
WHERE entity.name = '{appName}' OR service.name = '{appName}' SINCE 13 months ago
```
- 0件なら、**全件での確定ができない**。推奨にアクセスログ・アプリログの取り込みを挙げる。
- ログの属性名（`entity.name` / `service.name` 等）は取り込み方法によって異なる。

## B. 何をされたか

### I01 対象のタイムライン — 段階 S1（ユーザー）/ S3（API キー・ASN）
```sql
SELECT count(*) FROM Transaction
WHERE appName = '{appName}' AND enduser.id = '{subject}'
FACET http.statusCode TIMESERIES 1 minute SINCE {from} UNTIL {to}
```
- API キーなら `api.key_id`、ネットワークなら `client.asn` で同様に絞る。
- 活動の開始・ピーク・終了の時刻を特定する。D18 でその前後のデプロイも確認する。

### I02 対象が触った API とその結果 — 段階 S1
```sql
SELECT count(*), min(timestamp) AS first, max(timestamp) AS last FROM Transaction
WHERE appName = '{appName}' AND enduser.id = '{subject}'
FACET name, http.statusCode SINCE {from} UNTIL {to} LIMIT MAX
```
- **200 で返ったもの** が「データが返った可能性がある」範囲。403 / 404 は「試みたが返っていない」範囲。

### I03 200 で返ったリソース — 段階 S1
```sql
SELECT count(*) FROM Transaction
WHERE appName = '{appName}' AND enduser.id = '{subject}' AND http.statusCode = 200
FACET name, request.uri SINCE {from} UNTIL {to} LIMIT MAX
```
- `request.uri` のパスに含まれる ID が、**取得された可能性のあるリソース**。
- S2 の属性があれば、`resource.owner_match IS FALSE` で **他人のリソースだったもの** に絞れる（取得の確証に近づく）。
- クエリ文字列は `request.uri` に含まれない。クエリで ID を渡す API は、ログで確認する。
- I05 でサンプリングが見られた場合、この結果は一部。

### I04 トレースからログへ — データソース Logs in context
```sql
-- 1. 対象のトランザクションのトレース ID を集める
SELECT uniques(traceId) FROM Transaction
WHERE appName = '{appName}' AND enduser.id = '{subject}' SINCE {from} UNTIL {to}
```
```sql
-- 2. 同じトレース ID のログを取り出す
SELECT * FROM Log WHERE trace.id IN ({traceIds}) SINCE {from} UNTIL {to} LIMIT MAX
```
- `uniques()` は返す件数に上限がある。多い場合は時間帯を分けて実行する。
- Logs in context が無い場合は、時刻とユーザーでアクセスログを突き合わせる（精度は下がる）。
- 入れ子のクエリで1回にまとめた形と、アクセスログ（クエリ文字列）での穴埋めは `logs.nrql.md` の L02。

## C. レポートの形式

```
## 今のデータでわかること
- 記録の状況: サンプリング率（I05）、APM の保存期間（I06）、ログの有無と保存期間（I07）
- 対象の活動: 期間、API ごとの件数とステータス（I01・I02）
- 取得された可能性のあるリソース: 件数と種類（I03。生の ID は別添の保全データに入れ、本文には書かない）
- ログで確認できた範囲 / できなかった範囲（I04）

## わからないこと（と理由）
- 例: 「2026-10-01 以前は保存期間を過ぎている」「クエリ文字列で ID を渡す API はログが無いため不明」

## 推奨
- 調査のために: 保全（エクスポート）、ログの取り込み、保存期間の延長
- 再発防止のために: 該当 API の修正（コード監査の Finding）、S2 の属性の導入
```
