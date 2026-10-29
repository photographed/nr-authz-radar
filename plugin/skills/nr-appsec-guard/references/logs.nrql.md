# ログ（ラストワンマイル）NRQL

**原則: ログはスキャンしない。APM で見つけた手がかりを起点に、取りに行く。**

ログ全体を攻撃の文字列で検索すると、SIEM と同じく偽陽性が多くなり、ログの量に比例してコストもかかる。
ここにあるクエリは、すべて次の3つで範囲を絞っている（テストで確認している）。

1. **APM 由来のキー**（`trace.id`・仮名化したユーザー・アプリ名と決まった形のログ行）か、明示的なフィルタ
2. **短い時間の範囲**（調査や兆候の期間だけ）
3. **件数の上限**（`LIMIT`）

`hunt.py` はこのファイルのクエリを実行しない（定期の Hunt でログを読まない）。使うのは、証拠の詳細化・調査・Workflow Automation のときだけ。

表記は `detections.nrql.md` と同じ。`{from}` / `{to}` は調査の期間、`{subject}` は調査対象の仮名化ユーザー。
ログの属性名（`trace.id`・`entity.name`・`service.name`・`message` など）は取り込み方法によって異なるので、R16 の結果に合わせて読み替える。

**個人データ**: ログには個人データが入りやすい。レポートには件数と要約だけを書き、生の行は保全データに分けて関係者だけに渡す（`shared/privacy.md`）。

### L01 IDOR の証拠のログ行（誰の、どのレコードか） — 段階 S2 ＋ Logs in context — 要検証
```sql
SELECT timestamp, level, message FROM Log
WHERE trace.id IN (
  SELECT uniques(traceId) FROM Transaction
  WHERE appName = '{appName}' AND resource.owner_match IS FALSE AND authz.decision = 'allow'
  SINCE {since}
) SINCE {since} LIMIT 100
```
- D01 が出たトランザクションと **同じトレース** のログ行だけを取る。担当者が「どのレコードが返ったか」までたどれる。
- 入れ子のクエリが使えない場合は2段階にする: 先に `SELECT uniques(traceId) …` を実行し、その結果を `trace.id IN (…)` に入れる。

### L02 調査対象のアクセスの全件 — 段階 S1 ＋ Logs in context — 要検証
```sql
SELECT timestamp, message FROM Log
WHERE trace.id IN (
  SELECT uniques(traceId) FROM Transaction
  WHERE appName = '{appName}' AND enduser.id = '{subject}'
  SINCE {from} UNTIL {to}
) SINCE {from} UNTIL {to} LIMIT 200
```
```sql
-- アクセスログ（クエリ文字列を含む）。利用者を特定できないので、時間帯と API のパスで絞る
SELECT count(*) FROM Log
WHERE {accessLogFilter} AND {pathAttr} LIKE '{pathPrefix}%' AND {statusAttr} = 200
FACET {pathAttr} SINCE {from} UNTIL {to} LIMIT 100
```
- ④ 調査の I03（200 で返ったリソース）の **穴埋め**。APM の `request.uri` に入らないクエリ文字列（`?id=123`）や、APM のサンプリングで漏れた分を補う。
- アクセスログでの絞り込みは時間帯とパスだけなので、**他の利用者のアクセスも含み得る**。対象者のものと断定しない。

### L03 エッジで遮断されたリクエスト — 段階 S0 ＋ WAF / CDN のログ — 要検証
```sql
SELECT count(*) FROM Log
WHERE {edgeLogFilter} AND {edgeActionAttr} IN ('block', 'challenge')
FACET {edgeActionAttr}, {edgeRuleAttr} SINCE {from} UNTIL {to} LIMIT 20
```
- アプリに届く前に止まったものは APM に現れない。兆候が出た時間帯に、**どこまで試されていたか** の全体像を補う。
- IP アドレスでの集計はしない（`shared/privacy.md`）。必要なら ASN の単位で。

### L04 アプリが出した認可判断のログ（属性を送れない環境の代わり） — 段階 S2 ＋ Logs
```sql
SELECT count(*) FROM Log
WHERE (entity.name = '{appName}' OR service.name = '{appName}') AND message LIKE 'authz-radar %'
FACET message SINCE {since} LIMIT 20
```
- High-security mode などでカスタム属性を送れない場合、計装ライブラリが出す **決まった形のログ行**（`shared/attribute-spec.md` の「認可判断のログ行」）で代用する。
- `message LIKE 'authz-radar decision=allow owner_match=false%'` の行があれば、**D01 と同じ意味（他人のデータを返した証拠）**。
- ログ行には ID や個人データを入れない形にしているので、`FACET message` でも種類は少ない。
