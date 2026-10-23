# Java（Spring Boot / Spring Security）の計装

**目的**: 段階 S2（IDOR 成功の証拠 D01）に最短で到達する。属性の仕様は `shared/attribute-spec.md`、段階の考え方は `shared/goals.md`。

## 推奨の順番

| 順番 | 作業 | 到達する段階 | 手段 |
|---|---|---|---|
| 1 | 分散トレーシングが有効か確認し、SQL を `obfuscated` で記録する | S0 | `newrelic.yml` |
| 2 | **計装ライブラリを入れ、データ取得のメソッドに `@CheckOwnership` を付ける**（まず OBSERVE モード） | **S2** | API（ライブラリ） |
| 3 | 結果を確認してから ENFORCE モードに切り替える | S2 | 設定 |
| 4 | 必要なら全属性を送る（`attributes: FULL`） | S3 | 設定 |

コードを一切変更できない場合の代わりの手段は「コード変更なしでできること」を参照。ただし **S2 の `owner_match` はコード無しでは作れない**。

## 1. `newrelic.yml`（S0）

`instrumentation/java/examples/newrelic-authz-snippet.yml` を、既存の `newrelic.yml` の `common:` に合わせて取り込む。
- 分散トレーシングを有効にする（`Span` が無いと D07・D08・D20・U03 が使えない）
- `record_sql: obfuscated`（生の SQL には個人データが入り得る。`raw` にしない）
- 認証ヘッダー・Cookie・転送元 IP のヘッダーを属性から除外する（`shared/privacy.md`）

> 設定キーはエージェントのバージョンで異なることがある。適用前に、使っているエージェントのドキュメントで確認すること。

## 2. 計装ライブラリ（S2）

ソース: `instrumentation/java/`（パッケージ `io.github.photographed.authzradar`）。**Maven Central には未公開**のため、
ビルドして社内リポジトリに置くか、ソースを取り込んで使う。

```bash
cd instrumentation/java && ./gradlew build
```

### 2-1. 設定（`application.yml`）
```yaml
nr:
  authz-radar:
    attributes: MINIMAL          # S2。authz.decision・resource.owner_match・enduser.id だけを送る
    hmac-key: ${AUTHZ_RADAR_HMAC_KEY}   # 必ずシークレットストアから渡す。無いと enduser.id は送らない
    ownership-mode: OBSERVE      # まず記録だけ。確認後に ENFORCE へ
    bypass-authorities:          # 他人のデータを正当に見られる権限（管理者・サポート）
      - SCOPE_admin:read
```

### 2-2. 所有者照合を付ける
IDOR が起きるのは「クライアントが指定した ID でデータを取る場所」。**そのメソッドに `@CheckOwnership` を付ける。**

```java
public record Order(Long id, String ownerId, ...) implements Owned { }   // ownerId() があれば実装は不要

@Service
public class OrderService {
    @CheckOwnership(type = "order")
    public Order find(Long id) {
        return repository.findById(id).orElseThrow();
    }
}
```

- 対象は、`api-authz-review` が F4（IDOR / BOLA 候補）として挙げたエンドポイントのデータ取得メソッドから始める。
- 戻り値は `Owned`、`Optional<Owned>`、`Iterable<Owned>` に対応。
- 比較は `Authentication#getName()` と `ownerId()`。所有者をユーザー名以外（数値 ID 等）で持っている場合は `ownerId()` で合わせる。

### 2-3. 自動で記録されるもの
| 場面 | 記録 |
|---|---|
| ハンドラが正常に終わった | `authz.decision = allow` |
| `@CheckOwnership` で所有者が違った（ENFORCE） | `deny`、`owner_match = false`、403。expected error として Errors Inbox に記録 |
| `@CheckOwnership` で所有者が違った（OBSERVE） | `allow`、`owner_match = false` → **D01 が反応する** |
| 管理者・サポートの正当なアクセス | `allow`、`owner_match = false`、`authz.required_scope = admin:read`（D01 の除外条件） |
| `@PreAuthorize` で拒否 | `deny`（FULL なら `deny_reason = scope_missing / role_missing`） |
| URL のルールで拒否・未認証 | `deny`（FULL なら `deny_reason = unauthenticated`） |

### 2-4. OBSERVE から ENFORCE へ
OBSERVE で動かすと、**本当に他人のデータを返しているアクセス**が D01 として見えるようになる。これは実際の情報漏えいの可能性があるので、
見つかったら ④ 調査（`investigation.nrql.md`）の対象にする。誤検知（正当な共有・委任など）は `bypass-authorities` か `ownerId()` の見直しで解消し、
D01 が正当なものだけになったら ENFORCE に切り替える。

### 2-5. 確認する
```sql
-- 属性が届いているか（R02）
SELECT percentage(count(*), WHERE authz.decision IS NOT NULL) AS coverage
FROM Transaction WHERE appName = '{appName}' AND transactionType = 'Web' FACET name SINCE 1 hour ago
```
```sql
-- 所有者照合が動いているか
SELECT count(*) FROM Transaction WHERE appName = '{appName}' AND resource.owner_match IS NOT NULL
FACET name, resource.owner_match SINCE 1 hour ago
```

## 3. 全属性（S3）
`attributes: FULL` にすると、`shared/attribute-spec.md` の残り（`authz.required_scope`・`authz.granted_scopes`・`authz.deny_reason`・
`resource.type`・`auth.token_age_sec` 等）も送る。
- `authz.required_scope` は `@PreAuthorize` / `@Secured` から自動で取る（エンドポイントごとの記述は不要）
- `client.type` は `ClientTypeResolver` の Bean を用意したときだけ送る（クライアントが自由に設定できるヘッダーは信用しない）
- `client.asn`・`edge.verdict` はこのライブラリでは扱わない（エッジ側で付与する）

## 4. コード変更なしでできること（と限界）

| 手段 | できること | できないこと |
|---|---|---|
| `newrelic.yml`（servlet-user 計装） | `enduser.id`（S1） | **生のユーザー名が送られる**（仮名化できない）。メールアドレスをユーザー名にしている場合は使わない |
| XML（`instrumentation/java/examples/authz-extension.xml`） | 認可チェックのメソッドを計測対象にし、Span に出す（どの API で認可チェックが実行されたかが見える）。引数をそのまま属性にする | **値の比較ができないので `owner_match` は作れない**。High-security mode では使えない |

XML で認可チェックのメソッドを計測すると、「その API で所有者照合が一度も実行されていない」ことが Span で分かる。
コード監査の F4 を、実行時に裏付ける手段として使える。

## 対応状況

| 環境 | 状態 |
|---|---|
| Java | 17 以上 |
| Spring Boot 3.5.16 / Spring Security 6.5 | ✅ テスト済み（単体テストと、MockMvc による結合テスト） |
| Spring Boot 4.1.2 / Spring Security 7.1 | ⚠️ ライブラリのコンパイルのみ確認。テストは未実行（テスト用の依存関係の名前が 4.x で変わったため） |
| New Relic Java エージェント API | 9.5.0 |
| WebFlux | ❌ 未対応（Spring MVC のみ） |
