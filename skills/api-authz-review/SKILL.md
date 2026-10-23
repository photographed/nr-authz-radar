---
name: api-authz-review
description: Inventory and audit API authorization in source code (Java/Spring first) — enumerate endpoints, extract required scopes/roles, detect missing scope checks, IDOR/BOLA candidates (no ownership check), BFLA, mass assignment, SQL injection, OS command injection, unsafe deserialization and excessive data exposure, then rank findings deterministically (optionally boosted by New Relic Ground Truth traffic and attack signals). Use when asked to review API scopes, find IDOR/BOLA, check authorization, or prioritize API security fixes.
---

# api-authz-review — ソースコードの認可・スコープ監査

API ごとに「どのスコープが必要か」「所有者照合をしているか」をソースコードから洗い出し、
問題を **決定的なスコアで順位付け** する。New Relic が繋がっていれば実トラフィックと攻撃兆候で補正する。

プラグインのルートはこのファイルから `../../`。共通仕様:
- `shared/attribute-spec.md`（計装推奨で使う属性名）
- `shared/owasp-mapping.md`
- `shared/risk-scoring.md`（**順位付けは必ずこの仕様とスクリプトで行う**）
- `shared/standards.json`（Finding ごとの CWE・ASVS・OWASP・IPA。レポートに必ず併記する）

## 守ること

1. **生成のみ**: コードの修正は差分・パッチ案として提示する。ユーザーの明示的な指示なしにファイルを書き換えない。
2. **根拠を必ず示す**: 各 Finding に `file:line` を付ける。根拠を示せないものは出さない。
3. **断定しない**: コードだけで判定できないもの（Gateway・別サービスでの認可など）は `confidence: needs_review`。
4. **点数を自分で付けない**: 特徴量を JSON にまとめ、`scripts/risk_score.py` に計算させる。

## 手順

### Step 0. 入力を確認する
- 対象リポジトリ（またはモジュール）
- あれば: OpenAPI 定義（`security` / `scopes`）、API Gateway の設定（Kong / AWS API Gateway / Apigee 等）、`criticality.yaml`
- New Relic を使うか（使う場合は `newrelic-us` / `newrelic-jp` のどちらか、対象の `appName`）

Gateway の設定が無い場合は、「スコープ検証がコード外にある可能性」をユーザーに一度だけ確認する。

### Step 1. エンドポイント一覧を作る（Java / Spring）
探すもの:
- `@RestController` / `@Controller` 内の `@RequestMapping` / `@GetMapping` / `@PostMapping` / `@PutMapping` / `@PatchMapping` / `@DeleteMapping`（クラスとメソッドのパスを結合）
- WebFlux の `RouterFunction`（`route(GET("/..."), handler)`）
- JAX-RS（`@Path` + `@GET` 等）が混在していればそれも

各エンドポイントについて: HTTP メソッド、パス、ハンドラ（`Class#method`）、パス変数、`@RequestBody` の型、戻り値の型。

### Step 2. 認可の情報を取り出す
| 場所 | 例 |
|---|---|
| メソッド / クラスのアノテーション | `@PreAuthorize("hasAuthority('SCOPE_orders:read')")`、`@Secured`、`@RolesAllowed`、`@PostAuthorize` |
| `SecurityFilterChain` | `.requestMatchers("/admin/**").hasRole("ADMIN")`、`.permitAll()`、`.anyRequest().authenticated()` |
| オブジェクト単位の認可 | `hasPermission(#id, 'Order', 'read')`、`PermissionEvaluator`、独自の `@CheckOwnership` |
| データ取得 | `findById(id)` か `findByIdAndOwnerId(id, userId)` / `findByIdAndTenantId(...)` か、`@Query` に所有者条件があるか |

`requestMatchers` はパターンの記述順で評価される点に注意（先に書いた `permitAll` が後の制限より優先される）。

### Step 3. Finding を判定する
| ID | 判定条件 |
|---|---|
| F1 認証なし | `permitAll()` 対象、または `SecurityFilterChain` のどのルールにも掛からない（公開前提の `/health` 等は除外し理由を書く） |
| F2 スコープ無し | 認証は必須だが、スコープ / ロールの指定がどこにも無い |
| F3 スコープ不適切 | 書き込み系（POST/PUT/PATCH/DELETE）が `:read` 系スコープで通る、より広いスコープで代用している |
| F4 IDOR / BOLA 候補 | パス変数・パラメータの ID でリソースを取得し、**所有者 / テナント照合が無い**（`findById(id)` をそのまま返す等） |
| F5 BFLA | 管理系の処理（`/admin`、ロール変更、他ユーザー操作）に一般ユーザー権限で届く |
| F6 Mass Assignment | `@RequestBody` で JPA Entity を直接受け、`role` / `ownerId` / `status` 等を書き換えられる |
| F7 SQLi | `@Query(nativeQuery = true)`、`JdbcTemplate`、`createNativeQuery`、`createQuery` での文字列連結 / `String.format` |
| F8 過剰露出 | Entity をそのまま返す（DTO 無し）、`size` / `limit` に上限が無い |
| F9 OS コマンドインジェクション | 外部入力（リクエストのパラメータ・ヘッダー・ボディ・アップロードされたファイル名）が `Runtime.exec` / `ProcessBuilder` に届く。特に `sh -c` / `cmd /c` に文字列連結で渡すもの |
| F10 安全でないデシリアライズ | 外部入力を `ObjectInputStream.readObject` / `XMLDecoder` / XStream（許可リスト無し）で読む、Jackson の多態型を広く有効化（`enableDefaultTyping`、`@JsonTypeInfo(use = Id.CLASS)`）、SnakeYAML で `new Yaml()` を既定のまま外部入力に使う |

F9 / F10 は、入力の出どころ（リクエスト → メソッド呼び出しの連鎖）を辿り、**外部入力が届く場合だけ**報告する。届くか判断できない場合は `needs_review`。

OpenAPI 定義がある場合は、**定義のスコープと実装のスコープのズレ（ドリフト）**を F2 / F3 として報告する。

### Step 3.5（任意）IAST の結果で裏付ける
テスト環境に IAST（New Relic Security Agent）が入っている場合、IAST が検出した脆弱性と Finding を突き合わせる。
両方で見つかったものは `confidence: confirmed`。対応関係は `shared/standards.json` の `iast`、役割分担は `shared/data-sources.md` §4。
IAST で見つからなかったことを理由に Finding を取り下げない（テストで通らなかった経路は検査されないため）。

### Step 4. 特徴量を付ける
各 Finding について `shared/risk-scoring.md` §4 の `features` を埋める。

| 特徴量 | 判定のヒント |
|---|---|
| `data_sensitivity` | DTO / Entity のフィールド名: `myNumber` / `individualNumber`（マイナンバー）→ sensitive_personal、`cardNumber` / `cvv` → payment、`password` / `secret` / `token` → credential、`email` / `phone` / `address` / `birthDate` → personal |
| `privilege` | `/admin`、ロール・権限の変更 → admin |
| `bulk` | 一覧・検索・エクスポート、ページサイズ上限なし |
| `id_type` | `Long` / `Integer` の自動採番 → sequential、`UUID` → uuid |
| `exposure` | 外部公開パス → external、モバイル向け（`/mobile`、`/app`、モバイルクライアントから呼ばれる）→ mobile、内部専用 → internal_only、不明 → unknown |
| `gateway_enforced` | Gateway / OpenAPI でスコープ検証が確認できた場合のみ true |

### Step 5.（任意）New Relic で補正する
Ground Truth MCP（`newrelic-us` または `newrelic-jp`）で、エンドポイントとトランザクション名を突き合わせる。

```sql
-- エンドポイント別トラフィック（直近7日）
SELECT rate(count(*), 1 minute) FROM Transaction
WHERE appName = '{appName}' SINCE 7 days ago FACET name LIMIT MAX
```

- Spring のトランザクション名は設定によって `WebTransaction/SpringController/orders/{id} (GET)` 形式や
  `OrderController/getOrder` 形式になる。どちらでも突き合わせられるよう、パスとハンドラ名の両方で照合する。
- 一致しないものは `traffic_rpm: null`（未観測）。**0 と null を混同しない。**
- `attack_signal`: `nr-appsec-guard` の `references/detections.nrql.md` を実行し、末尾の「エンドポイント別 `attack_signal` の決め方」に従って決める。
  判定不能だった場合はスコア上 `none` として渡し、レポートに「判定不能（理由）」と書く。

トラフィック一覧は `nr-appsec-guard` の U01 でも取得できる（画面から呼ばれている API は U02）。あわせて **シャドー API**（New Relic にトラフィックがあるのにソースに無い）と
**ゾンビ API**（ソースにあるのにトラフィックが無い）を一覧にする（OWASP API9）。

### Step 6. 順位付けする
```bash
python3 <plugin-root>/scripts/risk_score.py findings.json --overrides criticality.yaml --format md
```

### Step 7. レポートを出す
`shared/goals.md` の「レポートの書き方」に従い、**今わかること（1〜5）と推奨（6〜7）を別の節に分ける。**

**今わかること**
1. サマリー（P0・P1 の件数、`dormant_critical` の件数）
2. ランキング表（スクリプトの出力をそのまま使う）
3. Finding の詳細（根拠 `file:line`、点数の内訳 `breakdown`、規格の番号 `standards`、修正パッチ案）
4. **スコープ一覧表**（CSV: `method,path,handler,required_scope,ownership_check,finding_ids`）
5. **IDOR の回帰テスト案**（MockMvc: ユーザー A がユーザー B のリソースを取得すると 403 / 404 になること）
**推奨**
6. 修正の推奨（Finding ごとの修正パッチ案は 3 に付けたもの。ここでは優先度順の対応計画にまとめる）
7. 計装の推奨（`shared/attribute-spec.md` の属性を、どのエンドポイントにどの計装の手段（yml / XML / API）で入れるか。**まず S2 の2属性**を、所有者照合が必要なエンドポイント（F4 の候補）に入れる）
   - Java / Spring の場合は、F4 の候補ごとに **データ取得メソッドへ `@CheckOwnership(type = "...")` を付けるパッチ案**と、エンティティへの `Owned` の実装案を出す（`nr-appsec-guard` の `references/instrumentation-java.md`）。最初は OBSERVE モードを推奨する
   - 所有者照合が無い F4 の候補は、修正（照合の追加）が本来の対策。計装は「どこで実際に起きているか」を確かめるためのもの、と区別して書く

`dormant_critical` は「修正」ではなく「無効化または削除」を最初の対応として提示する。
