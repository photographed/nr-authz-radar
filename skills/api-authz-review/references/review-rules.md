# コード監査の詳細な手順（api-authz-review）

`SKILL.md` から必要なときに読む。Step ごとに必要な部分だけを読めばよい。

### Step 0. 入力を確認する
- 対象リポジトリ（またはモジュール）
- あれば: OpenAPI 定義（`security` / `scopes`）、API Gateway の設定（Kong / AWS API Gateway / Apigee 等）、`criticality.yaml`
- New Relic を使うか（使う場合は `newrelic-us` / `newrelic-jp` のどちらか、対象の `appName`）

Gateway の設定が無い場合は、「スコープ検証がコード外にある可能性」をユーザーに一度だけ確認する。

**New Relic を使う場合は、まず `python3 scripts/find_appname.py <repo>` でリポジトリ→appName を特定する。**
各エージェントの設定（`newrelic.yml`/`newrelic.ini`/`newrelic.js`/`newrelic.config`、Go の `ConfigAppName`、環境変数 `NEW_RELIC_APP_NAME`）から候補を出す。確度 high が1つなら確認のうえ採用、複数（prod/staging・複数サービス）や0件（環境変数で外出し）ならユーザーに確認する。混ぜて1つのレポートにしない。

### Step 1. エンドポイント一覧を作る（Java / Spring）

**まず `scripts/inventory_java.py` を実行し、その結果（`inventory.md`）から読み始める。** リポジトリ全体を読まない。
スクリプトは正規表現による候補の抽出なので、フラグの付いたメソッドと、認可の無いエンドポイントを `file:line` で開いて確かめる。
スクリプトが拾えない形（WebFlux の `RouterFunction`、JAX-RS、gRPC、`@ServerEndpoint`、独自のアノテーション）が使われている場合だけ、該当するファイルを grep で探す。

探すもの（スクリプトの対象と、手で補うもの）:
- `@RestController` / `@Controller` 内の `@RequestMapping` / `@GetMapping` / `@PostMapping` / `@PutMapping` / `@PatchMapping` / `@DeleteMapping`（クラスとメソッドのパスを結合）
- WebFlux の `RouterFunction`（`route(GET("/..."), handler)`）
- JAX-RS（`@Path` + `@GET` 等）が混在していればそれも
- **REST 以外の方式**（`shared/protocols.md` §4）: GraphQL（`@QueryMapping` 等、DGS、スキーマの `id: ID!`）、SOAP（`@PayloadRoot`、`@WebMethod`）、gRPC（`*ImplBase`）、WebSocket（`@MessageMapping` / `@SubscribeMapping`、`WebSocketHandler`、`@ServerEndpoint`）。
  見落とすと棚卸しから丸ごと漏れる。エンドポイントの表記は同 §4（例: `GRAPHQL Query.order`、`WS SUBSCRIBE /topic/orders/{id}`）

各エンドポイントについて: HTTP メソッド、パス、ハンドラ（`Class#method`）、パス変数、`@RequestBody` の型、戻り値の型。

### Step 1b. エンドポイント一覧を作る（PHP / Laravel）

PHP のリポジトリでは **`scripts/inventory_php.py <src>` を実行し、`inventory.md` から読み始める**。
Laravel のルート（`routes/*.php` の `Route::get('/path', [Ctrl::class, 'method'])`）と、各ルート・グループのミドルウェア、
コントローラ本体の怪しい箇所（`find_by_id`・`sql_concat`・`mass_assignment`・`command_exec`・`unserialize`・`dynamic_include`）を候補として出す。

- **ミドルウェア** `auth` は認証であって認可ではない。所有者照合（`authz.owner` ミドルウェア・`ensureOwns`・`->where('user_id', ...)`・Gate/Policy）が **本体に無い** エンドポイントを開いて確かめる。
- `sql_concat` と raw SQL 一覧は F7（SQLi）の候補。`DB::select("… " . $x)` や `whereRaw`・`->query` の文字列連結。
- スクリプトが拾えない形（`Route::resource`、`__invoke` コントローラ、`spatie/laravel-permission`、Lumen、素の PHP ルータ、GraphQL の Lighthouse）は grep で補う。

### Step 1c. エンドポイント一覧を作る（Python / Flask・FastAPI・Django）

**`scripts/inventory_python.py <src>` を実行し、`inventory.md` から読み始める**。Flask / FastAPI のルートデコレータ、
DRF / Django のクラスビュー（`get`/`post` …）と、その認可（`@login_required`・`permission_classes`・`Depends(...)`）、
ハンドラ本体の候補（`get_by_id`・`sql_concat`・`command_exec`・`unsafe_deserialization`・`mass_assignment`）を出す。

- **認証 ≠ 認可**: `@login_required` や `Depends(get_current_user)` があっても、所有者照合（`filter(user=...)`・`request.user` との比較）が無ければ IDOR。
- パスが `?` の行は Django/DRF で `urls.py`（または `urlpatterns`）に定義されている。`urls.py` を開いて実パスを対応づける。
- **拾えない形**: FastAPI の位置引数 `Model.get(id)`（`.get(` は dict 等と区別できないため未フラグ）、`get_object_or_404(Model, id)` の一部、Starlette の `Mount`/`add_route`、Tornado、独自のルータ。これらは grep で補う。
- SQLi は `cursor.execute(f"…")`・`.raw()`・`.extra()` の文字列組み立て。ORM の素のクエリに注意。

### Step 1d. エンドポイント一覧を作る（Node.js / Express・Next.js）

**`scripts/inventory_node.py <src>` を実行し、`inventory.md` から読み始める**。Express/Koa/Fastify の
`app.get('/x', mw, handler)` と、Next.js のファイルベースルート（`app/**/route.{js,ts}` の `export GET`、`pages/api/**`）、
ミドルウェアの認可、本体の候補（`find_by_id`・`sql_concat`・`command_exec`・`unsafe_deserialization`・`mass_assignment`）を出す。

- **認証 ≠ 認可**: `requireAuth`・`passport.authenticate` は認証。所有者照合（`req.user` との比較・`where: { userId }`・`ownership(...)`）が無ければ IDOR。
- **Next.js の `middleware.ts` は Edge ランタイムで、New Relic にも検知にも出ない。** 認可をそこだけに置くのは危険。所有者照合は Route Handler の中で確認する（`instrumentation-nextjs.md`）。
- **拾えない形**: NestJS の `@Get()` + `@UseGuards()`、Fastify の `fastify.route({...})`、動的に組むルータ、tRPC、GraphQL のリゾルバ。これらは grep で補う。
- BFLA（管理者操作に役割チェックが無い）は regex では出ないので、`/admin/` などのパスは本体を読んで役割確認の有無を見る。

### Step 1e. エンドポイント一覧を作る（Ruby / Rails・Sinatra）

**`scripts/inventory_ruby.py <src>` を実行**。コントローラのアクションと、そこに掛かる `before_action`、本体の候補
（`find_by_id`・`sql_concat`・`command_exec`・`unsafe_deserialization`・`mass_assignment`）、`config/routes.rb` のルートを出す。

- **認証 ≠ 認可**: `before_action :authenticate_user!` は認証。`current_user.orders.find(...)` のようにスコープしていない `Model.find(params[:id])` は IDOR。
- 認可は Pundit（`authorize @order`）や CanCanCan（`load_and_authorize_resource`）で表現されることが多い。これらが本体・フィルタに無いか確認する。
- `routes.rb` の `resources` は複数のアクション（index/show/create/update/destroy）に展開される。実際に定義されているアクションと突き合わせる。
- SQLi は `where("... #{params} ...")`・`find_by_sql`・`order(params[...])`。

### Step 1f. エンドポイント一覧を作る（Go / net/http・chi・gin・echo）

**`scripts/inventory_go.py <src>` を実行**。`r.Get("/x", h)`・`mux.HandleFunc`・`e.GET` などのルート登録、一緒に渡すミドルウェア、
本体の候補（`query_by_id`・`sql_concat`・`command_exec`・`template_injection`）を出す。

- Go は認可フレームワークが定型でないので、`query_by_id`（リクエストの id をそのまま WHERE に使い、所有者の列が無い）を特に確認する。
- SQLi は `fmt.Sprintf` で組んだ文字列を `db.Query`/`Exec` に渡す形。プレースホルダ（`$1`・`?`）を使っているかを見る。
- **拾えない形**: 標準ライブラリの `http.ServeMux` を変数経由で組む、独自ルータ、gRPC。grep で補う。

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
| F11 GraphQL の防御不足 | 本番で introspection が有効（無効化の設定が無い）、クエリの深さ・複雑さの上限が無い（`MaxQueryDepthInstrumentation` 等が無い）、エイリアス・バッチの数の上限が無い |
| F12 WebSocket の防御不足 | `setAllowedOrigins("*")` / `setAllowedOriginPatterns("*")`（Cross-Site WebSocket Hijacking）、接続中にトークンの失効・取り消しを確かめない（接続時の1回だけの認証） |
| F10 安全でないデシリアライズ | 外部入力を `ObjectInputStream.readObject` / `XMLDecoder` / XStream（許可リスト無し）で読む、Jackson の多態型を広く有効化（`enableDefaultTyping`、`@JsonTypeInfo(use = Id.CLASS)`）、SnakeYAML で `new Yaml()` を既定のまま外部入力に使う |

WebSocket の **購読（subscribe）で他人の宛先を指定できる** ものは F4、**メッセージ単位の認可が無い**（接続時だけ確認している）ものは F2 として報告する。GraphQL の引数で ID を受け取るリゾルバは F4 の判定の対象。

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
   - 他の言語は `nr-appsec-guard` の `references/instrumentation-other-languages.md` の関数を、データ取得の直後に呼ぶパッチ案を出す
   - コードを変更できない場合は `scripts/gen_xml_candidates.py` で XML の候補を作る（認可チェックが実行されたかは見えるが、S2 にはならない）
   - 所有者照合が無い F4 の候補は、修正（照合の追加）が本来の対策。計装は「どこで実際に起きているか」を確かめるためのもの、と区別して書く

`dormant_critical` は「修正」ではなく「無効化または削除」を最初の対応として提示する。
