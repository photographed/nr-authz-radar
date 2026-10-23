# API の方式ごとの対応（REST・GraphQL・SOAP・gRPC・WebSocket・JSON-RPC）

**どの方式でも変わらないこと**: 所有者照合（S2）はデータ取得の層で行うので、方式や呼び出し元に関係なく同じ判定ができる（`docs/how-it-works.md`）。
**方式によって変わること**: API の一覧の作り方、トランザクション名、エラーの返り方、方式に固有の攻撃。

> 「JSON」は方式ではなくデータ形式。REST と JSON-RPC の行に含まれる。

## 1. 方式ごとの違い

| 方式 | Java エージェントの標準の計装（9.5.0 で確認） | トランザクション名 | 拒否・エラーの返り方 | ステータスを使う検知（D04・D10） |
|---|---|---|---|---|
| **REST** | ✅ | パスのテンプレート（例: `/orders/{id} (GET)`） | 401 / 403 / 404 | ✅ そのまま使える |
| **GraphQL** | ✅ graphql-java 16〜22 | **クライアントが付けた operation 名から作られる**（例: `GraphQL/operation/QUERY/<anonymous>/order`） | **拒否しても 200**（本文の `errors` に入る） | ❌ 反応しない → **D22** を使う |
| **SOAP** | ✅ Spring-WS 2.0、Apache CXF 2.7 | SOAPAction / 操作名（計装による） | 多くは **500 の SOAP Fault** | ❌ 反応しない → **D22** を使う |
| **gRPC** | ✅ grpc 1.4〜1.40 | サービス / メソッド名 | gRPC のステータス（`response.status`。7 = PERMISSION_DENIED、16 = UNAUTHENTICATED） | ⚠️ `response.status` で読み替える |
| **WebSocket**（STOMP を含む） | ❌ **計装なし**。接続（ハンドシェイク、101）だけがトランザクションになり、**メッセージはトランザクションにならない** | 接続の URL のみ | 接続を切る / エラーのメッセージを返す | ❌ 反応しない。そもそもメッセージが見えない |
| **JSON-RPC** | REST と同じ（HTTP として） | 全部が1つの URL（例: `/rpc (POST)`）にまとまる | 多くは 200（本文の `error` に入る） | ❌ 反応しない → **D22** を使う |

他の言語のエージェントの計装状況は未確認（各言語のドキュメントを参照）。

## 2. 方式ごとの盲点と対策

### GraphQL
| 盲点 | 対策 |
|---|---|
| トランザクション名がクライアントの operation 名で決まる。**攻撃者が `health` などに偽装できる**。名前を大量に変えて New Relic 側の集約（metric grouping issue）を起こすこともできる | `api.operation` に **サーバー側で決まるフィールド名**（例: `Query.order`）を送り、検知・利用実態はこちらで集計する |
| エイリアスで1回のリクエストに大量の ID を並べられる（`a1: order(id:1) a2: order(id:2) …`）。リクエスト数・URL 数で数える D02・D03 には1件にしか見えない | **D23**（1リクエストあたりの所有者照合の回数）。成功した IDOR は、所有者照合が1件でも一致しなければ false のまま残るので **D01 で見える** |
| 拒否しても 200 | **D22**（認可拒否の急増。方式に依存しない） |
| introspection が本番で有効、深さ・複雑さ・エイリアス数の上限がない | コード監査 **F11** |

### WebSocket
| 盲点 | 対策 |
|---|---|
| **メッセージがトランザクションにならないので、S2 の属性を送っても捨てられる**（エラーにもならない） | **メッセージごとにトランザクションを作る**（§3）。名前は `WebSocket/<宛先のテンプレート>` |
| 購読先の IDOR（他人の `/topic/orders/123` を購読できる） | 購読（subscribe）の処理にも所有者照合を入れる。コード監査 F4 の対象にする |
| 認可を接続時の1回しか確認しない | コード監査 F2（メッセージ単位の認可が無い） |
| 接続中にトークンが失効・取り消されても接続が続く | コード監査 **F12** |
| 接続元（Origin）を確認していない（Cross-Site WebSocket Hijacking） | コード監査 **F12** |

### SOAP・JSON-RPC
| 盲点 | 対策 |
|---|---|
| 1つの URL に操作が集まる | `api.operation` に操作名を送る。トランザクション名も操作単位にする（§3） |
| 拒否が 500 や 200 で返る | **D22** |
| SOAP の XXE | 本プラグインの対象外（IAST の結果を参照） |

### gRPC
| 盲点 | 対策 |
|---|---|
| HTTP のステータスではない | D04・D10 を `response.status`（gRPC のステータス）で読み替える。`api.protocol = grpc` |

## 3. トランザクションの作り方・名前の付け方

| 方式 | 方法 |
|---|---|
| GraphQL | Java: エージェントの計装に任せ、`api.operation` を計装ライブラリが送る。他の言語: リゾルバでサーバー側のフィールド名を `api.operation` に送る |
| SOAP | Java: エージェントの計装（Spring-WS・CXF）。`api.operation` に操作名 |
| gRPC | Java: エージェントの計装 |
| **WebSocket（Java / Spring STOMP）** | 計装ライブラリが `@MessageMapping` / `@SubscribeMapping` ごとにトランザクションを作る（`@Trace(dispatcher = true)`）。名前は `WebSocket/<宛先のテンプレート>` |
| WebSocket（Node.js） | `newrelic.startWebTransaction('/ws/<種類>', handler)` |
| WebSocket（Python） | `@newrelic.agent.web_transaction(...)` または `@newrelic.agent.background_task(name=...)` |
| WebSocket（Ruby） | `NewRelic::Agent::Tracer.in_transaction(name: 'WebSocket/<種類>', category: :web) { ... }` |
| WebSocket（Go） | `txn := app.StartTransaction("WebSocket/<種類>")` と `defer txn.End()` |
| WebSocket（.NET） | メッセージを処理するメソッドに `[Transaction(Web = true)]`、`SetTransactionName` |
| WebSocket（PHP） | 未確認（`newrelic_start_transaction` 等。エージェントのドキュメントを参照） |

上の API 名は各エージェントのパッケージで確認した（Node.js newrelic 14.8.0、Python newrelic 14.1.0、Ruby newrelic_rpm 10.9.1、Go go-agent v3.45.0、.NET NewRelic.Agent.Api 10.56.0）。

## 4. コード監査で棚卸しの対象にするもの（Java）

| 方式 | 探すもの |
|---|---|
| REST | `@RestController` の `@GetMapping` 等、`RouterFunction`、JAX-RS の `@Path` |
| GraphQL | Spring for GraphQL の `@QueryMapping` / `@MutationMapping` / `@SubscriptionMapping` / `@SchemaMapping`、Netflix DGS の `@DgsQuery` / `@DgsMutation` / `@DgsData`、スキーマ（`*.graphqls`）の `id: ID!` 引数 |
| SOAP | Spring-WS の `@Endpoint` + `@PayloadRoot`、JAX-WS の `@WebService` / `@WebMethod` |
| gRPC | `*Grpc.*ImplBase` を継承したクラスのメソッド |
| WebSocket | `@MessageMapping` / `@SubscribeMapping`、`WebSocketHandler` / `TextWebSocketHandler`、`@ServerEndpoint`、Spring Security の messaging の認可設定、`setAllowedOrigins` / `setAllowedOriginPatterns` |

エンドポイントの表記（Finding・優先度の入力で使う）:

| 方式 | 例 |
|---|---|
| REST | `GET /api/v1/orders/{id}` |
| GraphQL | `GRAPHQL Query.order` |
| SOAP | `SOAP getOrder` |
| gRPC | `GRPC OrderService/GetOrder` |
| WebSocket | `WS SUBSCRIBE /topic/orders/{id}`、`WS SEND /app/orders.update` |
| JSON-RPC | `JSONRPC order.get` |
