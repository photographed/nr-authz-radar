# リファレンス: データ・計装・アラート・ログ

必要なデータ、API の方式ごとの注意、計装の入れ方、アラートとログの扱いをまとめます。使い方の流れは [getting-started.md](getting-started.md)、考え方は [concepts.md](concepts.md)。

## 1. New Relic に必要なデータ

**見える範囲は「何のデータが入っているか」で決まります。** まず APM と分散トレーシングで API の実態をつかみ、そこから広げます。Readiness 監査はこの表を上から確認して不足を指摘します。詳細は [`shared/data-sources.md`](../shared/data-sources.md)。

| 優先度 | データソース | 主なイベント | これでできること |
|---|---|---|---|
| **必須** | APM エージェント | `Transaction`、`TransactionError` | API ごとのアクセス・ステータス・例外。**トランザクション名 = API エンドポイント** |
| **必須** | 分散トレーシング | `Span` | API の中の SQL 文・外部呼び出し。画面から API までのつながり |
| 推奨（S2） | 認可属性（コード計装） | `Transaction` の custom attribute | **IDOR 成功を証拠として見る唯一の手段**。最小は2属性（[`shared/attribute-spec.md`](../shared/attribute-spec.md)） |
| 推奨 | Browser エージェント | `PageView`、`AjaxRequest` | 画面から実際に呼ばれている API の一覧。正規の画面を通った呼び出しかの判定 |
| 推奨 | Change Tracking | デプロイ記録 | 「攻撃か、自分たちの変更か」の切り分け |
| 任意 | Logs in context・アクセスログ | `Log` | **調査の最後の詰めだけ**（全件の確定）。**攻撃を探すログ全文スキャンはしない。無くても検知・棚卸しは動く** |
| 任意 | WAF・ミドルウェア・OS のログ、Infrastructure / NPM | `Log`、`SystemSample` など | エッジの判定、侵入後の兆候 |
| 任意（申請制） | **IAST**（Limited Preview。Java は [New Relic Security Agent](https://github.com/newrelic/csec-java-agent)） | — | テスト環境で SQLi・RCE 等を検出し、コード監査を裏付ける。**本番では使わない。IDOR などの認可不備は IAST の対象外**なので補い合う |

### New Relic の機能との連携状況（正直な現状）

| 機能 | 状態 | 内容 |
|---|---|---|
| APM・分散トレーシング | ✅ 使用 | 検知・利用実態・調査の土台 |
| Browser | ⚠️ 一部 | `AjaxRequest`（U02）、Browser 由来の分散トレーシング（D12・U03）、セッションの無い API 呼び出し（D24）。`JavaScriptError` などは未使用 |
| Logs | ✅ ラストワンマイル | **スキャンはせず**、APM の手がかりで範囲を絞って取りに行く（L01〜L04、R16） |
| Errors Inbox | ⚠️ 間接的 | 元データの `TransactionError` を NRQL で使用（D06・D17・D21）。状態の連携は未実装（[`shared/inbox-integration.md`](../shared/inbox-integration.md)） |
| Performance Risks Inbox | ❌ 未実装 | 読み替えを設計済み。実データで確認してから実装 |
| Autopilot・iRCA | ⚠️ 下書き | Workflow Automation から呼ぶ形の下書き（未検証） |

### トランザクション名が API 単位になっているか

API 単位で認可を評価するには、**1つの API = 1つのトランザクション名**である必要があります。

| 状態 | 例 |
|---|---|
| ✅ 良い | `WebTransaction/SpringController/api/v1/orders/{id} (GET)` |
| ⚠️ まとめられすぎ | `WebTransaction/Servlet/dispatcherServlet`（全 API が同じ名前） |
| ⚠️ 細かすぎ | `.../orders/12345 (GET)`（ID ごとに名前が分かれる） |

### API 設計を3つの視点で突き合わせる

| 視点 | データ | ズレからわかること |
|---|---|---|
| コード | コード監査のエンドポイント一覧 | コードにあるのに観測されない → ゾンビ API |
| サーバー | APM の `Transaction` | 観測されるのにコードにない → シャドー API |
| 画面 | Browser の `AjaxRequest` | サーバーで呼ばれているのに画面からは呼ばれない → **直接呼び出しの可能性** |

## 2. API の方式（REST・GraphQL・SOAP・gRPC・WebSocket・JSON-RPC）

所有者照合（S2）はデータ取得の層で行うので、**方式や呼び出し元に関係なく同じ判定ができます。** 方式ごとの見え方の違いは [`shared/protocols.md`](../shared/protocols.md)。

| 方式 | 標準の計装 | 注意点 | 対策 |
|---|---|---|---|
| REST | ✅ | — | — |
| GraphQL | ✅ | **拒否しても 200**。トランザクション名は**クライアントが偽装できる** operation 名から作られる。エイリアスで1回に大量の ID を並べられる | `api.operation`（サーバー側）、D22、D23、F11 |
| SOAP | ✅ | 拒否が **500 の SOAP Fault** になりやすい | `api.operation`、D22 |
| gRPC | ✅ | HTTP ではなく gRPC のステータス | D04・D10 を `response.status` で読み替え |
| **WebSocket** | ❌ **計装なし** | **メッセージがトランザクションにならず属性が捨てられる**（エラーにもならない） | **メッセージごとにトランザクションを作る**（Java ライブラリは STOMP に自動対応）、R15、F12 |
| JSON-RPC | HTTP として | 1つの URL にまとまり、エラーは 200 | `api.operation`、D22 |

**ステータスコードを使う検知（D04・D10）は REST 専用です。** REST 以外で反応しないことを「安全」と読まないでください。

## 3. 計装（S2 への最短経路）

S2（IDOR 成功の証拠）に到達するためのコードを [`instrumentation/`](../instrumentation/) に置いています。全言語で仮名化したユーザー ID が同じ値になります。

| 言語 | 形 | 状態 |
|---|---|---|
| **Java**（Spring Boot / Spring Security） | 計装ライブラリ（アノテーション1つ。REST・GraphQL・WebSocket(STOMP) 対応） | ✅ Spring Boot 3.5・4.1 でテスト済み |
| **PHP**（Laravel 12 / 素の PHP） | 計装ライブラリ（Composer。ミドルウェア / トレイト） | ✅ 関数名をエージェント 12.12.0 で確認。PHP 8.5.11 のデモで実動作確認 |
| **Next.js**（App Router / Pages / Server Actions） | ヘルパー（`withAuthzRadar`。Route Handler で使う。Edge は対象外） | ✅ 単体テスト＋Next.js 15 のデモで確認 |
| Python・Node.js・Ruby・Go | 取り込める小さなファイル | ✅ 単体テスト済み |
| .NET | 同上 | ❌ 未コンパイル |

- コード監査（エンドポイント棚卸し）は言語ごとに `scripts/inventory_{java,php,python,node,ruby,go}.py`。
- コードを変更できない Java 向けに、認可チェックの XML 計装候補を作る `scripts/gen_xml_candidates.py`。
- リポジトリ→appName の突合は `scripts/find_appname.py`。
- 手元で試せる脆弱なデモ（ローカル専用）: [`examples/php-vuln-site`](../examples/php-vuln-site)（Laravel）、[`examples/nextjs-vuln-site`](../examples/nextjs-vuln-site)（Next.js）。
- 詳しい入れ方: [`instrumentation-java.md`](../skills/nr-appsec-guard/references/instrumentation-java.md)、[`instrumentation-php.md`](../skills/nr-appsec-guard/references/instrumentation-php.md)、[`instrumentation-nextjs.md`](../skills/nr-appsec-guard/references/instrumentation-nextjs.md)、[`instrumentation-other-languages.md`](../skills/nr-appsec-guard/references/instrumentation-other-languages.md)。

Java の例:
```java
@CheckOwnership(type = "order")          // データ取得メソッドに付けるだけ
public Order find(Long id) { ... }
```
既定は S2 の最小セット。まず **OBSERVE モード**（記録だけ）で本当に起きている IDOR を見てから、**ENFORCE モード**（拒否）に切り替えます。必要スコープは `@PreAuthorize` / `@Secured` から自動取得。

## 4. アラートと通知

```bash
python3 scripts/gen_alerts.py --stage S2 --sources spans,browser_dt --out out/terraform
```

- **今の段階とデータソースで動くアラートだけ**を Terraform として生成します（定義は [`shared/alerts.json`](../shared/alerts.json)）。生成しなかったものは `SKIPPED.md` に「何があれば追加できるか」付きで出ます。適用は人が行います。
- **証拠の強さで振り分けます**（偽陽性対策）:

| 証拠の強さ | 例 | 通知 |
|---|---|---|
| **証拠** | D01（他人のデータを返した）、D07（注入された形の SQL が実行された） | **CRITICAL**。Workflow で情報を集め、Autopilot（有効時。iRCA も使う）に調査させてから通知 |
| 強い兆候 | D02、D06、D21、D23 | HIGH（静かなチャンネル）。導入直後（`learning_mode`）は通知しない |
| 異常 | D03、D04、D10、D12 など | **既定では生成しない**。`--include-anomaly` で通知しない別ポリシーに入れ日次確認 |

| テンプレート | 状態 |
|---|---|
| Terraform（アラート・ポリシー・Workflow・Slack） | 構文チェック（`fmt`）のみ。`validate` は未実施 |
| Workflow Automation | **下書き・未検証**。一部のアクション名は公式テンプレートと照合が必要 |
| Slack 通知・Autopilot プロンプト・ランブック | 完成 |

## 5. ログ（ラストワンマイル）

**ログはスキャンしません。** APM の手がかり（トレース ID・ユーザー・時間帯）を起点にピンポイントで取りに行きます。

| ID | 内容 | 起点 |
|---|---|---|
| L01 | **IDOR の証拠のログ行**（誰の、どのレコードか） | D01 のトレース ID |
| L02 | 調査対象のアクセスの全件（APM に入らないクエリ文字列、サンプリング漏れ） | ④ 調査の対象と期間 |
| L03 | エッジ（WAF・CDN）で遮断されたリクエスト | 兆候の時間帯 |
| L04 | アプリが出した認可判断のログ行（High-security mode の代わり） | アプリ名と期間 |

CRITICAL のときは Workflow が L01 を取りに行きます。Java ライブラリの `log-decisions: true` で、拒否と「所有者が違うのに通した」ときだけ決まった形の1行を出します（ユーザー ID は入れない）。R16 でログにトレース ID が付いているかを確認します。

## 6. コストとトークン

- **定期の Hunt は `scripts/hunt.py`**（NerdGraph で NRQL を直接実行。AI を使わない）。毎日は軽量（`--levels evidence,strong`、最大7クエリ）、週1回は全部（最大21クエリ）。
- Ground Truth MCP は対話での調査に使い、**NRQL を実行するツールだけ**に絞る。Autopilot は CRITICAL のアラートからだけ。
- Claude のトークン: 短い SKILL.md・`catalog.py`（必要な節だけ）・`hunt.py` の要約・差分モードで読む量を減らしています。詳細は [`shared/cost.md`](../shared/cost.md)。

## 7. New Relic MCP（Ground Truth）の接続

プラグインの `.mcp.json` には US リージョン（`newrelic-us`）を登録しています。認証は OAuth が標準です（初回接続時にブラウザで認可）。

JP リージョンを使う場合は、公式ドキュメントで JP のエンドポイント URL を確認し、`newrelic-jp` という名前で追加してください。

```bash
claude mcp add --transport http newrelic-jp <JP リージョンの MCP エンドポイント URL>
```

> 未設定の環境変数を URL に使うと設定全体が無効になるため、JP は既定では登録していません。
