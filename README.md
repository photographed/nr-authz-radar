# nr-authz-radar

**New Relic Ground Truth（MCP）で、IDOR / BOLA・SQLi・AI エージェントによる API 攻撃に気づき、優先順位を付ける Claude Code プラグイン。**

> Claude Code plugin that detects and ranks authorization attacks (IDOR/BOLA, scope abuse, SQLi, AI-agent-like scraping)
> using New Relic Ground Truth (MCP), and audits API authorization scopes in source code.
> Community project — not affiliated with or endorsed by New Relic.
>
> **English: [README.en.md](README.en.md) / [Getting started](docs/getting-started.en.md)**

**はじめての方は [はじめに（インストールと使い方）](docs/getting-started.md) から。** 何が自動で何を人がやるか、頼み方の例、サンプルのレポートをまとめています。

## なぜ SIEM ではないのか

IDOR は攻撃が成功すると **200 OK** で返ります。ログを集めて相関しても「正常なアクセス」にしか見えません。
**攻撃が成功した IDOR を証拠として見つける**には、アプリ自身が「誰のデータに触れたか」を送る必要があります（必要なのは2属性だけ）。
一方で、それ以外の多くのこと（API の棚卸し、利用実態、SQLi や RCE の兆候、認証攻撃）は、**APM を入れただけの状態からでもできます。**
このプラグインは、ソースコードの **認可監査**、APM・分散トレーシング・Browser・ログを使った **利用実態の把握と検知**、
**調査の手順**、そして **段階的な計装の推奨** をセットで提供します。

## 4つの目的

扱う問題は4つの別々の目的に分かれます。答えたい問いも必要なデータも違うので、混ぜずに扱います。詳細は [`shared/goals.md`](shared/goals.md)。

| 目的 | 答えたい問い | 今のデータでできること（APM を入れただけ = S0） | 推奨に従うと増えること |
|---|---|---|---|
| **① 棚卸し** | API は全部でいくつあり、どんな認可設計か | **コード監査はすべて可能**（New Relic 不要）。観測されている API との突き合わせ | トランザクション名を API 単位に整えると突き合わせが正確になる |
| **② 利用実態** | どの API が、どこから、どれだけ使われているか | API ごとの件数・ステータス・呼び出し元（画面 / モバイル / 直接） | S1 でユーザー単位の利用状況 |
| **③ 攻撃検知** | 今、攻撃を受けているか | 403/404 の急増、SQLi・RCE の兆候、認証失敗の急増、画面を通らない直接呼び出し、新しい外部通信 | S1 で ID 列挙、**S2 で IDOR 成功の証拠**、S3 でスコープ不足・API キーの異常 |
| **④ 調査** | 何をされたか、どのデータが取られたか（200 も含む） | 対象のタイムライン、触った API、200 で返ったパス（**APM はサンプリングされ得るため一部**） | ログの取り込みで**全件での確定**、保存期間の延長 |

### 段階（アプリ側の計装をどこまでやるか）

| 段階 | やること | 増えること |
|---|---|---|
| **S0** | APM エージェントを入れる（分散トレーシングを有効に） | 上の表の「今のデータでできること」 |
| **S1** | `enduser.id` を送る（仮名化して） | ユーザー単位の利用実態・検知・調査 |
| **S2** | **`resource.owner_match` と `authz.decision` の2属性** | **IDOR 成功の証拠（D01）**。どうしても必要なコード計装はこれだけ |
| **S3** | 残りの属性 | スコープ不足、API キーの異常、トークンの有効期限など |

### レポートの原則
すべてのレポートで、**「今のデータでわかること・できること」と「推奨」を別の節に分けます。** 推奨には「それをやると何がわかるようになるか」と「どの目的に効くか」を必ず書きます。

## いつ使うか

**常時の監視は New Relic のアラートが担い、この Skill は「準備」「定期点検」「何かあったときの調査」で使います。** 目的ごとに適した頻度が違います。

| タイミング | 誰が動くか | やること | 目的 |
|---|---|---|---|
| **常時（毎分）** | **New Relic**（Skill は動いていない） | 生成したアラート（D01 など）が評価され、CRITICAL なら Workflow → Autopilot → Slack | ③ 攻撃検知 |
| **アラート発生時** | Skill（その都度） | 対象のユーザー・API・時間帯を起点に調査。関連する検知も実行 | ④ 調査 |
| **PR・リリースの前** | Skill（変更のたびに） | 変更された API だけをコード監査（所有者照合が抜けていないか）。**最も効果が大きい** | ① 棚卸し |
| **デプロイの1時間後** | Skill | 認可の挙動が変わっていないか確認（D01・D02・D18） | ③ 攻撃検知 |
| **毎日〜毎週** | Skill（定期） | **アラートにできない検知**（D05・D08・D09・D13・D14・D17・D20）を Hunt で実行 | ③ 攻撃検知 |
| **毎週〜毎月** | Skill（定期） | 利用実態とコードの突き合わせ（ゾンビ API・シャドー API）、優先度の更新 | ①② |
| **毎月〜四半期** | Skill（定期） | 前提の確認（段階の進み具合、プライバシー、サンプリング・保存期間）、しきい値の見直し、追加できるアラートの再生成 | 全体 |
| **四半期〜年1回** | Skill | リポジトリ全体のコード監査、規格の改訂の反映 | ① |
| **脅威情報が出たとき** | Skill（その都度） | 注意喚起（JPCERT など）に合わせて、該当する検知を Hunt で実行 | ③ |

- 毎日の Hunt が向いているのは、個人情報や決済を扱う API を外部に公開している場合。社内向けが中心なら毎週で十分です。
- **この Skill は呼ばれない限り動きません。** 定期実行には、Claude Code のスケジュール実行・GitHub Actions・`/loop` などを使います（テンプレートは今後追加予定）。無人実行での New Relic MCP の認証方法は未確認です。
- Autopilot の上限（1時間100リクエスト）はアラートからの自動実行と共有なので、定期の Hunt からは Autopilot を呼ばない設計にしています。

判定の仕組みの全体像は [`docs/how-it-works.md`](docs/how-it-works.md)。

## 前提: New Relic に必要なデータ

**見える範囲は「何のデータが入っているか」で決まります。** まず APM と分散トレーシングで API の実態をつかみ、そこから範囲を広げます。
Readiness 監査は、この表を上から順に確認して不足を指摘します。詳細は [`shared/data-sources.md`](shared/data-sources.md)。

| 優先度 | データソース | 主なイベント | これでできること |
|---|---|---|---|
| **必須** | APM エージェント | `Transaction`、`TransactionError` | API ごとのアクセス・ステータス・例外。**トランザクション名 = API エンドポイント** |
| **必須** | 分散トレーシング | `Span` | API の中の SQL 文・外部呼び出し。画面から API までのつながり |
| 推奨（S2） | 認可属性（コード計装） | `Transaction` の custom attribute | **IDOR 成功を証拠として見る唯一の手段**。最小は2属性（[`shared/attribute-spec.md`](shared/attribute-spec.md)） |
| 推奨 | Browser エージェント | `PageView`、`AjaxRequest` | 画面から実際に呼ばれている API の一覧。正規の画面を通った呼び出しかの判定 |
| 推奨 | Logs in context・アクセスログ | `Log` | トランザクションと結び付いたアプリのログ。**④ 調査で全件を確定させる手段**（APM はサンプリングされ得る） |
| 推奨 | Change Tracking | デプロイ記録 | 「攻撃か、自分たちの変更か」の切り分け（iRCA の精度にも影響） |
| 任意 | ミドルウェア・WAF・ファイアウォール・OS のログ | `Log` | クエリ文字列を含むリクエスト内容、エッジでの判定、侵入後の操作 |
| 任意 | Infrastructure / Network Performance Monitoring | `SystemSample`、`ProcessSample` など | 侵入後の兆候（不審なプロセス・通信） |
| 任意 | Vulnerability Management | — | 使っているライブラリの既知の脆弱性 |
| 任意（申請制） | **IAST**（Limited Preview。Java は [New Relic Security Agent](https://github.com/newrelic/csec-java-agent)） | — | テスト環境で SQLi・RCE・デシリアライズなどを検出し、コード監査の結果を裏付ける。**本番環境では使わない**。**IDOR などの認可の不備は IAST の対象外**なので、このプラグインと補い合う（[役割分担](shared/data-sources.md#4-iast-とこのプラグインの役割分担)） |

### New Relic の機能との連携状況（正直な現状）

| 機能 | 状態 | 内容 |
|---|---|---|
| APM（Transaction・TransactionError）・分散トレーシング（Span） | ✅ 使用 | 検知・利用実態・調査の土台 |
| Browser | ⚠️ 一部 | `AjaxRequest`（U02）、Browser 由来の分散トレーシング（`parent.type`。D12・U03）、**ブラウザのセッションが無いユーザーの API 呼び出し（D24）**。`JavaScriptError` などは未使用 |
| Logs（Logs in context・アクセスログ） | ✅ ラストワンマイル | **スキャンはせず**、APM の手がかり（トレース ID・ユーザー・時間帯）で範囲を絞って取りに行く（L01〜L04、R16） |
| Errors Inbox | ⚠️ 間接的 | 元データの `TransactionError` を NRQL で使用（D06・D17・D21）。**エラーグループの状態（未対応・解決済み・無視）などの連携は未実装**（設計: [`shared/inbox-integration.md`](shared/inbox-integration.md)） |
| Performance Risks Inbox | ❌ 未実装 | セキュリティの観点での読み替えを設計済み（同上）。データの取り出し方を実物で確認してから実装する |
| Autopilot・iRCA | ⚠️ 下書き | Workflow Automation から呼ぶ形の下書き（未検証） |

### トランザクション名が API 単位になっているか

API 単位で認可を評価するには、**1つの API = 1つのトランザクション名**である必要があります。

| 状態 | 例 |
|---|---|
| ✅ 良い | `WebTransaction/SpringController/api/v1/orders/{id} (GET)` |
| ⚠️ まとめられすぎ | `WebTransaction/Servlet/dispatcherServlet`（全 API が同じ名前） |
| ⚠️ 細かすぎ | `.../orders/12345 (GET)`（ID ごとに名前が分かれる） |

### API 設計（Ajax を含む）を3つの視点で突き合わせる

| 視点 | データ | ズレからわかること |
|---|---|---|
| コード | コード監査のエンドポイント一覧 | コードにあるのに観測されない → ゾンビ API |
| サーバー | APM の `Transaction` | 観測されるのにコードにない → シャドー API |
| 画面 | Browser の `AjaxRequest` | サーバーで呼ばれているのに画面からは呼ばれない → **直接呼び出しの可能性**（アプリ解析による API の特定） |

## API の方式（REST・GraphQL・SOAP・gRPC・WebSocket・JSON-RPC）

所有者照合（S2）はデータ取得の層で行うので、**方式や呼び出し元に関係なく同じ判定ができます。** 一方で、方式によって見え方が変わる部分があります。詳細は [`shared/protocols.md`](shared/protocols.md)。

| 方式 | Java エージェントの標準の計装 | 注意点 | 対策 |
|---|---|---|---|
| REST | ✅ | — | — |
| GraphQL | ✅ | **拒否しても 200**。トランザクション名は**クライアントが偽装できる** operation 名から作られる。エイリアスで1回に大量の ID を並べられる | `api.operation`（サーバー側のフィールド名）、D22（認可拒否の急増）、D23（1リクエストでの大量の照合）、F11 |
| SOAP | ✅ | 拒否が **500 の SOAP Fault** になることが多い | `api.operation`、D22 |
| gRPC | ✅ | HTTP ではなく gRPC のステータス | D04・D10 を `response.status` で読み替え |
| **WebSocket** | ❌ **計装なし** | **メッセージがトランザクションにならず、送った属性が捨てられる**（エラーにもならない） | **メッセージごとにトランザクションを作る**（Java ライブラリは STOMP に自動対応）、R15、F12 |
| JSON-RPC | HTTP として | 1つの URL にまとまり、エラーは 200 | `api.operation`、D22 |

**ステータスコードを使う検知（D04・D10）は REST 専用です。** REST 以外で反応しないことを「安全」と読まないでください。

## 含まれる Skill

| Skill | 役割 |
|---|---|
| `nr-appsec-guard` | 実行時: 前提の確認（段階とデータソース）、② 利用実態（U01〜U06）、③ 攻撃検知（D01〜D23。IDOR・SQLi・RCE の兆候・認証攻撃・AI エージェントらしい挙動）、④ 調査（I01〜I07）、計装の推奨（yml / XML / API）、アラート・Workflow Automation・Slack 通知の生成。Autopilot / iRCA の有無で動作を切り替え |
| `api-authz-review` | ① 棚卸し（コード）: エンドポイントとスコープの洗い出し、IDOR/BOLA・BFLA・Mass Assignment・SQLi・OS コマンドインジェクション・デシリアライズ・過剰露出の検出、New Relic の実トラフィックで補正したランキング |

## 計装（S2 への最短経路）

S2（IDOR 成功の証拠）に到達するためのコードを [`instrumentation/`](instrumentation/) に置いています。

| 言語 | 形 | 状態 |
|---|---|---|
| **Java**（Spring Boot / Spring Security） | 計装ライブラリ（アノテーション1つで使える。REST・GraphQL・WebSocket（STOMP）に対応） | ✅ Spring Boot 3.5・4.1 でテスト済み |
| Python・Node.js・Ruby・Go | 取り込める小さなファイル | ✅ 単体テスト済み（API は実パッケージで確認） |
| PHP | 同上 | ⚠️ API 名が未確認 |
| .NET | 同上 | ❌ 未コンパイル |

全言語で、仮名化したユーザー ID が同じ値になります（サービスごとに言語が違っても同じユーザーを追える）。
コードを変更できない Java アプリ向けには、認可チェックのメソッドを探して XML 計装の候補を作るスクリプト（`scripts/gen_xml_candidates.py`）もあります。

### Java

```java
@CheckOwnership(type = "order")          // データ取得メソッドに付けるだけ
public Order find(Long id) { ... }
```

- 既定は **S2 の最小セット**（`authz.decision`・`resource.owner_match`・仮名化した `enduser.id`）。設定で S3 の全属性
- **OBSERVE モード**（記録だけ）で本当に起きている IDOR を見つけてから、ENFORCE モード（拒否）に切り替えられる
- 必要スコープは `@PreAuthorize` / `@Secured` から自動で取得。エンドポイントごとの記述は不要
- GraphQL のリゾルバ（Spring for GraphQL）ではサーバー側のフィールド名を、WebSocket（STOMP）ではメッセージごとにトランザクションを作って記録
- Spring Boot 3.5（Spring Security 6.5）と 4.1（Spring Security 7.1）でテスト済み。Maven Central には未公開

使い方は [`instrumentation-java.md`](skills/nr-appsec-guard/references/instrumentation-java.md)、他の言語は [`instrumentation-other-languages.md`](skills/nr-appsec-guard/references/instrumentation-other-languages.md)。

## アラートと通知

```bash
python3 scripts/gen_alerts.py --stage S2 --sources spans,browser_dt --out out/terraform
```

- **今の段階とデータソースで動くアラートだけを Terraform として生成**します（定義は [`shared/alerts.json`](shared/alerts.json)）。生成しなかったものは `SKIPPED.md` に「何があれば追加できるか」付きで出ます。
- **証拠の強さで振り分けます**（偽陽性への対策）:

  | 証拠の強さ | 例 | 通知 |
  |---|---|---|
  | **証拠** | D01（他人のデータを返した）、D07（注入された形の SQL が実行された） | **CRITICAL**。Workflow Automation で情報を集め、Autopilot（有効な場合。iRCA の結果も使う）に調査させてから通知 |
  | 強い兆候 | D02、D06、D21、D23 | HIGH（静かなチャンネル）。導入直後（`learning_mode = true`）は通知しない |
  | 異常 | D03、D04、D10、D12 など | **既定では生成しない**。`--include-anomaly` で、通知しない別のポリシーに入れて日次で確認 |

- 既定で生成されるアラートは S3 でも6本。異常は単独で攻撃と判断しない（偽陽性が多いため）
- ランブックは New Relic Knowledge に登録して Autopilot が参照できる形です（[`templates/knowledge-runbooks/`](templates/knowledge-runbooks/)）。
- 適用は利用者が行います（生成のみ）。

| テンプレート | 状態 |
|---|---|
| Terraform（アラート条件・ポリシー・Workflow・Slack） | 構文チェック（`terraform fmt`）のみ。provider を使った `terraform validate` は未実施 |
| Workflow Automation（`templates/workflow-automation/security-triage.yaml`） | **下書き・未検証**。一部のアクション名・入出力の書き方は公式テンプレートと照合が必要 |
| Slack 通知の形式・Autopilot のプロンプト・ランブック | 完成 |

## ログ（ラストワンマイル）

**ログはスキャンしません。** APM で見つけた手がかり（トレース ID・ユーザー・時間帯）を起点に、ピンポイントで取りに行きます。ログ全体を攻撃の文字列で検索するやり方（SIEM 型）は、偽陽性とコストが増えるだけなので採りません。

| ID | 内容 | 起点 |
|---|---|---|
| L01 | **IDOR の証拠のログ行**（誰の、どのレコードか） | D01 のトレース ID |
| L02 | 調査対象のアクセスの全件（APM に入らないクエリ文字列、サンプリングで漏れた分） | ④ 調査の対象と期間 |
| L03 | エッジ（WAF・CDN）で遮断されたリクエスト | 兆候の時間帯 |
| L04 | アプリが出した認可判断のログ行（High-security mode で属性が送れない場合の代わり） | アプリ名と期間 |

- CRITICAL（証拠）のときは、Workflow Automation が L01 のログ行を取りに行きます（`logsEnabled`）
- Java ライブラリの `log-decisions: true` で、拒否と「所有者が違うのに通した」ときだけ、決まった形の1行を出します（ユーザー ID は入れない）
- 前提の確認 R16 で、Logs in context が効いているか（ログにトレース ID が付いているか）を確認します

## コストとトークン

- **定期の Hunt は `scripts/hunt.py`（NerdGraph で NRQL を直接実行。AI を使わない）**。毎日は軽量（`--levels evidence,strong`。最大7クエリ）、週1回は全部（最大21クエリ）
- Ground Truth MCP は対話での調査に使い、**NRQL を実行するツールだけ**に絞る。Autopilot は CRITICAL（証拠）のアラートからだけ
- Claude のトークン: SKILL.md を短くし（24.5KB → 9.4KB）、`catalog.py`（必要な節だけを読む）・`hunt.py` の要約・`inventory_java.py`（読むメソッドを絞る）・差分モード・作業ファイルの再利用で、読む量を減らしています
- 詳細と、New Relic に確認すべき料金の項目は [`shared/cost.md`](shared/cost.md)

```bash
NEW_RELIC_API_KEY=... python3 scripts/hunt.py --app shop-api --account-id 1234567 --stage S2 --sources spans --levels evidence,strong
python3 scripts/inventory_java.py src/main/java --changed-since origin/main     # PR の変更分だけ
python3 scripts/catalog.py index --stage S2                                       # 実行できる検知の一覧
```

## 対応範囲（何をカバーし、何をカバーしないか）

**このプラグインは、アプリケーション層の「認可・認証・インジェクション」と「それに気づくための監視」に絞っています。**
すべての項目に対応しているわけではありません。対象外の領域は、それぞれ専用のツールや対策と組み合わせてください。

凡例: ◎ 中心的に対応 / ○ 主要部分に対応 / △ 一部のみ / × 対象外

### OWASP Top 10:2025

| 項目 | 対応 | このプラグインでやること | やらないこと |
|---|---|---|---|
| A01 Broken Access Control | ◎ | IDOR / BOLA・スコープ不備・BFLA のコード監査（F2–F5）と実行時検知（D01–D05、方式に依存しない D22・D23） | — |
| A02 Security Misconfiguration | △ | `permitAll` 等のセキュリティ設定の漏れ（F1）、監視設定（High-security mode・`record_sql`）の確認 | サーバー・ミドルウェア・クラウドの設定監査 |
| A03 Software Supply Chain Failures | × | New Relic Vulnerability Management の結果を参照するよう案内するのみ | SBOM・依存関係の脆弱性スキャン |
| A04 Cryptographic Failures | × | — | 暗号方式・鍵管理・TLS 設定の監査 |
| A05 Injection | ○ | **SQL インジェクション**（F7、D06–D09）と **OS コマンドインジェクション・RCE の兆候**（F9、D20、D21） | XSS・LDAP・テンプレート等の他のインジェクション（IAST の結果を参照） |
| A06 Insecure Design | △ | Mass Assignment（F6）、上限のない一覧取得（F8）、GraphQL の防御不足（F11）、脅威モデル | 設計レビュー全般 |
| A07 Authentication Failures | ○ | 認証なしの API（F1）、認証失敗の急増（D10）、長寿命トークン（D15）、API キーの異常利用（D14）、WebSocket の接続中の権限確認（F12） | パスワードポリシー・MFA・セッション管理の監査 |
| A08 Software or Data Integrity Failures | △ | **安全でないデシリアライズのみ**（F10、D21） | CI/CD・署名・更新の完全性の検証 |
| A09 Security Logging and Alerting Failures | ◎ | 前提の確認（R01–R15。サンプリング・保存期間・WebSocket の計装漏れを含む）、調査の手順（I01–I07）、検知に必要な属性の計装推奨、アラートと Slack 通知の生成 | ログの長期保管・改ざん防止 |
| A10 Mishandling of Exceptional Conditions | △ | 新しい種類の例外の出現（D17。Errors Inbox の元データ `TransactionError` を使用） | 例外処理のコード監査全般 |

### OWASP API Security Top 10:2023

| 項目 | 対応 | 内容 |
|---|---|---|
| API1 Broken Object Level Authorization | ◎ | F4、D01–D03、D22、D23 |
| API2 Broken Authentication | ○ | F1、D10、D14、D15 |
| API3 Broken Object Property Level Authorization | ○ | F6（Mass Assignment）、F8（過剰なデータ露出） |
| API4 Unrestricted Resource Consumption | △ | 上限のない `size`（F8）、GraphQL の深さ・エイリアスの上限なし（F11）、自動化された大量アクセス（D11、D13、D23） |
| API5 Broken Function Level Authorization | ◎ | F5、D05 |
| API6 Unrestricted Access to Sensitive Business Flows | △ | 業務トランザクションの異常頻度（検知の考え方のみ） |
| API7 Server Side Request Forgery | × | — |
| API8 Security Misconfiguration | △ | A02 と同じ。GraphQL の introspection（F11）、WebSocket の Origin 確認（F12） |
| API9 Improper Inventory Management | ○ | シャドー API / ゾンビ API の突き合わせ（U01・U02 + コード監査） |
| API10 Unsafe Consumption of APIs | × | — |

### CIS

| 対象 | 対応 | 理由 |
|---|---|---|
| **CIS Benchmarks** | **×（対象外）** | OS・クラウド・Kubernetes・DB などの製品ごとの設定堅牢化ガイドで、本プラグインが扱うアプリ層の認可・検知とは対象が異なるため。CIS-CAT や各クラウドの設定監査ツールを使ってください |
| **CIS Controls v8** | △（参考として一部） | 下表の Safeguard に関連する作業を支援する。**準拠や認証の根拠にはなりません** |

| CIS Controls v8 の Safeguard | 本プラグインとの関係 |
|---|---|
| 3.14 Log Sensitive Data Access | 機微データへのアクセスを認可属性として記録する（`shared/attribute-spec.md`） |
| 6.8 Define and Maintain Role-Based Access Control | エンドポイントとスコープ・ロールの一覧表（コード監査の出力） |
| 8.5 Collect Detailed Audit Logs / 8.11 Conduct Audit Log Reviews | 認可判断の記録と、Hunt モードによる定期的な確認 |
| 13.1 Centralize Security Event Alerting | アラート・Workflow・Slack 通知の生成 |
| 16.12 Implement Code-Level Security Checks | ソースコードの認可監査（`api-authz-review`） |
| 16.14 Conduct Threat Modeling | 脅威モデル（`shared/threat-model-2026-jp.md`） |
| 17.4 Establish and Maintain an Incident Response Process | Knowledge 用ランブック、Autopilot / iRCA 連携（Phase 4） |

> Safeguard の番号は CIS Controls v8 / v8.1 に基づく。採用しているバージョンの原文で確認すること。

### その他の規格との対応

すべての Finding と検知に、以下の規格の番号を付けています。対応表の実体は [`shared/standards.json`](shared/standards.json) の1か所だけにあり、
ランキングの出力（`--format md` の Standards 列）やレポートにも同じ番号が表示されます。

| 規格 | 使い方 | 対応 |
|---|---|---|
| **OWASP ASVS 5.0** | 検証できる要件の一覧。**V8 Authorization** と **V16 Security Logging and Error Handling** が中心 | ○ 章レベル（個別要件の番号は原文で確認） |
| **CWE** | 脆弱性の分類番号。SAST や脆弱性管理ツールと結果を突き合わせられる | ◎ 全 Finding |
| **OWASP Automated Threats（OAT）** | 自動化された攻撃の振る舞いの分類。AI エージェントによる攻撃の検知（D02〜D13）に付与 | ○ 該当する検知のみ |
| **IPA「安全なウェブサイトの作り方」** | 日本で最も参照される Web アプリの指針。1.1 SQL インジェクション、1.4 セッション管理、1.11 アクセス制御や認可制御の欠落 | △ 該当する節のみ |
| **MITRE ATT&CK v20.0（Enterprise）** | 攻撃者の行動の分類。SOC・脅威インテリジェンスと共通の言葉で話せる。16 の技術に対応（下記） | ○ 全 Finding・検知（D18 を除く） |

コード監査の Finding との対応:

| Finding | CWE | ASVS 5.0 | OWASP | IPA | ATT&CK |
|---|---|---|---|---|---|
| F1 認証なしで公開されている API | CWE-306 | V6, V8 | A07, A01, API2 | 1.11 | T1190 |
| F2 スコープ・権限チェックが無い | CWE-862 | V8, V10 | A01, API5 | 1.11 | T1190 |
| F3 スコープ・権限が不適切 | CWE-863 | V8, V10 | A01, API5 | 1.11 | T1190 |
| F4 IDOR / BOLA（所有者照合が無い） | CWE-639 | V8 | A01, API1 | 1.11 | T1190 |
| F5 機能レベルの認可不備（BFLA） | CWE-285 | V8 | A01, API5 | 1.11 | T1190, T1098 |
| F6 Mass Assignment | CWE-915 | V15 | A06, API3 | — | T1190, T1098 |
| F7 SQL インジェクション | CWE-89 | V1 | A05 | 1.1 | T1190 |
| F8 過剰なデータ露出・上限のない取得 | CWE-213, CWE-770 | V14, V2 | A06, API3, API4 | — | T1190 |
| F9 OS コマンドインジェクション | CWE-78 | V1 | A05 | 1.2 | T1190, T1059 |
| F10 安全でないデシリアライズ | CWE-502 | V1 | A08 | — | T1190, T1059 |
| F11 GraphQL の防御不足（introspection・深さ・エイリアス） | CWE-770, CWE-200 | V4 | A06, API4, API8 | — | T1499.003 |
| F12 WebSocket の防御不足（Origin 確認・接続中の権限確認） | CWE-1385, CWE-613 | V4 | A01, A07, API2, API8 | — | T1185, T1550.004 |

検知（D01〜D23）の対応は `shared/standards.json` を参照してください。
OAT と AI エージェントの結び付けは本プラグインの分析であり、OWASP の公式な位置付けではありません。

#### MITRE ATT&CK

- **対応表は本プラグインの解釈です**（MITRE の公式な対応ではない）。技術の ID は MITRE の公式データ（attack-stix-data v20.0）で、存在すること・廃止されていないことを確認済み
- ATT&CK は攻撃者の行動の分類で、アプリの脆弱性の種類までは区別しない。**IDOR・SQLi・認可不備はすべて T1190（Exploit Public-Facing Application）** になる。脆弱性の種類は CWE・OWASP の番号で区別する
- 主な対応: 列挙・大量取得（D03・D12・D13・D23・D24）→ T1119 Automated Collection、スキャン（D04・D06）→ T1595 Active Scanning、クレデンシャルスタッフィング（D10・D11）→ T1110.004、盗まれたトークンの利用（D14・D15）→ T1550.001、RCE の兆候（D20・D21）→ T1059・T1105・T1071.001
- 自社の段階とデータソースで **何に気づけるか** を ATT&CK Navigator で見られる:

```bash
python3 scripts/attack_layer.py --stage S2 --sources spans --findings --out .authz-radar/attack-layer.json
# → https://mitre-attack.github.io/attack-navigator/ の "Open Existing Layer" で読み込む
```

色は 3 = 証拠、2 = 強い兆候、1 = 異常またはコード監査の Finding。**色が付いていない技術は検知できないという意味ではなく、本プラグインの対象外**です（初期アクセス以外の多くは EDR・SIEM の領域）。

### 対象外とした規格

| 規格 | 理由 |
|---|---|
| OWASP Top 10 for LLM Applications / Agentic Applications | **自社の AI アプリを守るための規格**で、「AI を使って攻撃してくる相手に気づく」という本プラグインの目的とは向きが逆のため |
| NIST CSF 2.0、ISO/IEC 27001 | 組織の管理体制の枠組みで、アプリ層の検知とは粒度が異なるため |
| PCI DSS v4.0.1 | カード情報を扱う場合のみ関係する（要件6.4 公開 Web アプリの保護、要件10 ログ）。必要に応じて上の CWE・ASVS の対応から辿ってください |

背景として参照している資料: [IPA 情報セキュリティ10大脅威 2026](https://www.ipa.go.jp/security/10threats/10threats2026.html)（組織編で「AI の利用をめぐるサイバーリスク」が初選出で3位、「システムの脆弱性を悪用した攻撃」が4位）

## 優先順位の考え方

```
優先度 = 本来の危険度（コードから判定。主軸）+ 攻撃兆候（あれば P0）+ トラフィック（同じ段階内の並び順のみ）
```

使われていない API でも、論理的に重大なら上位に来ます（攻撃者にとってはむしろ狙い目のため）。
計算は `scripts/risk_score.py` が決定的に行うので、同じ入力なら毎回同じ順位になります。詳細は [`shared/risk-scoring.md`](shared/risk-scoring.md)。

```bash
python3 scripts/risk_score.py examples/findings.sample.json \
  --overrides examples/criticality.sample.json --format md
```

## インストール

詳しい手順（クラウドのセッションでの使い方を含む）は [docs/getting-started.md](docs/getting-started.md)。

```
/plugin marketplace add photographed/nr-authz-radar
/plugin install nr-authz-radar
```

### New Relic MCP（Ground Truth）の接続

プラグインの `.mcp.json` には US リージョン（`newrelic-us` → `https://mcp.newrelic.com/mcp/`）を登録しています。
認証は OAuth が標準です（初回接続時にブラウザで認可）。

JP リージョンのアカウントを使う場合は、公式ドキュメントで JP のエンドポイント URL を確認し、`newrelic-jp` という名前で追加してください。

```bash
claude mcp add --transport http newrelic-jp <JP リージョンの MCP エンドポイント URL>
```

> 未設定の環境変数を URL に使うと設定全体が無効になるため、JP は既定では登録していません。

## 方針

- **生成のみ**: New Relic のアラート・Workflow、アプリの `newrelic.yml`・XML・コードは、すべてファイルや差分として出力します。適用は人が行います。
- **断定しない**: 「AI エージェントによる攻撃」は兆候として扱います。コードだけで判定できないものは `needs_review` にします。
- **データは最小限に**: IP アドレスは既定で New Relic に送りません（GDPR では個人データ、日本法でも個人関連情報に当たり得るため）。IP 粒度の分析は WAF / CDN に任せ、判定結果だけを受け取る設計です。詳細は [`shared/privacy.md`](shared/privacy.md)。

## ロードマップ

- [x] **v0.1.0** Phase 1: 共通仕様（属性、OWASP 対応、脅威モデル、ランキング）、Skill の骨組み、ランキングスクリプト
- [x] **v0.2.0** Phase 2: Readiness 監査（R01〜R11）と Hunt の NRQL カタログ（D01〜D18）。一部クエリは実アカウントで要検証
- [x] **v0.3.0** 必要なデータソースの整理（R12、D19）、IAST との役割分担、RCE の一部（F9、F10、D20、D21）
- [x] **v0.4.0** 4つの目的（棚卸し / 利用実態 / 攻撃検知 / 調査）と段階（S0〜S3）で再構成。利用実態 U01〜U05（D16・D19 を移動）、調査 I01〜I07、前提の確認 R13・R14。レポートを「今わかること」と「推奨」に分離
- [x] **v0.5.0** Java（Spring Boot / Spring Security）の計装ライブラリ。S2 の最小セットが既定、OBSERVE / ENFORCE モード、設定例（`newrelic.yml`・XML）
- [x] **v0.6.0** Phase 4: アラート条件の生成（段階とデータソースに合わせる）・Alert Workflow・Slack・Workflow Automation の下書き（Autopilot / iRCA 分岐）・Autopilot のプロンプト・Knowledge 用ランブック
- [x] **v0.7.0** Spring Boot 4.1 でのテスト、XML 候補の自動生成、Python・Node.js・Ruby・Go・PHP・.NET の S2 計装
- [x] **v0.8.0** REST 以外の方式（GraphQL・SOAP・gRPC・WebSocket・JSON-RPC）への対応: `api.protocol`・`api.operation`、方式に依存しない検知 D22・D23、R15、U06、F11・F12、Java ライブラリの GraphQL・STOMP 対応
- [x] **v0.9.0** 英語対応（README・はじめに・サンプル・スクリプトの `--lang en`・Skill の出力言語）、はじめにのドキュメント、サンプルの実行結果
- [x] **v0.10.0** 証拠の強さ（証拠 / 強い兆候 / 異常）による報告とアラートの振り分け、`hunt.py`（NerdGraph）、トークン削減（短い SKILL.md・`catalog.py`・`inventory_java.py`・差分モード）、コストの整理
- [x] **v0.11.0** 連携状況の表記を実態に合わせて修正、Browser の突き合わせ（D24・U07）、Errors Inbox・Performance Risks Inbox の連携の設計、ログのラストワンマイル（L01〜L04・R16・Workflow・Java の認可判断のログ行）
- [ ] Phase 5: 攻撃シナリオでの検証（**v1.0.0 はリリースの判断をした時点で付ける**）

## 参考

- [JPCERT/CC 注意喚起 JPCERT-AT-2026-0030 の報道](https://scan.netsecurity.ne.jp/article/2026/10/13/56428.html)
- [New Relic Ground Truth (MCP)](https://docs.newrelic.com/docs/agentic-ai/mcp/overview/)
- [New Relic Autopilot](https://docs.newrelic.com/docs/agentic-ai/autopilot/overview/)
- [Performance Risks Inbox](https://docs.newrelic.com/whats-new/2026/05/whats-new-05-14-performance-risks-inbox/)
- [OWASP API Security Top 10 2023](https://owasp.org/API-Security/editions/2023/en/0x11-t10/)

## License

MIT
