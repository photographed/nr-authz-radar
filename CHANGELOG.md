# Changelog

形式は [Keep a Changelog](https://keepachangelog.com/ja/1.1.0/)、バージョンは [SemVer](https://semver.org/lang/ja/) に従う。
バージョンは `.claude-plugin/plugin.json` の1か所で管理する。属性仕様（`shared/attribute-spec.md`）だけは別にスキーマバージョンを持つ。

1.0.0 未満は、仕様が互換性なく変わる可能性がある。マイナーバージョン（0.x）は機能の追加ごとに上げる。**1.0.0 はリリースの判断をした時点で付ける**（実データでの検証 = Phase 5 が前提）。

## [Unreleased]

## [0.17.3] - 2026-10-28

### Added
- **`docs/status.md`**: 「今できること（検証済み）／ 実環境で未検証 ／ 未実装 ／ 今後」を1枚に整理。README からもリンク。「今何ができるのか分かりにくい」への対応

### Fixed
- **ドキュメントの実機能との乖離を修正**（PHP・Next.js をフル対応する前の記述が残っていた）:
  - getting-started（日英）の計装の説明を更新: PHP は Composer ライブラリ、Next.js はヘルパー、.NET は未コンパイル、と現状に合わせた
  - 古い範囲表記を修正: 前提の確認 `R01〜R15`→`R01〜R17`、検知 `D01〜D23`→`D01〜D25`


## [0.17.2] - 2026-10-28

### Changed
- **README を大幅に短く・人が読みやすく再構成**（405行→約60行）。「何ができるか」と「使い方」に絞り、詳細は docs に分離。フィードバック「README が長すぎて分かりにくい」への対応
- 新しいドキュメント: `docs/concepts.md`（4つの目的・段階・いつ使うか・優先順位・方針）、`docs/reference.md`（必要データ・連携状況・API 方式・計装・アラート・ログ・コスト・MCP 接続）、`docs/coverage.md`（OWASP・API Top 10・CIS・CWE・ASVS・OAT・IPA・ATT&CK・対象外）
- ロードマップは CHANGELOG に一本化（README からは変更履歴へのリンクのみ）
- README.en.md も同様に短縮


## [0.17.1] - 2026-10-28

### Changed
- **Logs の位置づけを明確化**（顧客フィードバック: ドキュメントから「ログで攻撃を探す」と誤読された）。データソース表の Logs を「推奨」→「任意」にし、**攻撃探索のログ全文スキャンはしない／Logs は調査の最後の詰め（L01〜L04）だけ／無くても中心機能は動く**ことを README・`shared/data-sources.md`・`shared/goals.md` に明記。`goals.md` に「対象外（意図的にやらないこと）」節を追加


## [0.17.0] - 2026-10-28

### Added
- **`scripts/find_appname.py`**: リポジトリ↔New Relic appName の突合（IDE 向け）。各エージェントの設定（Java/Ruby `newrelic.yml`、Python/PHP `newrelic.ini`、Node `newrelic.js`、.NET `newrelic.config`、Go の `ConfigAppName`）と、Dockerfile・compose・.env の `NEW_RELIC_APP_NAME` から候補を抽出し、**確度付き**（high=設定に literal／medium=環境変数の literal 既定／low=環境変数参照のみ＝値は repo 外）で出す。prod/staging や複数サービスは分けて提示し、混ぜない。`;` 区切りの複数 appName は分割。vendor/node_modules は除外。単体テスト8件
- `api-authz-review` の Step 0 に「New Relic を使うならまず `find_appname.py` で appName を特定」を追加

### Note
- appName が環境変数でデプロイ時に外出しされている場合は repo から値が取れない。その場合は R17（`FACET appName`）で実データ側から一覧するか、ユーザーに確認する


## [0.16.0] - 2026-10-28

### Added
- **D25 WAF / CDN がブロックした攻撃**（`edge.verdict`・AWS WAF メトリクス）。「WAF が N 件ブロック、うちアプリに到達して成功したものは D01 等で M 件」とセットで報告する運用に。hunt-only（防御の記録であって侵害ではない）。遮断された URL の詳細は既存の L03（ログ）で、hunt はログを読まない原則を維持
- **R17 対象アプリ（entity）の一覧**。複数アプリ環境で「どのアプリを見たか」を冒頭に明記し、混ぜて報告しないためのチェックを前提確認の最初に追加
- **`scripts/ip_reputation.py`**: 送信元 IP を AbuseIPDB 等と**手元で**照合する任意ツール。**IP は New Relic に送らず**、利用者の API キーで動く。IPv4/IPv6 を任意テキストから抽出・検証し、private/reserved は照合しない。単体テスト7件

### Note
- 顧客フィードバック由来（複数アプリ・WAF への言及・不審 IP 照合）。「WAF をすり抜けたクエリ文字列の SQLi をログから拾う」案は、偽陽性ゼロの設計思想と衝突するため今回は見送り（成功検知は D01/D07、ログ全文スキャンはしない方針を維持）


## [0.15.0] - 2026-10-27

### Added
- **コード監査（棚卸し）を全言語に拡大**。`scripts/inventory_python.py`（Flask/FastAPI/DRF）、`inventory_node.py`（Express/Koa/Fastify ＋ Next.js のファイルベースルート）、`inventory_ruby.py`（Rails/Sinatra ＋ `routes.rb`）、`inventory_go.py`（net/http・chi・gin・echo）。いずれも認可（認証と区別）と本体の候補（IDOR・SQLi・コマンド実行・安全でないデシリアライズ・mass assignment）を出す。`api-authz-review` の Step 1c〜1f に追加。ソースのみのフィクスチャと計 19 件のテスト
- **攻撃検知の言語カバー**: D06（DB 構文エラー）と D21（RCE／デシリアライズ）に Node.js・Python・Ruby・Go・.NET のパターンを追加（SQL Server `Incorrect syntax near`、MySQL `Error 1064`、psycopg/pg の構文エラークラス、node-serialize、.NET `BinaryFormatter`、Python `pickle`/PyYAML、Ruby `Psych`）。偽陽性を抑えるためメッセージ中心、言語ごとの出方を注記

### Note
- 各 inventory は正規表現ベースで、拾えない形（NestJS・tRPC・Django `urls.py` の一部・gRPC 等）は各 Step に明記。候補であって断定ではない


## [0.14.0] - 2026-10-27

### Added
- **Next.js 対応**。`instrumentation/node/nextjs.js`: App Router の Route Handler・Pages API・Server Actions 向けの `withAuthzRadar`（`AsyncLocalStorage` でリクエストごとに独立した状態、`OwnershipError`→`Response` 変換）・`setUser`・`ownership`・`protocol`・`deny`。既存の Node コアの上に薄く実装。単体テスト13件
- `instrumentation/node/package.json`（`@nr-authz-radar/node`、`.` と `./nextjs` の exports、`newrelic` は optional peer）
- 脆弱なデモ `examples/nextjs-vuln-site`（App Router・Next.js 15）。IDOR（計装あり／なし）、observe/enforce 切替、**127.0.0.1 限定・デプロイ禁止**。Next.js 15.5 で observe の D01 ログと enforce の 404 を実機確認
- 計装リファレンス `instrumentation-nextjs.md`。**`middleware.ts` は Edge ランタイムで Node エージェントが効かない**こと、属性はトランザクションのある場所（Route Handler 等）でだけ付くことを明記

### Note
- 実際に New Relic へ属性が届くことは未確認（Phase 5）。`@newrelic/next` と Next.js のバージョンの組み合わせに依存するため、導入時に R02 で確認する

## [0.13.0] - 2026-10-27

### Added
- **PHP をフル対応に**。計装ライブラリ `instrumentation/php/`（Composer パッケージ）: 素の PHP 向けの `Telemetry`・`Pseudonymizer`・`DecisionLog`・`NewRelicAgent`、Laravel 12 統合（サービスプロバイダ、`authz.owner` ミドルウェア、`ChecksOwnership` トレイト、設定ファイル）。関数名は New Relic PHP エージェント 12.12.0 のソースで確認（`newrelic_set_user_id` は 10.12+、無い環境は自動代替）。23 件の単体テストは PHP 8.3 で通過
- **PHP には expected error の仕組みが無い**ことを反映: 拒否は既定でエラーとして送らず、`authz.decision` 属性で検知（`instrumentation-php.md`）
- 手元で試せる脆弱なデモ `examples/php-vuln-site`（Laravel 12・PHP 8.5.11・Docker）。IDOR（計装あり／なし）・SQLi・BFLA を仕込み、observe/enforce を切替可能。**127.0.0.1 限定・デプロイ禁止**。PHP 8.5.11 と 8.3 で動作確認済み
- `scripts/inventory_php.py`: Laravel のルート・ミドルウェアとコントローラの怪しい箇所を棚卸し（`find_by_id`・`sql_concat` 等）。`api-authz-review` の Step 1b
- D06（DB 構文エラー）と D21（RCE の試み）に PHP / PDO のパターンを追加（SQLSTATE、`unserialize()`、`phar://` 等）

### Changed
- `instrumentation-other-languages.md` の PHP 行を「未確認」から「確認済み・デモで実動作確認」に更新。PHP は専用ページ `instrumentation-php.md` へ分離

## [0.12.0] - 2026-10-27

### Added
- **MITRE ATT&CK v20.0（Enterprise）との対応**: 全 Finding（F1〜F12）と検知（D18 以外）に技術 ID を付与（`shared/standards.json`）。16 技術の ID は MITRE の公式データ（attack-stix-data）で、存在すること・廃止されていないことを確認済み。対応は本プラグインの解釈
- `scripts/attack_layer.py`: 段階とデータソースで実行できる検知から ATT&CK Navigator のレイヤーを作る（3 = 証拠、2 = 強い兆候、1 = 異常・コード監査の Finding）
- ランキングの Standards 列と、生成するアラート条件の説明に ATT&CK の ID を表示
- テスト: ID の形式・辞書との一致・バージョン、レイヤーの形と段階による絞り込み

## [0.11.0] - 2026-10-23

### Added
- ログのラストワンマイル `references/logs.nrql.md`（L01 IDOR の証拠のログ行、L02 調査の全件化、L03 エッジでの遮断、L04 認可判断のログ行）。**ログはスキャンしない**: 全クエリが APM 由来のキーか明示的なフィルタ・時間の範囲・件数の上限で絞られていることと、`hunt.py` がログを読まないことをテストで確認
- 前提の確認 R16（Logs in context が効いているか、認可判断のログ行があるか）
- Workflow Automation に、CRITICAL のときだけ L01 のログ行を取りに行く手順（`logsEnabled`。未検証）
- Java ライブラリの `log-decisions`: 拒否と、所有者が違うのに通したときだけ、決まった形のログ行を1行出す（ユーザー ID は入れない）。High-security mode で属性が送れない場合の代わり。形式は `shared/attribute-spec.md`
- D24（ブラウザのセッションが無いユーザーの API 呼び出し）: `hunt.py` が APM と Browser の2つのクエリを実行して差を取る。U07（画面から来た拒否と直接来た拒否）
- `shared/inbox-integration.md`: Errors Inbox（エラーグループの状態の反映）と Performance Risks Inbox（リスクのセキュリティでの読み替え）の連携の設計。**データの取得は未実装**

### Changed
- **README・Skill の説明を実態に合わせて修正**: Errors Inbox は元データ（`TransactionError`）を使っているだけ、Performance Risks Inbox は未実装、Browser は一部であることを「連携状況」の表に明記

## [0.10.0] - 2026-10-23

### Added
- **証拠の強さ**（証拠 / 強い兆候 / 異常 / リスク / 参考）を全検知に付与。`shared/detections.json` に、名前（日英）・段階・必要なデータソースとあわせて1か所で管理。検知の見出しにも表示
- `scripts/hunt.py`: 検知のカタログを NerdGraph で直接実行し（AI を使わない）、証拠の強さごとの短い要約を出す。段階・データソースで実行できない検知は理由付きで飛ばす。個人やリソースを示す値は要約で伏せ字にする。`--levels evidence,strong` で軽量な日次実行
- `scripts/catalog.py`: 検知・利用実態・調査・前提の確認の一覧（1行1件）と、必要な ID の節だけを表示
- `scripts/inventory_java.py`: Java のエンドポイント（REST・GraphQL・STOMP・SOAP）と怪しい箇所の候補を一覧にする。`--changed-since` で PR の変更分だけ
- `shared/cost.md`: New Relic 側のコスト（クエリ数の実測、使い分け、確認すべき料金の項目）と、Claude 側のトークン削減の仕組み
- `--include-anomaly`（`gen_alerts.py`）、Terraform の `learning_mode` 変数

### Changed
- **アラートの振り分けを証拠の強さに基づいて変更**: CRITICAL（通知・Autopilot）は「証拠」だけ、「強い兆候」は HIGH、「異常」は既定で生成しない。既定のアラートは S3 でも6本（以前は12本）
- レポートは証拠の強さごとに分け、異常だけで攻撃と書かない（`shared/goals.md`）
- 両 Skill の SKILL.md を短い入口にした（24.5KB → 9.4KB）。詳細は `skills/api-authz-review/references/review-rules.md`・`skills/nr-appsec-guard/references/recommendations.md` へ移動
- D20 のクエリの `LIMIT MAX` を `LIMIT 200` に変更（カタログで最も重いクエリのため）


## [0.9.0] - 2026-10-23

### Added
- 英語対応: `README.en.md`、`docs/getting-started.en.md`、サンプルレポートの英語版。両 Skill に「ユーザーの言語で出力する」規則。`gen_alerts.py`・`gen_xml_candidates.py` に `--lang en`
- `docs/getting-started.md`: 全体像（フォルダの役割、何が自動で何を人がやるか）、インストール手順、頼み方の例、`instrumentation/` の組み込み方、FAQ
- サンプル: 意図的に脆弱にした `examples/sample-app/`（ビルドしない）と、それに対する実際のコード監査の結果（`docs/samples/`）。New Relic のレポートは架空のデータによる例であることを明記

## [0.8.0] - 2026-10-23

### Added
- `shared/protocols.md`: REST・GraphQL・SOAP・gRPC・WebSocket・JSON-RPC ごとの盲点と対策。Java エージェント 9.5.0 の計装を確認（GraphQL・Spring-WS・CXF・gRPC はあり、**WebSocket は無し**）。GraphQL のトランザクション名がクライアントの operation 名（偽装できる）から作られることを確認
- 属性（スキーマ 0.3）: `api.protocol`、`api.operation`（サーバー側で決まる名前）、`resource.check_count`
- 検知: D22（認可拒否の急増。方式に依存しない）、D23（1リクエストで大量の所有者照合。GraphQL のエイリアス等）。どちらもアラートに追加（12種類）
- 前提の確認 R15（API の方式。WebSocket のメッセージが計装されていない状態を検出）、利用実態 U06（方式・操作ごと）
- コード監査: GraphQL・SOAP・gRPC・WebSocket のエンドポイントの棚卸し、F11（GraphQL の防御不足）、F12（WebSocket の防御不足）
- Java ライブラリ: Spring for GraphQL のリゾルバ、Spring STOMP のメッセージ（メッセージごとにトランザクションを作る）に対応。HTTP リクエストの外での状態管理
- 各言語の WebSocket でトランザクションを作る API（パッケージで確認）

### Changed
- D04・D10 を「REST 専用」と明記（反応しないことを安全と読まない）
- 拒否の理由は最初に記録されたものを優先する（外側の処理が `owner_mismatch` を上書きしていた問題の修正）

### Docs
- README に「いつ使うか」（目的ごとの頻度）
- `docs/how-it-works.md`: IDOR などの判定の仕組み（4つの層と、それぞれで言えること）、限界

## [0.7.0] - 2026-10-23

### Added
- Java ライブラリを **Spring Boot 4.1.2 / Spring Security 7.1.2 でもテスト**（`-PspringBootVersion=4.1.2`）。テスト用の依存をバージョンで切り替え、MockMvc はバージョンに依存しない方法で組み立てる
- `scripts/gen_xml_candidates.py`: Java のソースから認可チェックのメソッド（`PermissionEvaluator`、`@PreAuthorize` から呼ばれる Bean、認可らしい名前）を探し、XML 計装の候補とレポートを出す。引数は記録しない
- Python・Node.js・Ruby・Go・PHP・.NET の S2 計装 `instrumentation/<言語>/` と `references/instrumentation-other-languages.md`
  - API 名は各言語のエージェントのパッケージで確認（PHP を除く）。Go は本物の `*newrelic.Transaction` との互換をコンパイル時に確認
  - Python・Node.js・Ruby・Go・PHP は単体テスト済み。.NET は未コンパイル
- テスト `tests/test_languages.py`: 各言語のテストの実行、**全言語（Java を含む）で仮名化したユーザー ID が一致すること**、属性名が仕様どおりであること

## [0.6.0] - 2026-10-23

### Added
- アラートのカタログ `shared/alerts.json`（10種類）と、アラートにしない検知の理由（9種類）。検知の全件がどちらかに入っていることをテストで確認
- `scripts/gen_alerts.py`: **現在の段階とデータソースで動くアラートだけ**を Terraform として生成し、生成しなかったものを `SKIPPED.md`（何があれば追加できるか）に出す
- Terraform のテンプレート: ポリシー、Slack の通知チャンネル（CRITICAL / HIGH を分離）、Alert Workflow
- Workflow Automation の下書き `templates/workflow-automation/security-triage.yaml`（Autopilot / iRCA のオン・オフを入力値で切り替える。**未検証**）
- Autopilot のプロンプト `templates/autopilot/security-prompt.md`、Slack 通知の形式 `templates/slack/security-alert.md`
- New Relic Knowledge 用のランブック6本 `templates/knowledge-runbooks/`（IDOR、偵察、SQLi、認証攻撃、自動化、RCE）

### Known limitations
- Terraform は `terraform fmt` による構文チェックのみ。provider を取得できない環境のため `terraform validate` は未実施
- Workflow Automation のアクション名・入出力・式の書き方の一部は公式テンプレートと未照合

## [0.5.0] - 2026-10-23

### Added
- Java（Spring Boot / Spring Security）の計装ライブラリ `instrumentation/java/`（`io.github.photographed.authzradar`）
  - `@CheckOwnership` と `Owned` で所有者照合を記録（OBSERVE / ENFORCE モード、管理者等の正当なアクセスの除外）
  - 既定は S2 の最小セット（`authz.decision`・`resource.owner_match`・HMAC で仮名化した `enduser.id`）。`attributes: FULL` で S3
  - 必要スコープを `@PreAuthorize` / `@Secured` から自動取得、Spring Security の拒否イベントを記録、拒否を expected error として送信
  - HMAC の鍵が無いときは `enduser.id` を送らない
  - 単体テストと MockMvc による結合テスト（Spring Boot 3.5.16 / Spring Security 6.5）。Spring Boot 4.1.2 はコンパイルのみ確認
- `references/instrumentation-java.md`: 推奨の順番、OBSERVE から ENFORCE への切り替え、確認用 NRQL、コード変更なしでできることと限界
- 設定例: `newrelic.yml`（分散トレーシング、`record_sql: obfuscated`、認証ヘッダー等の除外）、XML（認可チェックのメソッドを Span に出す）
- テスト: Java の属性名の定数が `shared/attribute-spec.md` と一致しているかを確認

## [0.4.0] - 2026-10-23

### Added
- `shared/goals.md`: 4つの目的（① 棚卸し / ② 利用実態 / ③ 攻撃検知 / ④ 調査）と、アプリ側の計装の段階（S0〜S3）。どうしても必要なコード計装は S2 の2属性（`resource.owner_match`・`authz.decision`）だけであることを明記
- ② 利用実態のクエリ `references/usage.nrql.md`（U01〜U05）
- ④ 調査のクエリと手順 `references/investigation.nrql.md`（I01〜I07）。サンプリング・保存期間の確認、APM は手がかり / ログで確定、保全
- 前提の確認 R13（サンプリング）・R14（保存期間）
- すべての検知と利用実態のクエリに、必要な段階（S0〜S3）を表示

### Changed
- **レポートを「今のデータでわかること・できること」と「推奨（段階的に）」の2節に分離**（両 Skill・前提の確認）
- **ID の変更**: D16 → U01、D19 → U02（攻撃検知ではなく利用実態のため）。`standards.json` では `usage` に移動
- 「計装の3段階（yml / XML / API）」を「計装の手段」に改名（段階 S0〜S3 と区別するため）
- README を4つの目的と段階を軸に再構成。データソースの表の「必須」から認可属性を外し、「推奨（S2）」にした

## [0.3.0] - 2026-10-23

### Added
- RCE の一部に対応: コード監査 F9（OS コマンドインジェクション）・F10（安全でないデシリアライズ）、検知 D20（見たことのない外部への通信）・D21（RCE の試みで出る例外）。F9 / F10 の影響度の下限は5
- `shared/data-sources.md`: 必要なデータソース（必須 / 推奨 / 任意）、トランザクション名の品質基準、コード・サーバー・画面の3視点での API 突き合わせ
- README に「前提: New Relic に必要なデータ」を追加。IAST（Limited Preview・申請制）を任意のデータソースとして記載
- Readiness 監査 R12（トランザクション名の品質）
- 検知 D19（画面から呼ばれている API の一覧。AjaxRequest）
- IAST（New Relic Security Agent for Java）との役割分担を `shared/data-sources.md` §4 に記載。コード監査に IAST での裏付けの手順（Step 3.5）を追加。`standards.json` に `iast` を追加

## [0.2.0] - 2026-10-23

### Added
- Readiness 監査 R01〜R11（R11 はすでに送られている個人データの検出）
- 検知 NRQL カタログ D01〜D18（IDOR / BOLA、ID 列挙、SQLi、認証攻撃、AI エージェントらしい挙動、インベントリ、変更相関）
- `shared/privacy.md`（GDPR・個人情報保護法の論点、IP の扱いのレベル L0〜L2）
- `shared/standards.json`（Finding と検知ごとの CWE・ASVS 5.0・OWASP・OAT・IPA）。ランキング出力に Standards 列を追加
- README に対応範囲（OWASP Top 10:2025、API Top 10:2023、CIS、ASVS、CWE、OAT、IPA）と対象外の規格を明記
- `CHANGELOG.md`

### Changed
- 属性仕様をスキーマ 0.2 に更新: `client.ip_hash` を廃止し、`client.asn`・`client.country`・`edge.verdict` と、オプトインの `client.ip_hmac` を追加。**IP アドレスは既定で送らない**
- 優先度: 攻撃のしやすさの下限を 1 にした（内部 API も攻撃されるため）

### Fixed
- `.mcp.json`: 未設定の環境変数を URL に使っていたため、JP サーバーの設定が無効になっていた。US のみ登録し、JP は README の手順で追加する方式に変更

## [0.1.0] - 2026-10-23

### Added
- 共通仕様（属性スキーマ 0.1、OWASP 対応表、日本の脅威モデル、優先度ランキング仕様）
- Skill の骨組み: `nr-appsec-guard`、`api-authz-review`
- `scripts/risk_score.py`（決定的な優先度ランキング）とテスト
