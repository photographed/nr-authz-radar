# Changelog

形式は [Keep a Changelog](https://keepachangelog.com/ja/1.1.0/)、バージョンは [SemVer](https://semver.org/lang/ja/) に従う。
バージョンは `.claude-plugin/plugin.json` の1か所で管理する。属性仕様（`shared/attribute-spec.md`）だけは別にスキーマバージョンを持つ。

1.0.0 未満は、仕様が互換性なく変わる可能性がある。マイナーバージョン（0.x）は機能の追加ごとに上げる。**1.0.0 はリリースの判断をした時点で付ける**（実データでの検証 = Phase 5 が前提）。

## [Unreleased]

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
