# Changelog

形式は [Keep a Changelog](https://keepachangelog.com/ja/1.1.0/)、バージョンは [SemVer](https://semver.org/lang/ja/) に従う。
バージョンは `.claude-plugin/plugin.json` の1か所で管理する。属性仕様（`shared/attribute-spec.md`）だけは別にスキーマバージョンを持つ。

1.0.0 未満は、仕様が互換性なく変わる可能性がある。マイナーバージョン（0.x）は機能の追加ごとに上げる。**1.0.0 はリリースの判断をした時点で付ける**（実データでの検証 = Phase 5 が前提）。

## [Unreleased]

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
