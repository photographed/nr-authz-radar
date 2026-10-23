# Changelog

形式は [Keep a Changelog](https://keepachangelog.com/ja/1.1.0/)、バージョンは [SemVer](https://semver.org/lang/ja/) に従う。
バージョンは `.claude-plugin/plugin.json` の1か所で管理する。属性仕様（`shared/attribute-spec.md`）だけは別にスキーマバージョンを持つ。

1.0.0 未満は、仕様が互換性なく変わる可能性がある。**1.0.0 は実データでの検証（Phase 5）が通った時点で付ける。**

## [Unreleased]

### Added
- `shared/data-sources.md`: 必要なデータソース（必須 / 推奨 / 任意）、トランザクション名の品質基準、コード・サーバー・画面の3視点での API 突き合わせ
- README に「前提: New Relic に必要なデータ」を追加。IAST（Limited Preview・申請制）を任意のデータソースとして記載
- Readiness 監査 R12（トランザクション名の品質）
- 検知 D19（画面から呼ばれている API の一覧。AjaxRequest）

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
