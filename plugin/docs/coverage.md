# 対応範囲（何をカバーし、何をカバーしないか）

**このプラグインは、アプリケーション層の「認可・認証・インジェクション」と「それに気づくための監視」に絞っています。**
すべての項目に対応しているわけではありません。対象外の領域は、それぞれ専用のツールや対策と組み合わせてください。

対応表の実体は [`shared/standards.json`](../shared/standards.json) の1か所にあり、ランキングの出力（`--format md` の Standards 列）やレポートにも同じ番号が表示されます。

凡例: ◎ 中心的に対応 / ○ 主要部分に対応 / △ 一部のみ / × 対象外

## OWASP Top 10:2025

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
| A09 Security Logging and Alerting Failures | ◎ | 前提の確認（R01–R17。サンプリング・保存期間・WebSocket の計装漏れを含む）、調査の手順（I01–I07）、検知に必要な属性の計装推奨、アラートと Slack 通知の生成 | ログの長期保管・改ざん防止 |
| A10 Mishandling of Exceptional Conditions | △ | 新しい種類の例外の出現（D17。Errors Inbox の元データ `TransactionError` を使用） | 例外処理のコード監査全般 |

## OWASP API Security Top 10:2023

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

## CIS

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
| 17.4 Establish and Maintain an Incident Response Process | Knowledge 用ランブック、Autopilot / iRCA 連携 |

> Safeguard の番号は CIS Controls v8 / v8.1 に基づく。採用しているバージョンの原文で確認すること。

## その他の規格（CWE・ASVS・OAT・IPA・ATT&CK）

すべての Finding と検知に、以下の規格の番号を付けています。

| 規格 | 使い方 | 対応 |
|---|---|---|
| **CWE** | 脆弱性の分類番号。SAST や脆弱性管理ツールと結果を突き合わせられる | ◎ 全 Finding |
| **OWASP ASVS 5.0** | 検証できる要件の一覧。**V8 Authorization** と **V16 Security Logging and Error Handling** が中心 | ○ 章レベル（個別要件の番号は原文で確認） |
| **OWASP Automated Threats（OAT）** | 自動化された攻撃の振る舞いの分類。AI エージェントによる攻撃の検知に付与 | ○ 該当する検知のみ |
| **IPA「安全なウェブサイトの作り方」** | 日本で最も参照される Web アプリの指針。1.1 SQL インジェクション、1.4 セッション管理、1.11 アクセス制御や認可制御の欠落 | △ 該当する節のみ |
| **MITRE ATT&CK v20.0（Enterprise）** | 攻撃者の行動の分類。SOC・脅威インテリジェンスと共通の言葉で話せる | ○ 全 Finding・検知（一部除く） |

### コード監査の Finding との対応

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
| F11 GraphQL の防御不足 | CWE-770, CWE-200 | V4 | A06, API4, API8 | — | T1499.003 |
| F12 WebSocket の防御不足 | CWE-1385, CWE-613 | V4 | A01, A07, API2, API8 | — | T1185, T1550.004 |

検知の対応は [`shared/standards.json`](../shared/standards.json) を参照してください。OAT と AI エージェントの結び付けは本プラグインの分析であり、OWASP の公式な位置付けではありません。

### MITRE ATT&CK の注意

- **対応表は本プラグインの解釈です**（MITRE の公式な対応ではない）。技術 ID は MITRE の公式データ（attack-stix-data v20.0）で存在・非廃止を確認済み。
- ATT&CK は攻撃者の行動の分類で、脆弱性の種類までは区別しない。**IDOR・SQLi・認可不備はすべて T1190（Exploit Public-Facing Application）** になる。種類は CWE・OWASP で区別する。
- 自社の段階とデータソースで「何に気づけるか」を ATT&CK Navigator で見られる:

```bash
python3 scripts/attack_layer.py --stage S2 --sources spans --findings --out .authz-radar/attack-layer.json
# → https://mitre-attack.github.io/attack-navigator/ の "Open Existing Layer" で読み込む
```

色は 3 = 証拠、2 = 強い兆候、1 = 異常またはコード監査の Finding。**色が付いていない技術は「検知できない」ではなく「対象外」**です（初期アクセス以外の多くは EDR・SIEM の領域）。

## 対象外とした規格

| 規格 | 理由 |
|---|---|
| OWASP Top 10 for LLM Applications / Agentic Applications | **自社の AI アプリを守るための規格**で、「AI を使って攻撃してくる相手に気づく」という本プラグインの目的とは向きが逆のため |
| NIST CSF 2.0、ISO/IEC 27001 | 組織の管理体制の枠組みで、アプリ層の検知とは粒度が異なるため |
| PCI DSS v4.0.1 | カード情報を扱う場合のみ関係する（要件6.4 公開 Web アプリの保護、要件10 ログ）。必要に応じて上の CWE・ASVS の対応から辿ってください |

背景資料: [IPA 情報セキュリティ10大脅威 2026](https://www.ipa.go.jp/security/10threats/10threats2026.html)（組織編で「AI の利用をめぐるサイバーリスク」が初選出で3位、「システムの脆弱性を悪用した攻撃」が4位）。
