# nr-authz-radar

**New Relic Ground Truth（MCP）で、IDOR / BOLA・SQLi・AI エージェントによる API 攻撃に気づき、優先順位を付ける Claude Code プラグイン。**

> Claude Code plugin that detects and ranks authorization attacks (IDOR/BOLA, scope abuse, SQLi, AI-agent-like scraping)
> using New Relic Ground Truth (MCP), and audits API authorization scopes in source code.
> Community project — not affiliated with or endorsed by New Relic.

## なぜ SIEM ではないのか

IDOR は攻撃が成功すると **200 OK** で返ります。ログを集めて相関しても「正常なアクセス」にしか見えません。
気づくには、アプリ自身が「誰が・どのスコープで・誰のデータに触れたか」を送る必要があります。
このプラグインは、その **計装の推奨** と、APM・Browser・Errors Inbox・Performance Risks Inbox を使った **検知**、
そしてソースコードの **認可監査** をセットで提供します。

## 前提: New Relic に必要なデータ

**見える範囲は「何のデータが入っているか」で決まります。** まず APM と分散トレーシングで API の実態をつかみ、そこから範囲を広げます。
Readiness 監査は、この表を上から順に確認して不足を指摘します。詳細は [`shared/data-sources.md`](shared/data-sources.md)。

| 段階 | データソース | 主なイベント | これでできること |
|---|---|---|---|
| **必須** | APM エージェント | `Transaction`、`TransactionError` | API ごとのアクセス・ステータス・例外。**トランザクション名 = API エンドポイント** |
| **必須** | 分散トレーシング | `Span` | API の中の SQL 文・外部呼び出し。画面から API までのつながり |
| **必須** | 認可属性（コード計装） | `Transaction` の custom attribute | **IDOR 成功を見る唯一の手段**（[`shared/attribute-spec.md`](shared/attribute-spec.md)） |
| 推奨 | Browser エージェント | `PageView`、`AjaxRequest` | 画面から実際に呼ばれている API の一覧。正規の画面を通った呼び出しかの判定 |
| 推奨 | Logs in context | `Log` | トランザクションと結び付いたアプリのログ |
| 推奨 | Change Tracking | デプロイ記録 | 「攻撃か、自分たちの変更か」の切り分け（iRCA の精度にも影響） |
| 任意 | ミドルウェア・WAF・ファイアウォール・OS のログ | `Log` | クエリ文字列を含むリクエスト内容、エッジでの判定、侵入後の操作 |
| 任意 | Infrastructure / Network Performance Monitoring | `SystemSample`、`ProcessSample` など | 侵入後の兆候（不審なプロセス・通信） |
| 任意 | Vulnerability Management | — | 使っているライブラリの既知の脆弱性 |
| 任意（申請制） | **IAST**（Limited Preview） | — | テスト環境でインジェクション系の脆弱性（RCE につながるものを含む）を検出し、コード監査の結果を裏付ける。**本番環境では使わない** |

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

## 含まれる Skill

| Skill | 役割 |
|---|---|
| `nr-appsec-guard` | 実行時: Readiness 監査、Hunt（NRQL による検知）、計装推奨（yml / XML / API）、アラート・Workflow Automation・Slack 通知の生成。Autopilot / iRCA の有無で動作を切り替え |
| `api-authz-review` | コード: エンドポイントとスコープの洗い出し、IDOR/BOLA・BFLA・Mass Assignment・SQLi・過剰露出の検出、New Relic の実トラフィックで補正したランキング |

## 対応範囲（何をカバーし、何をカバーしないか）

**このプラグインは、アプリケーション層の「認可・認証・インジェクション」と「それに気づくための監視」に絞っています。**
すべての項目に対応しているわけではありません。対象外の領域は、それぞれ専用のツールや対策と組み合わせてください。

凡例: ◎ 中心的に対応 / ○ 主要部分に対応 / △ 一部のみ / × 対象外

### OWASP Top 10:2025

| 項目 | 対応 | このプラグインでやること | やらないこと |
|---|---|---|---|
| A01 Broken Access Control | ◎ | IDOR / BOLA・スコープ不備・BFLA のコード監査（F2–F5）と実行時検知（D01–D05） | — |
| A02 Security Misconfiguration | △ | `permitAll` 等のセキュリティ設定の漏れ（F1）、監視設定（High-security mode・`record_sql`）の確認 | サーバー・ミドルウェア・クラウドの設定監査 |
| A03 Software Supply Chain Failures | × | New Relic Vulnerability Management の結果を参照するよう案内するのみ | SBOM・依存関係の脆弱性スキャン |
| A04 Cryptographic Failures | × | — | 暗号方式・鍵管理・TLS 設定の監査 |
| A05 Injection | ○ | **SQL インジェクションのみ**（F7、D06–D09） | XSS・OS コマンド・LDAP・テンプレート等の他のインジェクション |
| A06 Insecure Design | △ | Mass Assignment（F6）、上限のない一覧取得（F8）、脅威モデル | 設計レビュー全般 |
| A07 Authentication Failures | ○ | 認証なしの API（F1）、認証失敗の急増（D10）、長寿命トークン（D15）、API キーの異常利用（D14） | パスワードポリシー・MFA・セッション管理の監査 |
| A08 Software or Data Integrity Failures | × | — | CI/CD・署名・デシリアライズの検証 |
| A09 Security Logging and Alerting Failures | ◎ | Readiness 監査（R01–R11）、検知に必要な属性の計装推奨、アラートと Slack 通知の生成 | ログの長期保管・改ざん防止 |
| A10 Mishandling of Exceptional Conditions | △ | 新しい種類の例外の出現（D17）、Errors Inbox の活用 | 例外処理のコード監査全般 |

### OWASP API Security Top 10:2023

| 項目 | 対応 | 内容 |
|---|---|---|
| API1 Broken Object Level Authorization | ◎ | F4、D01–D03 |
| API2 Broken Authentication | ○ | F1、D10、D14、D15 |
| API3 Broken Object Property Level Authorization | ○ | F6（Mass Assignment）、F8（過剰なデータ露出） |
| API4 Unrestricted Resource Consumption | △ | 上限のない `size`（F8）、自動化された大量アクセス（D11、D13） |
| API5 Broken Function Level Authorization | ◎ | F5、D05 |
| API6 Unrestricted Access to Sensitive Business Flows | △ | 業務トランザクションの異常頻度（検知の考え方のみ） |
| API7 Server Side Request Forgery | × | — |
| API8 Security Misconfiguration | △ | A02 と同じ |
| API9 Improper Inventory Management | ○ | シャドー API / ゾンビ API の突き合わせ（D16 + コード監査） |
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

コード監査の Finding との対応:

| Finding | CWE | ASVS 5.0 | OWASP | IPA |
|---|---|---|---|---|
| F1 認証なしで公開されている API | CWE-306 | V6, V8 | A07, A01, API2 | 1.11 |
| F2 スコープ・権限チェックが無い | CWE-862 | V8, V10 | A01, API5 | 1.11 |
| F3 スコープ・権限が不適切 | CWE-863 | V8, V10 | A01, API5 | 1.11 |
| F4 IDOR / BOLA（所有者照合が無い） | CWE-639 | V8 | A01, API1 | 1.11 |
| F5 機能レベルの認可不備（BFLA） | CWE-285 | V8 | A01, API5 | 1.11 |
| F6 Mass Assignment | CWE-915 | V15 | A06, API3 | — |
| F7 SQL インジェクション | CWE-89 | V1 | A05 | 1.1 |
| F8 過剰なデータ露出・上限のない取得 | CWE-213, CWE-770 | V14, V2 | A06, API3, API4 | — |

検知（D01〜D18）の対応は `shared/standards.json` を参照してください。
OAT と AI エージェントの結び付けは本プラグインの分析であり、OWASP の公式な位置付けではありません。

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
- [ ] Phase 3: Java（Spring Security）の計装サンプル、XML 候補の生成 → 以降、APM エージェント対応の全言語
- [ ] Phase 4: アラート条件・Workflow Automation（Autopilot / iRCA 分岐）・Slack・Knowledge 用ランブックのテンプレート
- [ ] Phase 5: 攻撃シナリオでの検証 → **v1.0.0**

## 参考

- [JPCERT/CC 注意喚起 JPCERT-AT-2026-0030 の報道](https://scan.netsecurity.ne.jp/article/2026/10/13/56428.html)
- [New Relic Ground Truth (MCP)](https://docs.newrelic.com/docs/agentic-ai/mcp/overview/)
- [New Relic Autopilot](https://docs.newrelic.com/docs/agentic-ai/autopilot/overview/)
- [Performance Risks Inbox](https://docs.newrelic.com/whats-new/2026/05/whats-new-05-14-performance-risks-inbox/)
- [OWASP API Security Top 10 2023](https://owasp.org/API-Security/editions/2023/en/0x11-t10/)

## License

MIT
