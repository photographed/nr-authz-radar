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

## 含まれる Skill

| Skill | 役割 |
|---|---|
| `nr-appsec-guard` | 実行時: Readiness 監査、Hunt（NRQL による検知）、計装推奨（yml / XML / API）、アラート・Workflow Automation・Slack 通知の生成。Autopilot / iRCA の有無で動作を切り替え |
| `api-authz-review` | コード: エンドポイントとスコープの洗い出し、IDOR/BOLA・BFLA・Mass Assignment・SQLi・過剰露出の検出、New Relic の実トラフィックで補正したランキング |

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

`.mcp.json` に US と JP の2つを登録しています。認証は OAuth が標準です（初回接続時にブラウザで認可）。

| サーバー名 | エンドポイント |
|---|---|
| `newrelic-us` | `https://mcp.newrelic.com/mcp/` |
| `newrelic-jp` | 環境変数 `NR_MCP_JP_URL` で指定（**公式ドキュメントで URL を確認して設定してください**） |

## 方針

- **生成のみ**: New Relic のアラート・Workflow、アプリの `newrelic.yml`・XML・コードは、すべてファイルや差分として出力します。適用は人が行います。
- **断定しない**: 「AI エージェントによる攻撃」は兆候として扱います。コードだけで判定できないものは `needs_review` にします。
- **データは最小限に**: IP アドレスは既定で New Relic に送りません（GDPR では個人データ、日本法でも個人関連情報に当たり得るため）。IP 粒度の分析は WAF / CDN に任せ、判定結果だけを受け取る設計です。詳細は [`shared/privacy.md`](shared/privacy.md)。

## ロードマップ

- [x] Phase 1: 共通仕様（属性、OWASP 対応、脅威モデル、ランキング）、Skill の骨組み、ランキングスクリプト
- [x] Phase 2: Readiness 監査（R01〜R11）と Hunt の NRQL カタログ（D01〜D18）。一部クエリは実アカウントで要検証
- [ ] Phase 3: Java（Spring Security）の計装サンプル、XML 候補の生成 → 以降、APM エージェント対応の全言語
- [ ] Phase 4: アラート条件・Workflow Automation（Autopilot / iRCA 分岐）・Slack・Knowledge 用ランブックのテンプレート
- [ ] Phase 5: 攻撃シナリオでの検証

## 参考

- [JPCERT/CC 注意喚起 JPCERT-AT-2026-0030 の報道](https://scan.netsecurity.ne.jp/article/2026/10/13/56428.html)
- [New Relic Ground Truth (MCP)](https://docs.newrelic.com/docs/agentic-ai/mcp/overview/)
- [New Relic Autopilot](https://docs.newrelic.com/docs/agentic-ai/autopilot/overview/)
- [Performance Risks Inbox](https://docs.newrelic.com/whats-new/2026/05/whats-new-05-14-performance-risks-inbox/)
- [OWASP API Security Top 10 2023](https://owasp.org/API-Security/editions/2023/en/0x11-t10/)

## License

MIT
