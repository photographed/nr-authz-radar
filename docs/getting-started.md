# はじめに: インストールと使い方

English: [getting-started.en.md](getting-started.en.md)

## 1. 全体像

このリポジトリは **Claude Code のプラグイン** です。Claude に「何を・どの順で・どう判断するか」を教える手順書（Skill）と、
決まった計算をするスクリプト、New Relic に適用する設定の雛形、**あなたのアプリに組み込むコード** が入っています。

```
あなた ──「API の認可をレビューして」「New Relic で攻撃の兆候を調べて」
  │
  ▼
Claude Code ── Skill（手順書）を読む
  ├─ ソースコードを読む ............... コード監査
  ├─ New Relic に NRQL を投げる ....... New Relic MCP（Ground Truth）経由・読み取りのみ
  ├─ スクリプトを実行する ............. 順位の計算・アラートの生成・XML 候補の生成
  └─ レポートとファイルを書き出す
  │
  ▼
あなた ── レポートを読み、ファイル（設定・パッチ）を確認して **自分で適用する**
```

### フォルダの役割

| フォルダ | 中身 | 誰が使うか |
|---|---|---|
| `skills/` | Claude への手順書。`api-authz-review`（コード監査）と `nr-appsec-guard`（New Relic での確認・検知・調査・計装の推奨・アラート生成） | Claude |
| `shared/` | 共通の仕様（属性、目的と段階、データソース、方式、優先度、プライバシー、規格の対応表） | Claude と人 |
| `scripts/` | 決まった計算・生成をするスクリプト。`risk_score.py`（順位）、`gen_alerts.py`（アラート）、`hunt.py`（NerdGraph で検知を実行。AI を使わない）、`inventory_java.py`（エンドポイントの一覧）、`catalog.py`（必要な節だけを表示）、`gen_xml_candidates.py`（XML 計装の候補）、`attack_layer.py`（ATT&CK Navigator のレイヤー） | **Claude が実行**（人が直接実行してもよい） |
| `templates/` | New Relic に適用する設定の雛形（Terraform、Workflow Automation、Slack、Autopilot のプロンプト、ランブック） | Claude が埋めて出力 → **人が適用** |
| `instrumentation/` | **あなたのアプリに組み込むコード**。Java は計装ライブラリ、Python・Node.js・Ruby・Go・PHP・.NET は取り込める小さなファイル | **開発者**（Claude は実行しない。組み込むパッチ案を作る） |
| `examples/`・`docs/samples/` | サンプルのアプリと、実際の実行結果・レポート例 | 人 |

### 何が自動で、何を人がやるか

| 作業 | 誰が | 備考 |
|---|---|---|
| ソースコードを読んで問題を探す | **Claude（自動）** | |
| New Relic のデータを調べる | **Claude（自動）** | 読み取りのみ |
| 順位の計算 | **Claude がスクリプトを実行（自動）** | 同じ入力なら毎回同じ順位 |
| レポートの作成 | **Claude（自動）** | 「今わかること」と「推奨」を分ける |
| アラートの Terraform・XML・修正パッチの作成 | **Claude（自動）** | ファイルとして出力するだけ |
| **New Relic への適用**（`terraform apply` など） | **人** | Skill は New Relic の設定を変更しない |
| **アプリへの組み込み**（パッチ・計装コード） | **人**（開発者） | Skill はコードを書き換えない（パッチ案を出す） |
| Slack の Destination の作成 | **人** | New Relic の画面で OAuth が必要 |

## 2. インストール

### 必要なもの
- Claude Code（CLI・デスクトップアプリ・Web のいずれか）
- Python 3.10 以上（スクリプトの実行に使う。追加のパッケージは不要）
- New Relic のアカウント（New Relic の確認・検知を使う場合）。コード監査だけなら不要

### 手順 A: 手元の Claude Code（CLI・デスクトップ）
```text
/plugin marketplace add photographed/nr-authz-radar
/plugin install nr-authz-radar@nr-authz-radar
```
New Relic に接続する（初回はブラウザで OAuth 認可）:
```text
/mcp
```
一覧の `newrelic-us` を選んで認証する。**JP リージョン**のアカウントは、公式ドキュメントで JP の MCP エンドポイントを確認して追加する:
```bash
claude mcp add --transport http newrelic-jp <JP リージョンの MCP エンドポイント URL>
```

### 手順 B: Claude Code on the web（クラウドのセッション）
1. New Relic MCP を **コネクタ** として追加する（claude.ai の Connectors 設定。URL: `https://mcp.newrelic.com/mcp/`、OAuth）。コネクタはセッション開始時に読み込まれるので、追加後に新しいセッションを始める
2. クラウド環境のネットワーク許可に `mcp.newrelic.com` を追加する（環境の設定 → Network access）
3. プラグインを使うリポジトリの `.claude/settings.json` に、マーケットプレイスとプラグインを登録する（キー名は Claude Code のドキュメントで要確認）:
   ```json
   {
     "extraKnownMarketplaces": {
       "nr-authz-radar": { "source": { "source": "github", "repo": "photographed/nr-authz-radar" } }
     },
     "enabledPlugins": { "nr-authz-radar@nr-authz-radar": true }
   }
   ```

### 動作の確認
Claude に「nr-authz-radar で何ができる？」と聞く。2つの Skill（`api-authz-review`、`nr-appsec-guard`）の説明が返れば読み込まれている。

## 3. 使い方（頼み方の例）

普段の言葉で頼めば、Claude が該当する Skill を選ぶ。**日本語で頼めば日本語、英語で頼めば英語で出力する。**

| やりたいこと | 頼み方の例 | Claude がやること | 出力（サンプル） |
|---|---|---|---|
| **コード監査**（① 棚卸し） | 「このリポジトリの API の認可をレビューして。優先順位も付けて」 | エンドポイントとスコープの洗い出し → 問題の検出 → `risk_score.py` で順位付け | [コード監査レポート](samples/code-review-report.md)、[順位](samples/ranking.md) |
| **前提の確認** | 「New Relic のアプリ shop-api で、今どんな攻撃に気づける状態か確認して」 | R01〜R15 を実行し、段階（S0〜S3）とデータソースを判定 | [New Relic レポート（例）](samples/newrelic-report.illustrative.md) |
| **攻撃の兆候を調べる**（③ Hunt） | 「shop-api で直近24時間に IDOR や SQLi の兆候がないか調べて」 | 今の段階で実行できる検知（D01〜D23）だけを実行 | 同上 |
| **利用実態**（②） | 「shop-api の API ごとの利用状況と、使われていない API を出して」 | U01〜U06 を実行し、コードと突き合わせ | — |
| **調査**（④） | 「仮名化ユーザー u_3f9a… の昨日 10〜12時のアクセスを調べて」 | まず記録が残っているかを確認（I05〜I07）→ I01〜I04 | — |
| **アラートの作成** | 「今の段階で作れるアラートを Terraform で出して」 | `gen_alerts.py` を実行。作れないものは条件付きで一覧に | [生成しなかったアラート](samples/alerts-SKIPPED-S0.md)、[Terraform の抜粋](samples/alerts-excerpt-S0.tf) |
| **計装のパッチ** | 「IDOR の候補に計装を入れるパッチを作って」 | `@CheckOwnership` 等のパッチ案を作る | コード監査レポートの「推奨」 |
| **XML の候補**（コード変更なし） | 「認可チェックのメソッドを XML で計装する候補を出して」 | `gen_xml_candidates.py` を実行 | [XML 候補](samples/xml-candidates.md) |

**いつ使うか**（頻度）は README の「いつ使うか」を参照。最も効果が大きいのは **PR・リリース前のコード監査**。

### サンプルの見方
- [`docs/samples/code-review-report.md`](samples/code-review-report.md) — **実際の実行結果**（`examples/sample-app/` を監査したもの）
- [`docs/samples/newrelic-report.illustrative.md`](samples/newrelic-report.illustrative.md) — **架空のデータによる例**（New Relic 未接続のため）。順位への影響の部分だけは実際の計算
- `*.en.md` は英語版

## 4. `instrumentation/` をアプリに組み込む

IDOR が成功したかどうかは、アプリしか知らない。**`resource.owner_match` と `authz.decision` の2つを送るコード**を組み込むと、D01（IDOR 成功の証拠）が使えるようになる（段階 S2）。

| 言語 | 組み込み方 |
|---|---|
| Java（Spring Boot） | `instrumentation/java/` をビルドして依存に追加し、データ取得のメソッドに `@CheckOwnership(type = "order")`。詳細: [`instrumentation-java.md`](../skills/nr-appsec-guard/references/instrumentation-java.md) |
| Python・Node.js・Ruby・Go・PHP・.NET | `instrumentation/<言語>/` のファイルをプロジェクトにコピーし、データ取得の直後に照合の関数を呼ぶ。詳細: [`instrumentation-other-languages.md`](../skills/nr-appsec-guard/references/instrumentation-other-languages.md) |

最初は **OBSERVE モード**（記録だけ）で出し、本当に起きている IDOR を確認してから ENFORCE（拒否）に切り替える。

## 5. スクリプトを直接実行する（Claude を使わない場合）

```bash
# 順位の計算
python3 scripts/risk_score.py docs/samples/findings.json --format md

# アラートの生成（今の段階とデータソースを指定。--lang en で英語のレポート）
python3 scripts/gen_alerts.py --stage S0 --sources spans --out out/terraform

# XML 計装の候補
python3 scripts/gen_xml_candidates.py path/to/src/main/java --xml out/authz-extension.xml --report out/xml-candidates.md
```

### 定期実行（AI を使わない Hunt）
```bash
export NEW_RELIC_API_KEY=...   # User キー
python3 scripts/hunt.py --app shop-api --account-id 1234567 --stage S2 --sources spans --levels evidence,strong
# 結果: .authz-radar/hunt/hunt-summary.md（証拠の強さごとの要約）
```
cron や CI から実行できる。要約を Claude に読ませて解釈させてもよい（読む量が少ないので安い）。

## 6. よくある質問

| 質問 | 答え |
|---|---|
| New Relic の設定を勝手に変える？ | 変えない。New Relic への問い合わせは読み取りのみで、設定はファイルとして出力するだけ |
| アプリのコードを勝手に書き換える？ | 書き換えない。修正はパッチ案として出す |
| New Relic が無くても使える？ | コード監査（`api-authz-review`）は単体で使える。New Relic があると、利用実態と攻撃兆候で順位が補正される |
| カスタム属性が無いと何もできない？ | できることは多い（S0 でも API の棚卸し・利用実態・SQLi や RCE の兆候など）。**IDOR が成功した証拠だけは S2 の2属性が必要** |
| REST 以外（GraphQL・WebSocket など）は？ | 対応している。ただしステータスコードを使う検知は REST 専用。詳細: [`shared/protocols.md`](../shared/protocols.md) |
| 英語で使える？ | 使える。英語で頼めば英語で出力する。スクリプトのレポートは `--lang en` |
| ログも使う？ | ラストワンマイルとして使う。**スキャンはせず**、APM の手がかり（トレース ID・ユーザー・時間帯）で絞って取りに行く（L01〜L04） |
| 偽陽性が多くならない？ | 証拠の強さで分けている。通知するのは「証拠」（D01・D07）と「強い兆候」だけで、量や割合の「異常」は既定では通知しない。詳細: [`docs/how-it-works.md`](how-it-works.md) |
| コストは？ | 定期の Hunt は AI を使わない `hunt.py`。Autopilot は証拠のアラートからだけ。詳細: [`shared/cost.md`](../shared/cost.md) |
| 現在の検証状況は？ | スクリプト・計装コードはテスト済み。**NRQL・Terraform・Workflow Automation は実際の New Relic 環境では未検証**（Phase 5 で検証予定） |
