---
name: api-authz-review
description: Inventory and audit API authorization in source code (Java/Spring first) — enumerate endpoints, extract required scopes/roles, detect missing scope checks, IDOR/BOLA candidates (no ownership check), BFLA, mass assignment, SQL injection, OS command injection, unsafe deserialization and excessive data exposure, then rank findings deterministically (optionally boosted by New Relic Ground Truth traffic and attack signals). Use when asked to review API scopes, find IDOR/BOLA, check authorization, or prioritize API security fixes.
---

# api-authz-review — ソースコードの認可・スコープ監査

API ごとに「どのスコープが必要か」「所有者照合をしているか」をコードから洗い出し、問題を決定的なスコアで順位付けする。
プラグインのルートはこのファイルから `../../`（以下 `<root>`）。

## 守ること
1. **ユーザーの言語で出力する**（英語なら英語）。ID・属性名・CWE 等の番号・コードは訳さない
2. **生成のみ**: 修正はパッチ案として出す。ユーザーの指示なしにファイルを書き換えない
3. **根拠を示す**: Finding には必ず `file:line`。示せないものは出さない。判断できないものは `needs_review`
4. **点数を自分で付けない**: 特徴量を JSON にして `scripts/risk_score.py` に計算させる

## トークンを節約する読み方（必ず守る）
- **リポジトリ全体を読まない。** 最初に `inventory_java.py` を実行し、**フラグの付いたメソッドと認可の無いエンドポイントだけ** を開く
- **PR・差分のレビューでは `--changed-since <ref>`** で変更したファイルだけを対象にする
- 詳しい判定ルールは `references/review-rules.md` の **必要な Step だけ** を読む（全体を読まない）
- 作業ファイルは対象リポジトリの `.authz-radar/` に置き、**同じコミットに対する結果があれば再利用する**（`inventory.json`・`findings.json`・`ranking.md`）。`.authz-radar/` は `.gitignore` に入れるよう勧める
- チャットに出すのは要約（上位5件・件数・次の一手）だけ。全文は `.authz-radar/report.md` に書き、パスを示す

## 手順
```bash
python3 <root>/scripts/inventory_java.py <src/main/java> --out .authz-radar/inventory.json      # 全体
python3 <root>/scripts/inventory_java.py <src/main/java> --changed-since origin/main             # PR
```
1. **入力の確認**（review-rules Step 0）: OpenAPI・API Gateway の設定・`criticality.yaml` の有無。Gateway が不明なら一度だけ確認する
2. **棚卸し**（Step 1・2）: `inventory.md` を読む。スクリプトが拾えない形（WebFlux の RouterFunction、JAX-RS、gRPC、`@ServerEndpoint`）だけ grep で補う
3. **判定**（Step 3）: F1〜F12。候補のメソッドを開いて確かめる。WebSocket の購読先 IDOR は F4、メッセージ単位の認可なしは F2
4. **IAST での裏付け**（Step 3.5、任意）
5. **特徴量**（Step 4）→ `.authz-radar/findings.json`
6. **New Relic で補正**（Step 5、任意）: トラフィックは U01、攻撃兆候は `scripts/hunt.py` の結果（`hunt-summary.md`）を使う。MCP で1件ずつ問い合わせない
7. **順位付け**（Step 6）: `python3 <root>/scripts/risk_score.py .authz-radar/findings.json --format md`
8. **レポート**（Step 7）: 「今わかること」と「推奨」を分ける（`shared/goals.md`）。規格の番号は `shared/standards.json`

## 参照（必要なときだけ）
| 内容 | ファイル |
|---|---|
| Step ごとの詳しい判定ルール・特徴量のヒント・レポートの構成 | `references/review-rules.md` |
| 優先度の仕様 | `shared/risk-scoring.md` |
| REST 以外の方式の棚卸し対象と表記 | `shared/protocols.md` §4 |
| 計装の推奨（S2） | `../nr-appsec-guard/references/instrumentation-java.md`・`instrumentation-other-languages.md` |
