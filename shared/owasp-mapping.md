# OWASP 対応表 → New Relic シグナル / コード監査 Finding

対象: **OWASP Top 10:2025** と **OWASP API Security Top 10:2023**。
「SIEM でログを相関する」のではなく、**アプリ内部の文脈（認可判断・トランザクション・DB・Browser）**で気づくことを重視する。

| 脅威 | OWASP | 実行時シグナル（nr-appsec-guard） | コード監査 Finding（api-authz-review） |
|---|---|---|---|
| IDOR / BOLA | A01 / API1 | `owner_match=false AND decision='allow'`、ユーザー単位の `deny(owner_mismatch)` 急増 | F4 |
| ID 列挙 | A01 / API1 | ユーザー/IP あたりの 404・deny 比率の急上昇、同一トランザクション名への高頻度アクセス | F4（連番ID） |
| スコープ逸脱 | A01 / API5 | `deny(scope_missing)` の集中、`required_scope` と `granted_scopes` の不一致 | F2 / F3 |
| 機能レベル認可不備（BFLA） | API5 | 管理系トランザクションへの一般ユーザーからのアクセス | F5 |
| Mass Assignment / 過剰露出 | API3 | レスポンスサイズの異常（Performance Risks: large payload） | F6 / F8 |
| SQL インジェクション | A05 | **Errors Inbox**: DB 構文エラーの新規グループ / **Performance Risks**: slow SQL・クエリ過多 / TransactionError | F7 |
| 認証攻撃（総当たり・分散） | A07 / API2 | 401 急増、1アカウントに多数IP | F1 |
| リソース消費（スクレイピング） | API4 | 少数アカウント × 多数IP、機械的に一定のリクエスト間隔 | F8（無制限 `size`） |
| 機微な業務フローの悪用 | API6 | 業務トランザクション（購入・ポイント付与等）の異常頻度 | — |
| インベントリ管理不備（シャドー/ゾンビ API） | API9 | ソースに無いのにトラフィックがあるトランザクション | 突合で検出 |
| 既知の脆弱部品 | A03 | New Relic Vulnerability Management | — |
| 例外処理の不備 | A10 | Errors Inbox: スタックトレース露出・未処理例外の急増 | — |
| 監視の欠落 | A09 | **Readiness 監査そのもの**（必要な属性が届いていない＝リスク） | — |

## AI エージェント特有の兆候（横断）

| 兆候 | シグナル |
|---|---|
| ブラウザを経由しない API 直叩き | APM トランザクションはあるが、同じ `enduser.id` の Browser PageView / セッションが無い |
| 分散アクセス | 短時間に多数の IP、1 IP あたりは少数リクエスト（例: 40分で326 IP / 1,200件超の観測報告） |
| 機械的な間隔 | リクエスト間隔のばらつきが極端に小さい |
| 網羅的探索 | 404 / 405 が多数のパスに分散、存在しない旧バージョン API への試行 |
