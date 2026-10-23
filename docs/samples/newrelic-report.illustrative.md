# サンプル: New Relic のレポート（前提の確認 + Hunt）

> ⚠️ **架空のデータによる例です。** New Relic に接続していない環境で作成したため、件数・割合などの数値はすべて説明用に作ったもの。
> 形式（「今わかること」と「推奨」を分ける、判定不能を明記する）と、判断の流れを示すのが目的。
> 最後の「順位への影響」だけは、架空の入力（[`findings-with-newrelic.illustrative.json`](findings-with-newrelic.illustrative.json)）で `risk_score.py` を実際に実行した結果。

想定: [`examples/sample-app/`](../../examples/sample-app/) を Java エージェントで監視している。カスタム属性はまだ無い。

依頼の例: 「shop-api を New Relic で点検して。今どんな攻撃に気づける状態か、今起きていることも見て」

---

## 今のデータでわかること・できること

### 現在の段階とデータソース
- **段階: S0**（APM エージェントのみ。`authz.decision`・`resource.owner_match`・`enduser.id` が無い — R02）
- データソース: APM ✅、分散トレーシング ✅、Browser ✅、Logs ❌、Change Tracking ❌
- API の方式（R15）: REST、**GraphQL**、**WebSocket（接続 101 はあるが、メッセージのトランザクションが無い）**
- Autopilot / iRCA: 無効（R09。ユーザーに確認済み）

### 目的ごとの状況
| 目的 | 状況 | 理由 |
|---|---|---|
| ① 棚卸し | ⚠️ 一部 | REST はトランザクション名が API 単位（R12 良好）。GraphQL は1本にまとまり、名前はクライアントの operation 名（偽装できる） |
| ② 利用実態 | ✅ できる | U01・U02・U03 を実行 |
| ③ 攻撃検知 | ⚠️ 一部 | S0 のため **D01（IDOR 成功の証拠）は判定不能**。D04・D06・D10・D12 等は実行 |
| ④ 調査 | ❌ ほぼ不可 | ログが無い（R14）。Transaction は直近1日で約 62% しか残っていない（R13・サンプリング） |

### 検知の結果
| 脅威 | 検知 | 結果 | 内容 |
|---|---|---|---|
| IDOR 成功 | D01 | ❌ 判定不能 | `resource.owner_match` が無い |
| ID 列挙 | D03 | ❌ 判定不能 | `enduser.id` が無い |
| 403/404 の急増 | D04 | ⚠️ `weak` | `/api/v0/members/{id}/profile` で 404 の割合が平常時の 2.6 倍（ID を順に試すと存在しない ID で 404 になる） |
| SQLi | D06・D07 | `none` | 構文エラー・注入らしい SQL 文は無し（**脆弱性が無いという意味ではない**。コード監査では F7 あり） |
| 認証失敗 | D10 | `none` | — |
| 画面を通らない呼び出し | D12 | ⚠️ `weak` | `/api/v0/...` は 100% が分散トレーシングの親なし（画面・現行アプリから呼ばれていない）。平常時は 92% |
| RCE の試み | D21 | `none` | — |
| GraphQL・WebSocket の拒否 | D22 | ❌ 判定不能 | S2 未満。**D04・D10 は GraphQL・WebSocket では反応しない**ので、上の `none` は安全を意味しない |

### 利用実態（抜粋）
| API | rpm | 呼び出し元（U03） | メモ |
|---|---|---|---|
| `GET /api/v1/orders/{id}` | 120 | Browser 88% / Mobile 11% | 主要な API |
| `GET /api/v1/products/search` | 40 | Browser 97% | |
| `GET /api/v0/members/{id}/profile` | 3.2 | **親なし 100%** | 現行アプリは使っていないはずの旧 API |
| `PUT /api/admin/users/{id}/role` | **0**（30日間） | — | 使われていない |

### 判定できなかったこと
- 旧 API への 404 の増加と直接呼び出しが、**ID の列挙かどうか**（`enduser.id` が無く、ユーザー単位で見られない。そもそも認証が無い API）
- **他人の会員情報が実際に返ったか**（S2 の属性が無い。ログも無い）
- WebSocket のメッセージで何が起きているか（メッセージが計装されていない）

---

## 推奨（段階的に）

1. **今すぐ**: `/api/v0/**` を停止する（コード監査の #1。認証なしでマイナンバーを含む会員情報が返る）。D04・D12 の兆候と合わせると、列挙されている可能性がある
   → 効く目的: ③ / 個人情報保護の観点で、社内の手順に従って関係部署と共有する
2. **今すぐ**: 停止の前後で、`/api/v0` で **200 で返ったアクセス**を、ロードバランサー・CDN のログで確認する（APM はサンプリングされており一部しか無い）
   → これでわかること: 何件の会員情報が返ったか / 効く目的: ④
3. **今週**: ログ（アクセスログ・アプリのログ）を New Relic に取り込む
   → これでわかること: 調査で全件を確定できる（I04） / 効く目的: ④
4. **次のリリース**: S2 の2属性（Java ライブラリ、OBSERVE モード）
   → これでわかること: D01（IDOR 成功の証拠）・D22（GraphQL・WebSocket でも使える拒否の検知）/ 効く目的: ③
5. **次のリリース**: WebSocket のメッセージをトランザクションにする（Java ライブラリが STOMP に自動対応）
   → これでわかること: WebSocket 経由のアクセスと IDOR / 効く目的: ②③
6. **アラート**: 今の段階（S0）で作れる5種類を生成（[`alerts-SKIPPED-S0.md`](alerts-SKIPPED-S0.md) に残りと条件）。S2 に進んだら再生成して D01・D02・D22 を追加

## 順位への影響（実際の計算結果）

コード監査の順位に、上の利用実態と兆候を入れて再計算した（[`ranking-with-newrelic.illustrative.md`](ranking-with-newrelic.illustrative.md)）。

| エンドポイント | New Relic なし | New Relic あり | 変化の理由 |
|---|---|---|---|
| `GET /api/v0/members/{id}/profile`（F1・F4・F8） | P1 | **P0** | 攻撃兆候（D04・D12 が `weak`）× Critical |
| `PUT /api/admin/users/{id}/role`（F5） | P1 | P1・**`dormant_critical`** | 30日間トラフィック 0 → **最初の対応が「無効化または削除」に変わる** |
| `GET /api/v1/products/search`（F7） | P1 | P1 | 兆候なし。トラフィックは同じ段階内の並び順にだけ効く |
