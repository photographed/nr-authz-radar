# サンプル: コード監査レポート（`api-authz-review`）

> **これは実際の実行結果です。** 対象は意図的に脆弱にしたサンプル [`examples/sample-app/`](../../examples/sample-app/)。
> `api-authz-review` の手順に沿って Claude が監査し、順位は `scripts/risk_score.py` が計算した（入力: [`findings.json`](findings.json)、出力: [`ranking.md`](ranking.md)）。
> New Relic は未接続のため、トラフィックは「未観測」。

---

## 今のデータでわかること

### サマリー
- エンドポイント: **9**（REST 6、GraphQL 1、WebSocket 1、管理系 1）
- Finding: **10 件**（P1: 5、P2: 3、P3: 2）
- **最優先**: 旧モバイル向け API `GET /api/v0/members/{id}/profile` が **認証なしで、他人の会員情報（マイナンバーを含む）を ID の指定だけで返す**（F1 + F4 + F8）
- New Relic 未接続のため、全件 `not_observed`（使われているかは不明）。接続すると、トラフィックが 0 の Critical は「無効化または削除」が最初の対応になる

### ランキング
| # | 優先度 | 段階 | エンドポイント | 種別 | 点数（影響×攻撃のしやすさ） | 規格 |
|---|---|---|---|---|---|---|
| 1 | P1 | Critical | `GET /api/v0/members/{id}/profile` | F1 認証なし | 25 (5×5) | CWE-306 / A07 / API2 |
| 2 | P1 | Critical | `GET /api/v0/members/{id}/profile` | F4 IDOR | 25 (5×5) | CWE-639 / A01 / API1 / IPA 1.11 |
| 3 | P1 | Critical | `GET /api/v1/products/search` | F7 SQLi | 20 (4×5) | CWE-89 / A05 / IPA 1.1 |
| 4 | P1 | Critical | `GET /api/v0/members/{id}/profile` | F8 過剰露出 | 20 (5×4) | CWE-213 / API3 |
| 5 | P1 | Critical | `PUT /api/admin/users/{id}/role` | F5 BFLA | 20 (5×4) | CWE-285 / API5 |
| 6 | P2 | High | `POST /api/v1/orders/{id}/cancel` | F3 スコープ不適切 | 12 (3×4) | CWE-863 / API5 |
| 7 | P2 | High | `GET /api/v1/orders/{id}` | F4 IDOR | 15 (3×5) | CWE-639 / API1 |
| 8 | P2 | High | `GRAPHQL Query.order` | F4 IDOR | 15 (3×5) | CWE-639 / API1 |
| 9 | P3 | Medium | `WS CONNECT /ws` | F12 WebSocket | 5 (1×5) | CWE-1385 |
| 10 | P3 | Medium | `GRAPHQL /graphql` | F11 GraphQL（要確認） | 4 (1×4) | CWE-770 / API4 |

同じ段階の中では、確度が高いもの（confirmed）を先に並べる（6位の F3 が7位より上なのはこのため）。

### Finding の詳細（上位）

**#1・#2・#4 `GET /api/v0/members/{id}/profile`（F1・F4・F8、confirmed）**
- 根拠: `config/SecurityConfig.java:16` で `/api/v0/**` を `permitAll()`。`member/LegacyMemberController.java:21` で `findById(id)` をそのまま返す。`Member` に `myNumber`（マイナンバー）・`address`・`birthDate` があり、Entity をそのまま返している
- 攻撃のしやすさ: 認証不要、ID は連番、モバイルアプリの解析で見つかる（JPCERT-AT-2026-0030 の手口）
- 点数の内訳: 影響 5（sensitive_personal）× 攻撃 5（認証なし +1、連番 +1、mobile +1、上限 5）
- 修正案:
  ```diff
  - .requestMatchers("/api/v0/**").permitAll()
  + .requestMatchers("/api/v0/**").denyAll()     // 現行アプリは /api/v1/me を使用。v0 は停止する
  ```
  継続が必要な場合は、認証を必須にし、`/api/v1/me` と同じく本人のデータだけを返す DTO にする（`myNumber` は返さない）

**#3 `GET /api/v1/products/search`（F7、confirmed）**
- 根拠: `search/SearchController.java:22` で、検索語 `q` を文字列連結して SQL を組み立てている
- 点数の内訳: 影響 4（SQLi は DB 全体に届くため下限 4）× 攻撃 5
- 修正案:
  ```diff
  - jdbc.queryForList("SELECT id, name, price FROM product WHERE name LIKE '%" + q + "%'")
  + jdbc.queryForList("SELECT id, name, price FROM product WHERE name LIKE ?", "%" + q + "%")
  ```

**#5 `PUT /api/admin/users/{id}/role`（F5、likely）**
- 根拠: `admin/AdminController.java:12`。`@PreAuthorize` が無く、URL のルールも `anyRequest().authenticated()` のみ。**ログインしていれば誰でもロールを変えられる**
- 修正案: `@PreAuthorize("hasAuthority('SCOPE_admin:write')")` を付ける。`/api/admin/**` を URL のルールでも制限する

**#6 `POST /api/v1/orders/{id}/cancel`（F3、confirmed）**
- 根拠: `order/OrderController.java:32-33`。書き込み（キャンセル）が `orders:read` スコープで通る。所有者照合はある
- 修正案: `SCOPE_orders:write` にする

**#7・#8 `GET /api/v1/orders/{id}`・`GRAPHQL Query.order`（F4、likely）**
- 根拠: `order/OrderController.java:23`、`order/OrderGraphQl.java:19`。どちらも `findById(id)`。**同じコントローラの `/receipt` は `findByIdAndOwnerId` を使っており、照合のパターンは既にある**
- 修正案:
  ```diff
  - return orders.findById(id).orElseThrow();
  + return orders.findByIdAndOwnerId(id, me.getName()).orElseThrow();
  ```

**#9 `WS CONNECT /ws`（F12、likely）** — `config/WebSocketConfig.java:13` の `setAllowedOriginPatterns("*")`。許可するオリジンを列挙する
**#10 `GRAPHQL /graphql`（F11、needs_review）** — introspection の無効化・深さの上限の設定がソースに見当たらない。`application.yml` 等で設定していないかを確認する

### スコープ一覧（CSV）
```csv
method,path,handler,required_scope,ownership_check,finding_ids
GET,/api/v0/members/{id}/profile,LegacyMemberController#profile,none (permitAll),no,F1-001;F4-001;F8-001
GET,/api/v1/orders/{id},OrderController#get,orders:read,no,F4-002
GET,/api/v1/orders/{id}/receipt,OrderController#receipt,orders:read,yes,
POST,/api/v1/orders/{id}/cancel,OrderController#cancel,orders:read,yes,F3-001
GRAPHQL,Query.order,OrderGraphQl#order,orders:read,no,F4-003
GET,/api/v1/products/search,SearchController#search,products:read,n/a,F7-001
PUT,/api/admin/users/{id}/role,AdminController#changeRole,none (authenticated),n/a,F5-001
WS,CONNECT /ws,WebSocketConfig,authenticated,n/a,F12-001
GET,/actuator/health,(actuator),none (permitAll),n/a,
```

### IDOR の回帰テスト案
```java
@Test
void aliceCannotReadBobsOrder() throws Exception {
    mvc.perform(get("/api/v1/orders/{id}", BOBS_ORDER_ID).with(jwt().jwt(j -> j.subject("alice"))
            .authorities(new SimpleGrantedAuthority("SCOPE_orders:read"))))
       .andExpect(status().isNotFound());   // 403 でもよい。存在を明かさないなら 404
}
```

### 判定できなかったこと
- 使われているか（New Relic 未接続）。旧 API `/api/v0` に今もアクセスがあるかで、最初の対応（停止か修正か）が変わる
- GraphQL の設定（F11）は、ソース以外（設定ファイル）にある可能性

---

## 推奨（段階的に）

1. **今日中**: `/api/v0/**` を停止（#1・#2・#4）。マイナンバーを含む会員情報が、認証なしで ID の指定だけで取れる状態。**停止前に、④ 調査で過去のアクセス（200 で返った分）を確認する**
   → 効く目的: ③ 攻撃検知・④ 調査 / これでわかること: 既に取得されたか
2. **今週中**: SQLi（#3）と管理 API の認可（#5）を修正
3. **次のリリース**: 注文の IDOR（#7・#8）を `findByIdAndOwnerId` に統一、キャンセルのスコープ（#6）を修正、WebSocket のオリジン（#9）
4. **計装（S2）**: IDOR の候補（#7・#8）のデータ取得に `@CheckOwnership(type = "order")` を付け、**まず OBSERVE モード**で本番に出す
   → これでわかること: **修正前に、他人の注文が実際に返っているか（D01）** / 効く目的: ③ 攻撃検知
5. **New Relic に接続して再実行**: トラフィックと攻撃兆候で順位を補正する（トラフィック 0 の Critical は停止を推奨に変える）
