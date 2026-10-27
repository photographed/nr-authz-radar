# Next.js の計装

**目的**: 段階 S2（IDOR 成功の証拠 D01）に到達する。属性の仕様は `shared/attribute-spec.md`。
手元で試せる脆弱なデモは [`examples/nextjs-vuln-site`](../../../examples/nextjs-vuln-site)（App Router・ローカル専用）。

## どこで記録できるか（必ず確認する）

New Relic の Node エージェントを `NODE_OPTIONS='-r @newrelic/next'` で読み込むと、**アクティブなトランザクションがある場所でだけ**カスタム属性が付く。公式 `@newrelic/next` が計装するのは SSR（`getServerSideProps`）・middleware・トランザクション名で、**ビルド時とクライアント側は対象外**。

| 場所 | 記録できるか |
|---|---|
| **Route Handler**（`app/**/route.ts`）・Pages API（`pages/api/**`）・**Server Actions** | ✅ ここで所有者照合を呼ぶ |
| **`middleware.ts`（Edge ランタイム）** | ❌ **Node エージェントが読み込まれない。** 認可をミドルウェアだけに置くと、検知に必要な属性が一切出ない |
| Server Components（RSC のレンダリング中） | △ SSR トランザクション内なら付くが、設計上は取得処理を Route Handler / Server Action に寄せるのが確実 |
| クライアントコンポーネント・ビルド時 | ❌ サーバーのテレメトリ対象外 |

**結論**: 所有者照合（`owner_match`）は、ミドルウェアではなく **Route Handler・API Route・Server Action の中**で呼ぶ。Edge ミドルウェアは認証の入口には使えても、IDOR 検知の属性はそこからは出ない。

## 使い方（App Router Route Handler）

```bash
npm install @nr-authz-radar/node        # リポジトリ内なら file:../../instrumentation/node
```

```js
// app/api/orders/[id]/route.js
const { withAuthzRadar, setUser, ownership } = require('@nr-authz-radar/node/nextjs')

async function handler (request, { params }) {
  const user = await getUser(request)            // 自分の認証
  if (!user) return Response.json({ error: 'unauthenticated' }, { status: 401 })
  setUser(user.id)                               // 仮名化した enduser.id

  const { id } = await params
  const order = await db.loadOrder(id)
  ownership(order.user_id, user.id, { resourceType: 'order' })  // observe なら false でも通す（D01）
  return Response.json(order)
}

const GET = withAuthzRadar(handler)              // per-request 状態と、OwnershipError→Response を担う
module.exports = { GET }
```

- `withAuthzRadar` は `AsyncLocalStorage` で**リクエストごとに独立した状態**を持つ（並行リクエストで `owner_match` が混ざらない）。
- enforce モードでは `ownership` が投げる `OwnershipError` を `withAuthzRadar` が `deny_status`（既定 404）の `Response` に変換する。observe モードでは 200 のまま記録する（＝ D01）。
- Server Action でも同じ: `export const doThing = withAuthzRadar(async (formData) => { ... })`。
- 正当な他人アクセスは `ownership(ownerId, userId, { bypassScope: 'admin:read' })`。D01 から除外される。
- REST 以外は `protocol('graphql', serverSideOperationName)`（`shared/protocols.md`）。**クライアントが付ける GraphQL の operation 名は使わない**。
- 自前の認証で 401/403 を返すだけの経路は `deny('unauthenticated' | 'scope_missing' | ...)` を呼ぶと `authz.decision=deny` を記録できる。

## 設定（環境変数）

| 変数 | 既定 | 意味 |
|---|---|---|
| `AUTHZ_RADAR_HMAC_KEY` | （空） | 仮名化の鍵。**全サービスで同じ値**だと同じユーザーを追える。無いとユーザー ID を送らない |
| `AUTHZ_RADAR_OWNERSHIP_MODE` | `enforce` | `observe`（穴を通して記録＝D01 を可視化）／ `enforce`（遮断） |
| `AUTHZ_RADAR_ATTRIBUTES` | `minimal` | `minimal`（S2）／ `full`（S3） |
| `AUTHZ_RADAR_LOG_DECISIONS` | `false` | 認可判断ログ行を出す（High-security mode や、エージェント未導入時の確認、L04 用） |

`withAuthzRadar(handler, { nr, key, enforce, attributes, denyStatus, log })` で明示的に渡すこともできる（テストやマルチテナントで）。

## エージェントの起動と設定

```bash
NEW_RELIC_LICENSE_KEY=xxxx NODE_OPTIONS='-r @newrelic/next' next start
```
- 分散トレーシングを有効化（`Span` が無いと D07・D08・D20 が使えない）。`newrelic.cjs` に設定の雛形。
- 拒否は Node のコア（`authz-radar.js`）側では `noticeError(err, {}, true)` で expected error として送れるが、Next.js ヘルパー経由の既定ではエラーにせず `authz.decision` 属性で検知する（エラー率を汚さないため）。

## 確認した前提と未確認

- **確認済み**: ヘルパーの単体テスト（`nextjs.test.js`、13 ケース）。デモ（Next.js 15.5）で Route Handler から observe の D01 ログ・enforce の 404 が出ることを実機で確認。
- **未確認（Phase 5）**: 実際に New Relic アカウントへ属性が届くこと。これは `@newrelic/next` のバージョンと Next.js のバージョンの組み合わせに依存する（App Router の Route Handler のトランザクション計装はバージョンで差がある）。導入時に R02（属性が届いているか）の NRQL で必ず確認する。
