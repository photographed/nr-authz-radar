# nextjs-vuln-site — ローカル検証用の「やられサイト」（Next.js App Router）

`nr-authz-radar` が **IDOR / BOLA** をどう捉えるかを手元で確かめるための、意図的に脆弱な API です。
PHP 版 [`examples/php-vuln-site`](../php-vuln-site) の Next.js 版にあたります。

> **これは意図的に脆弱です。127.0.0.1 からのみ使い、絶対に公開・デプロイしないでください。**

## これで何がわかるか

| エンドポイント | 仕込んだ穴 | 見え方 |
|---|---|---|
| `GET /api/orders/[id]` | IDOR（他人の注文が見える）。**計装あり** | observe では 200 のまま `owner_match=false` ＋ `decision=allow` を記録（＝検知 **D01**）。enforce では 404 |
| `GET /api/raw/orders/[id]` | 同じ IDOR だが **計装なし** | 200 だけ。New Relic からは普通のアクセスと区別できない（「入れる前」） |

エージェントが無くても、`AUTHZ_RADAR_LOG_DECISIONS=true` なら**認可判断ログ**がサーバー出力に出るので、
計装の効き目を手元で確認できます（属性を送れない環境の代わり＝検知 **L04** でもあります）。

## 動かす

```bash
cd examples/nextjs-vuln-site
cp .env.example .env.local        # 既定は observe
npm install
npm run build && npm start        # http://127.0.0.1:3000
./check.sh                        # 4 パターンを流す。認可判断ログは起動した端末に出る
```

ユーザーは Alice・Bob（一般）と Admin。トークンは `token-alice` / `token-bob` / `token-admin`。
リクエストには `?api_token=` か `Authorization: Bearer` を付けます。

モード切替は `.env.local` の `AUTHZ_RADAR_OWNERSHIP_MODE`（`observe` ↔ `enforce`）。

## どこが計装できる/できないか（重要）

New Relic の Node エージェント（`@newrelic/next`）が**アクティブなトランザクションを張る場所でだけ**カスタム属性が付きます。

- ✅ **Route Handler**（`app/**/route.js`）・Pages API（`pages/api/**`）・**Server Actions**: ここで所有者照合を呼ぶ（このデモがそれ）
- ❌ **`middleware.ts` は Edge ランタイム**で動き、Node エージェントが読み込まれない → **何も記録されない**。認可はミドルウェアだけに置かず、ハンドラでも確認する
- ❌ クライアントコンポーネント・ビルド時: サーバーのテレメトリは出ない

## New Relic に送る（任意）

```bash
npm install newrelic @newrelic/next
NEW_RELIC_LICENSE_KEY=xxxx NODE_OPTIONS='-r @newrelic/next' npm start
```

`newrelic.cjs` が設定の雛形です。キーが無くても計装ライブラリは安全に何もしないので、認可判断ログで動きを確認できます。

## 中身

計装は `app/api/orders/[id]/route.js`（`@nr-authz-radar/node/nextjs` の `withAuthzRadar` / `setUser` / `ownership`）。
`app/api/raw/orders/[id]/route.js` だけはあえて計装していません。
