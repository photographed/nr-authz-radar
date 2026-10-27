# php-vuln-site — ローカル検証用の「やられサイト」（Laravel 12 / PHP 8.5.11）

`nr-authz-radar` が **IDOR・SQLi・BFLA** をどう捉えるかを、自分の手元で確かめるための
意図的に脆弱な API です。既存の Java 版 [`examples/sample-app`](../sample-app) の PHP 版にあたります。

> **これは意図的に脆弱です。127.0.0.1 からのみ使い、絶対に公開・デプロイしないでください。**
> クラウド（AWS 等）で動かすと本物の攻撃対象になります。ローカルの Docker だけで動かしてください。

## これで何がわかるか

| エンドポイント | 仕込んだ穴 | nr-authz-radar の見え方 |
|---|---|---|
| `GET /api/orders/{id}` | IDOR / BOLA（他人の注文が見える） | **計装あり**。observe では 200 のまま `resource.owner_match=false` ＋ `authz.decision=allow` を記録（= 検知 **D01**）。enforce では 404 で遮断 |
| `PATCH /api/orders/{id}/ship` | BFLA（管理者チェック無しで誰でも発送扱いにできる） | 認可判断を記録。役割の欠落は `authz.deny_reason` に出る設計 |
| `GET /api/raw/orders/{id}` | 同じ IDOR だが **計装なし** | 200 だけ。**New Relic からは普通のアクセスと区別できない**（「入れる前」の状態） |
| `GET /api/raw/orders?item=` | SQL インジェクション（文字列連結） | 構文エラーは `TransactionError` に残り、検知 **D06**。`UNION SELECT` は `db.statement` に形が残り **D07** |

「計装あり」と「計装なし（raw）」を並べているのは、**カスタム属性を送らないと IDOR は 200 OK のままで見えない**
という、このツールの前提（`shared/attribute-spec.md`）を手元で確認できるようにするためです。

## 動かす（Docker・PHP 8.5.11）

```bash
cd examples/php-vuln-site
cp .env.example .env            # 既定は observe モード（IDOR を通して記録する）
docker compose up --build -d    # 127.0.0.1:8000 のみで待ち受け

# 初回だけ: アプリキーと DB を用意
docker compose exec app php artisan key:generate
docker compose exec app php artisan migrate --seed

./check.sh                      # 6 パターンを流して結果と認可判断ログを表示
docker compose down
```

ユーザーは Alice・Bob（一般）と Admin。API トークンはそれぞれ `token-alice` / `token-bob` / `token-admin`
（seed で固定）。リクエストには `?api_token=` か `Authorization: Bearer` を付けます。

## モードの切り替え

`.env` の `AUTHZ_RADAR_OWNERSHIP_MODE` を変えて `docker compose restart app`:

- `observe`（既定）: 穴はそのまま。**実際に起きている IDOR を記録して可視化**する（既存アプリに入れる最初の段階）
- `enforce`: 所有者が違えば 404 で遮断する

## New Relic に送る（任意）

ライセンスキーがあれば、PHP エージェント入りでビルドして実データを見られます。

```bash
NR_AGENT=1 docker compose build
# .env に NEW_RELIC_LICENSE_KEY を設定してから docker compose up -d
```

キーが無くても計装ライブラリは安全に何もしないので、認可判断ログ（`storage/logs/laravel.log`）で
動きを確認できます。これは属性を送れない環境（High-security mode）の代わりでもあります（検知 **L04**）。

## 中身

`app/Http/Controllers/Api/` にコントローラ、`routes/api.php` にルート、`database/seeders/` にデータ。
計装は `OrderController`（`ChecksOwnership` トレイト）と `config/authz-radar.php`。
`RawOrderController` だけはあえて計装していません。
