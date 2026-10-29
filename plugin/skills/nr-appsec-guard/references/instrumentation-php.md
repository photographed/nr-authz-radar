# PHP（Laravel 12 / 素の PHP）の計装

**目的**: 段階 S2（IDOR 成功の証拠 D01）に最短で到達する。属性の仕様は `shared/attribute-spec.md`、段階の考え方は `shared/goals.md`。
確認できる手元の脆弱なデモは [`examples/php-vuln-site`](../../../examples/php-vuln-site)（Laravel 12・PHP 8.5.11・ローカル専用）。

## 確認した前提（New Relic PHP エージェント）

エージェントのソース（`newrelic/newrelic-php-agent` 12.12.0）で関数の存在を確認している。

| 使うもの | 関数 | 備考 |
|---|---|---|
| カスタム属性 | `newrelic_add_custom_parameter` | `resource.owner_match` などを送る |
| ユーザー | `newrelic_set_user_id`（エージェント **10.12 以上**） | 10.12 未満は `enduser.id` をカスタム属性で代用（ライブラリが自動で切替） |
| エラー | `newrelic_notice_error` | **expected を指定する引数は無い**（後述） |

- 関数が無い環境（エージェント未導入）では、ライブラリは **何もしないだけ**（例外にしない）。
- **自動計装される主なフレームワーク**: Laravel・Symfony・CodeIgniter・Drupal・Magento・Slim・Yii・WordPress・Laminas。トランザクション名はフレームワークが付ける（Laravel はルートのアクション）。
- **expected error が無い**: Java/Python 等と違い、PHP エージェントには拒否を「想定内のエラー」として送る仕組みが無い（設定は `newrelic.error_collector.ignore_exceptions` のみ）。そのため **拒否は既定でエラーとして送らない**（`notice_denials=false`）。検知はエラーではなくカスタム属性（`authz.decision`）で行う。

## 推奨の順番

| 順番 | 作業 | 到達する段階 | 手段 |
|---|---|---|---|
| 1 | 分散トレーシングを有効化し、SQL を obfuscated で記録（`newrelic.ini`） | S0 | 設定 |
| 2 | **ライブラリを入れ、リソース取得の直後に所有者照合を呼ぶ**（まず observe） | **S2** | コード |
| 3 | 結果を確認して enforce に切り替える | S2 | 設定（`.env`） |
| 4 | 必要なら全属性（`attributes=full`） | S3 | 設定 |

**S2 の `owner_match` はコード無しでは作れない**（「要求者＝所有者か」の比較はアプリにしかできない）。PHP エージェントには Java の XML のようなカスタム計装エディタが無いため、属性の送信は必ずコード（この API）で行う。

## Laravel 12

```bash
composer require photographed/nr-authz-radar
php artisan vendor:publish --tag=authz-radar-config   # config/authz-radar.php
```

サービスプロバイダは自動検出され、次を行う:
- リクエストごとに `enduser.id`（仮名化）と、Sanctum トークンの権限（`authz.granted_scopes`・`client.type=api_key`、full のみ）を送る
- `web`・`api` グループに記録用ミドルウェアを自動で追加（`auto_middleware`）
- Gate の失敗と認証失敗（`Failed`）を拾い、401/403 のレスポンスを `authz.decision=deny` にする

**所有者照合（IDOR 検知の核）は2通り。**

ルートモデルバインディングを使うなら、ミドルウェアだけで済む:
```php
// orders.user_id と現在のユーザーを比較。resource.type は 'order'
Route::get('/orders/{order}', [OrderController::class, 'show'])->middleware('authz.owner:order');
// 列名と resource.type を変える場合
Route::get('/teams/{team}', ...)->middleware('authz.owner:team,owner_id,team');
```

コントローラやリゾルバで ID から取得するなら、トレイト:
```php
use AuthzRadar\Laravel\ChecksOwnership;

class OrderController extends Controller {
    use ChecksOwnership;
    public function show(string $id) {
        $order = Order::findOrFail($id);
        $this->ensureOwns($order);              // orders.user_id を auth()->id() と比較
        return response()->json($order);
    }
}
```

**正当な他人アクセス**（管理者・サポート）は `config/authz-radar.php` の `bypass_abilities` に Gate の ability を列挙する。その経路は `authz.required_scope` に印が付き、D01 から除外される。

`config/authz-radar.php` の主な設定:
- `ownership_mode`: `observe`（穴を通して記録＝D01 を可視化。既存アプリの最初の段階）／ `enforce`（`deny_status`（既定 404）で遮断）
- `attributes`: `minimal`（S2）／ `full`（S3）
- `hmac_key`: 仮名化の鍵（**全サービスで同じ値**にすると同じユーザーを追える。無いとユーザー ID を送らない）
- `log_decisions`: High-security mode など属性を送れない環境と、ログのラストワンマイル（L04）向けに、決まった形の認可判断ログ行を出す

## 素の PHP（フレームワーク無し）

`AuthzRadar\Telemetry` を直接使う。1リクエスト（または WebSocket メッセージ・ジョブ）につき1インスタンス:
```php
require 'vendor/autoload.php';  // Composer を使わないなら instrumentation/php/autoload.php
use AuthzRadar\{Telemetry, NewRelicAgent, Pseudonymizer};

$t = new Telemetry(new NewRelicAgent(), new Pseudonymizer(getenv('AUTHZ_RADAR_HMAC_KEY')),
                   Telemetry::MINIMAL, Telemetry::OBSERVE);
$t->user($currentUserId);
$order = $db->loadOrder($_GET['id']);
$t->checkOwnership($order['user_id'], $currentUserId, 'order');   // observe なら false でも例外にしない
```

REST 以外（GraphQL・SOAP・JSON-RPC・WebSocket）は `$t->protocol('graphql', $serverSideOperationName)` を呼ぶ（`shared/protocols.md`）。**クライアントが付ける GraphQL の operation 名は使わない**（偽装できる）。1メッセージごとに `$t->reset()`。

## `newrelic.ini`（S0 と、ラストワンマイル）

```ini
newrelic.distributed_tracing_enabled = true        ; Span が無いと D07・D08・D20 が使えない
newrelic.transaction_tracer.record_sql = obfuscated ; 生 SQL には個人データが入り得る。off にはしない
newrelic.application_logging.forwarding.enabled = true ; 認可判断ログ（L04）を New Relic に送る
```

- **拒否をエラーにしない**ため、`notice_denials` は既定 false のまま（PHP に expected error が無いため）。もし他の経路で拒否を `newrelic_notice_error` に送っているなら、`newrelic.error_collector.ignore_exceptions` にそのクラスを足してエラー率を汚さないようにする。
- High-security mode（`newrelic.high_security = true`）ではカスタム属性・ユーザー属性を送れない。その場合は `log_decisions=true` にして認可判断ログ行で代用し、Readiness 監査で「属性ベース検知は不可」と判定する（L04）。

## テスト

`instrumentation/php/tests/TelemetryTest.php` を `php tests/TelemetryTest.php` で実行（エージェント不要。属性の送られ方を差し替えた記録器で確認）。実エージェントを入れたアプリでの確認は Phase 5。
