# Java 以外の言語の計装（S2）

> **PHP は専用ページ `instrumentation-php.md` を参照**（Laravel 12 統合・`newrelic.ini`・素の PHP）。以下は Python / Node.js / Ruby / Go / .NET 共通の最小ファイルの説明。

**目的**: 段階 S2（`resource.owner_match` と `authz.decision`）に到達する。Java は計装ライブラリがある（`instrumentation-java.md`）。
他の言語は、そのまま取り込める小さなファイルを `instrumentation/<言語>/` に置いている。

## 共通の使い方

クライアントが指定した ID でリソースを取得した **直後** に、所有者を照合する関数を呼ぶ。どの言語でも規則は同じ。

| 規則 | 内容 |
|---|---|
| 所有者が一致 | `owner_match = true`、`decision = allow` |
| 一致しない（enforce） | `owner_match = false`、`decision = deny`、expected error を記録して例外（403 / 404 に変換する） |
| 一致しない（observe） | `owner_match = false`、`decision = allow` → **D01 が反応する**（本当に起きている IDOR を見つける） |
| 正当な他人アクセス | `authz.required_scope` に印（例: `admin:read`）。D01 の除外条件 |
| 1リクエストで複数回 | 一致しないものが1件でもあれば `owner_match` は false のまま（後から true で上書きしない） |
| ユーザー | 秘密鍵付き HMAC で仮名化した `enduser.id`（`u_` + 16桁）。**鍵が無いと送らない**。全言語で同じ値になる |

最初は observe で動かし、D01 が正当なものだけになったら enforce に切り替える（`instrumentation-java.md` §2-4 と同じ）。

## 言語ごとの状況

| 言語 | ファイル | 確認した API（パッケージ） | テスト |
|---|---|---|---|
| Python | `instrumentation/python/authz_radar.py` | `newrelic.agent.add_custom_attribute`・`set_user_id`・`notice_error(expected=True)`（newrelic 14.1.0） | ✅ 単体テスト。実パッケージでの呼び出しも確認 |
| Node.js | `instrumentation/node/authz-radar.js` | `addCustomAttribute`・`setUserID`・`noticeError(err, attrs, expected)`（newrelic 14.8.0） | ✅ 単体テスト |
| Ruby | `instrumentation/ruby/authz_radar.rb` | `NewRelic::Agent.add_custom_attributes`・`set_user_id`・`notice_error(e, expected: true)`（newrelic_rpm 10.9.1） | ✅ 単体テスト |
| Go | `instrumentation/go/authzradar.go` | `txn.AddAttribute`・`SetUserID`・`NoticeExpectedError`（go-agent v3.45.0。**Go 1.25 以上**） | ✅ 単体テスト。本物の `*newrelic.Transaction` が必要な API を満たすこともコンパイル時に確認 |
| PHP | `instrumentation/php/`（Laravel 12 統合つき。別ページ **`instrumentation-php.md`**） | ✅ 関数名をエージェント 12.12.0 のソースで確認（`newrelic_add_custom_parameter`・`newrelic_set_user_id` 10.12+・`newrelic_notice_error`）。関数が無ければ何もしない | ✅ 単体テスト。Laravel 12・PHP 8.5.11 の脆弱デモ `examples/php-vuln-site` で実動作を確認 |
| .NET | `instrumentation/dotnet/AuthzRadar.cs` | `GetAgent().CurrentTransaction`・`AddCustomAttribute`・`SetUserId`・`NoticeError`（NewRelic.Agent.Api 10.56.0） | ❌ **未コンパイル**（ビルド環境に .NET SDK が無い） |

どの言語でも、テストは **New Relic の API を差し替えて** 行っている（エージェント無しで、どの属性がどう送られるかを確認）。
実際のエージェントを入れたアプリでの確認は Phase 5 で行う。

## REST 以外の方式

- **WebSocket**: どの言語でも、メッセージの処理をトランザクションの中で行う。そうしないと属性は捨てられる。各言語の方法は `shared/protocols.md` §3（Node.js `startWebTransaction`、Python `web_transaction` / `background_task`、Ruby `Tracer.in_transaction`、Go `app.StartTransaction`、.NET `[Transaction]`）。
- **GraphQL・SOAP・JSON-RPC・WebSocket**: `api.protocol` と、サーバー側で決まる `api.operation` を、各言語の属性 API で送る（例: Python `newrelic.agent.add_custom_attribute("api.operation", "Query.order")`）。
- 1回のリクエストで何度も所有者照合を行う方式（GraphQL のエイリアスなど）では、ファイルの `RequestState` を **リクエスト（またはメッセージ）単位で1つ** 使う。リゾルバごとに作り直すと、一致しなかったことが後の一致で上書きされる。

## 認可判断のログ行（任意）
High-security mode などで属性が送れない場合は、拒否したときと、所有者が違うのに通したときだけ、`shared/attribute-spec.md` の「認可判断のログ行」の形で1行出す（ユーザー ID は入れない）。
ログを New Relic に送り、トレース ID を付ける（各エージェントの Logs in context）と、`logs.nrql.md` の L04 で数えられる。

## expected error の扱い

拒否を expected error として送ると、Errors Inbox でまとまって見えつつ、エラー率や Apdex を悪化させない。

| 言語 | 方法 |
|---|---|
| Java・Python・Node.js・Ruby・Go | API の引数（または専用の関数）で expected を指定できる |
| .NET | API の引数では指定できなかった（確認できた範囲）。**エージェントの設定で、例外クラスを expected に指定する** |
| PHP | **expected を指定する仕組みが無い**（`newrelic.error_collector.ignore_exceptions` のみ）。そのため拒否は既定でエラーとして送らず、`authz.decision` 属性で検知する（`instrumentation-php.md`） |

## 確認する
```sql
SELECT count(*) FROM Transaction
WHERE appName = '{appName}' AND resource.owner_match IS NOT NULL
FACET name, resource.owner_match, authz.decision SINCE 1 hour ago
```
