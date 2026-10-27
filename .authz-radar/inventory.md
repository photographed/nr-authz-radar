# PHP endpoint inventory (4 endpoints, 3 to read)

Candidates only. Read the flagged methods (file:line) to confirm. Middleware that is not an
authorization check (e.g. `throttle`) does not count as authorization.

| Endpoint | Handler | Middleware | Flags | Handler location |
|---|---|---|---|---|
| `GET /orders/{id}` | `OrderController@show` | auth | — | `examples/php-vuln-site/app/Http/Controllers/Api/OrderController.php:22` |
| `PATCH /orders/{id}/ship` | `AdminController@markShipped` | auth | find_by_id | `examples/php-vuln-site/app/Http/Controllers/Api/AdminController.php:18` |
| `GET /raw/orders/{id}` | `RawOrderController@show` | auth | find_by_id | `examples/php-vuln-site/app/Http/Controllers/Api/RawOrderController.php:22` |
| `GET /raw/orders` | `RawOrderController@search` | auth | sql_concat | `examples/php-vuln-site/app/Http/Controllers/Api/RawOrderController.php:28` |

## Raw SQL built by concatenation (possible SQL injection)

| Location |
|---|
| `examples/php-vuln-site/app/Http/Controllers/Api/RawOrderController.php:31` |
