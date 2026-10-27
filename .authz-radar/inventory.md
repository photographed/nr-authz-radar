# Go endpoint inventory (3 endpoints, 3 to read)

Candidates only. Read the flagged handlers (file:line) to confirm. Auth middleware that only
authenticates is not authorization.

| Endpoint | Handler | Authz mw | Flags | Location |
|---|---|---|---|---|
| `GET /api/orders/{id}` | `(inline/ref)` | **none** | query_by_id | `tests/fixtures/go-authz/handlers.go:13` |
| `GET /api/search` | `(inline/ref)` | **none** | sql_concat | `tests/fixtures/go-authz/handlers.go:20` |
| `POST /api/admin/orders/{id}/ship` | `(inline/ref)` | **none** | command_exec | `tests/fixtures/go-authz/handlers.go:26` |
