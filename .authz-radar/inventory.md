# Node.js endpoint inventory (5 endpoints, 2 to read)

Candidates only. Read the flagged handlers (file:line) to confirm. Middleware that only
authenticates (requireAuth, passport) is not authorization. Next.js `middleware.ts` runs on
the Edge runtime and is not instrumented — check owner rules in the route handler.

| Endpoint | Handler | Authz mw | Flags | Location |
|---|---|---|---|---|
| `GET /api/orders/[id]` | `route.js:GET` | yes | — | `tests/fixtures/node-authz/app/api/orders/[id]/route.js:13` |
| `GET /api/orders/:id` | `(inline)` | yes | find_by_id | `tests/fixtures/node-authz/routes/orders.js:7` |
| `GET /api/orders/:id/receipt` | `(inline)` | yes | — | `tests/fixtures/node-authz/routes/orders.js:13` |
| `GET /api/search` | `(inline)` | **none** | sql_concat | `tests/fixtures/node-authz/routes/orders.js:19` |
| `POST /api/admin/orders/:id/ship` | `(inline)` | yes | — | `tests/fixtures/node-authz/routes/orders.js:26` |
