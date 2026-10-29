# Sample: code review report (`api-authz-review`)

> **This is real output.** Target: the intentionally vulnerable sample [`examples/sample-app/`](../../examples/sample-app/).
> Claude reviewed it following the `api-authz-review` steps; the ranking was computed by `scripts/risk_score.py`
> (input: [`findings.json`](findings.json), output: [`ranking.md`](ranking.md)). New Relic was not connected, so traffic is "not observed".

---

## What the current data tells us

### Summary
- Endpoints: **9** (REST 6, GraphQL 1, WebSocket 1, admin 1)
- Findings: **10** (P1: 5, P2: 3, P3: 2)
- **Top priority**: the old mobile API `GET /api/v0/members/{id}/profile` **returns any member's profile (including their My Number) to anyone, without authentication, just by changing the ID** (F1 + F4 + F8)
- New Relic is not connected, so every finding is `not_observed` (we do not know whether the APIs are used). Once connected, a Critical API with zero traffic gets "disable or remove" as its first action

### Ranking
| # | Priority | Tier | Endpoint | Type | Score (impact × exploitability) | Standards |
|---|---|---|---|---|---|---|
| 1 | P1 | Critical | `GET /api/v0/members/{id}/profile` | F1 no authentication | 25 (5×5) | CWE-306 / A07 / API2 |
| 2 | P1 | Critical | `GET /api/v0/members/{id}/profile` | F4 IDOR | 25 (5×5) | CWE-639 / A01 / API1 / IPA 1.11 |
| 3 | P1 | Critical | `GET /api/v1/products/search` | F7 SQL injection | 20 (4×5) | CWE-89 / A05 / IPA 1.1 |
| 4 | P1 | Critical | `GET /api/v0/members/{id}/profile` | F8 excessive data exposure | 20 (5×4) | CWE-213 / API3 |
| 5 | P1 | Critical | `PUT /api/admin/users/{id}/role` | F5 BFLA | 20 (5×4) | CWE-285 / API5 |
| 6 | P2 | High | `POST /api/v1/orders/{id}/cancel` | F3 wrong scope | 12 (3×4) | CWE-863 / API5 |
| 7 | P2 | High | `GET /api/v1/orders/{id}` | F4 IDOR | 15 (3×5) | CWE-639 / API1 |
| 8 | P2 | High | `GRAPHQL Query.order` | F4 IDOR | 15 (3×5) | CWE-639 / API1 |
| 9 | P3 | Medium | `WS CONNECT /ws` | F12 WebSocket | 5 (1×5) | CWE-1385 |
| 10 | P3 | Medium | `GRAPHQL /graphql` | F11 GraphQL (needs review) | 4 (1×4) | CWE-770 / API4 |

Within a tier, confirmed findings come first (that is why #6 ranks above #7).

### Details (top findings)

**#1, #2, #4 `GET /api/v0/members/{id}/profile` (F1, F4, F8 — confirmed)**
- Evidence: `config/SecurityConfig.java:16` opens `/api/v0/**` with `permitAll()`. `member/LegacyMemberController.java:21` returns `findById(id)` as is. `Member` has `myNumber`, `address` and `birthDate`, and the entity is returned directly
- Exploitability: no authentication, sequential IDs, discoverable by analyzing the mobile app (a technique named in JPCERT-AT-2026-0030)
- Score breakdown: impact 5 (sensitive_personal) × exploitability 5 (no auth +1, sequential +1, mobile +1, capped at 5)
- Fix:
  ```diff
  - .requestMatchers("/api/v0/**").permitAll()
  + .requestMatchers("/api/v0/**").denyAll()     // the current app uses /api/v1/me; shut v0 down
  ```
  If v0 must stay, require authentication and return only the caller's own data through a DTO (never `myNumber`)

**#3 `GET /api/v1/products/search` (F7 — confirmed)**
- Evidence: `search/SearchController.java:22` builds SQL by concatenating the search term `q`
- Score breakdown: impact 4 (SQL injection reaches the whole database, floor 4) × exploitability 5
- Fix:
  ```diff
  - jdbc.queryForList("SELECT id, name, price FROM product WHERE name LIKE '%" + q + "%'")
  + jdbc.queryForList("SELECT id, name, price FROM product WHERE name LIKE ?", "%" + q + "%")
  ```

**#5 `PUT /api/admin/users/{id}/role` (F5 — likely)**
- Evidence: `admin/AdminController.java:12` has no `@PreAuthorize`, and the URL rules only say `anyRequest().authenticated()`. **Any logged-in user can change roles**
- Fix: add `@PreAuthorize("hasAuthority('SCOPE_admin:write')")` and restrict `/api/admin/**` in the URL rules too

**#6 `POST /api/v1/orders/{id}/cancel` (F3 — confirmed)**
- Evidence: `order/OrderController.java:32-33`. A write (cancel) is allowed with the `orders:read` scope. The ownership check is there
- Fix: require `SCOPE_orders:write`

**#7, #8 `GET /api/v1/orders/{id}` and `GRAPHQL Query.order` (F4 — likely)**
- Evidence: `order/OrderController.java:23`, `order/OrderGraphQl.java:19`. Both use `findById(id)`. **`/receipt` in the same controller already uses `findByIdAndOwnerId`, so the pattern exists**
- Fix:
  ```diff
  - return orders.findById(id).orElseThrow();
  + return orders.findByIdAndOwnerId(id, me.getName()).orElseThrow();
  ```

**#9 `WS CONNECT /ws` (F12 — likely)** — `setAllowedOriginPatterns("*")` in `config/WebSocketConfig.java:13`. List the allowed origins
**#10 `GRAPHQL /graphql` (F11 — needs review)** — no introspection or depth limit settings found in the source. Check `application.yml` and similar

### Scope inventory (CSV)
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

### IDOR regression test
```java
@Test
void aliceCannotReadBobsOrder() throws Exception {
    mvc.perform(get("/api/v1/orders/{id}", BOBS_ORDER_ID).with(jwt().jwt(j -> j.subject("alice"))
            .authorities(new SimpleGrantedAuthority("SCOPE_orders:read"))))
       .andExpect(status().isNotFound());   // 403 is fine too; 404 avoids revealing that it exists
}
```

### What we could not determine
- Whether the APIs are used (New Relic not connected). Whether `/api/v0` still receives traffic changes the first action (shut down vs fix)
- GraphQL settings (F11) may live outside the source (configuration files)

---

## Recommendations (step by step)

1. **Today**: shut down `/api/v0/**` (#1, #2, #4). Member profiles including My Number can be read without authentication by changing the ID. **Before shutting it down, check past access (responses returned with 200) with ④ investigation**
   → Goal: ③ detection, ④ investigation / What you learn: whether data has already been taken
2. **This week**: fix the SQL injection (#3) and the admin API authorization (#5)
3. **Next release**: use `findByIdAndOwnerId` for the order IDORs (#7, #8), fix the cancel scope (#6), restrict WebSocket origins (#9)
4. **Instrumentation (stage S2)**: add `@CheckOwnership(type = "order")` to the data access for the IDOR candidates (#7, #8) and ship it **in OBSERVE mode first**
   → What you learn: **whether other people's orders are actually being returned before the fix (D01)** / Goal: ③ detection
5. **Connect New Relic and run again**: traffic and attack signals adjust the ranking (a Critical API with zero traffic gets "disable" as the recommendation)
