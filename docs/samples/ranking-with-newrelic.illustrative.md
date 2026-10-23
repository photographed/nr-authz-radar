| # | Priority | Tier | Endpoint | Type | Score (I×E) | Attack | Traffic (rpm) | Flags | First action | Standards |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | P0 | Critical | `GET /api/v0/members/{id}/profile` | F1 | 25 (5×5) | weak | 3.2 | - | fix | CWE-306 / ASVS V6 / ASVS V8 / A07 / A01 / API2 / IPA 1.11 |
| 2 | P0 | Critical | `GET /api/v0/members/{id}/profile` | F4 | 25 (5×5) | weak | 3.2 | - | fix | CWE-639 / ASVS V8 / A01 / API1 / IPA 1.11 |
| 3 | P0 | Critical | `GET /api/v0/members/{id}/profile` | F8 | 20 (5×4) | weak | 3.2 | - | fix | CWE-213 / CWE-770 / ASVS V14 / ASVS V2 / A06 / API3 / API4 |
| 4 | P1 | Critical | `GET /api/v1/products/search` | F7 | 20 (4×5) | none | 40.0 | - | fix | CWE-89 / ASVS V1 / A05 / IPA 1.1 |
| 5 | P1 | Critical | `PUT /api/admin/users/{id}/role` | F5 | 20 (5×4) | none | 0 | dormant_critical | disable_or_remove | CWE-285 / ASVS V8 / A01 / API5 / IPA 1.11 |
| 6 | P2 | High | `POST /api/v1/orders/{id}/cancel` | F3 | 12 (3×4) | none | 2.0 | - | fix | CWE-863 / ASVS V8 / ASVS V10 / A01 / API5 / IPA 1.11 |
| 7 | P2 | High | `GET /api/v1/orders/{id}` | F4 | 15 (3×5) | none | 120.0 | - | fix | CWE-639 / ASVS V8 / A01 / API1 / IPA 1.11 |
| 8 | P2 | High | `GRAPHQL Query.order` | F4 | 15 (3×5) | none | 15.0 | - | fix | CWE-639 / ASVS V8 / A01 / API1 / IPA 1.11 |
| 9 | P3 | Medium | `WS CONNECT /ws` | F12 | 5 (1×5) | none | not observed | not_observed | fix | CWE-1385 / CWE-613 / ASVS V4 / A01 / A07 / API2 / API8 |
| 10 | P3 | Medium | `GRAPHQL /graphql` | F11 | 4 (1×4) | none | 15.0 | needs_review | fix | CWE-770 / CWE-200 / ASVS V4 / A06 / API4 / API8 |
