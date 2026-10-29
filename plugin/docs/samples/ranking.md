| # | Priority | Tier | Endpoint | Type | Score (I×E) | Attack | Traffic (rpm) | Flags | First action | Standards |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | P1 | Critical | `GET /api/v0/members/{id}/profile` | F1 | 25 (5×5) | none | not observed | not_observed | fix | CWE-306 / ASVS V6 / ASVS V8 / A07 / A01 / API2 / IPA 1.11 / ATT&CK T1190 |
| 2 | P1 | Critical | `GET /api/v0/members/{id}/profile` | F4 | 25 (5×5) | none | not observed | not_observed | fix | CWE-639 / ASVS V8 / A01 / API1 / IPA 1.11 / ATT&CK T1190 |
| 3 | P1 | Critical | `GET /api/v1/products/search` | F7 | 20 (4×5) | none | not observed | not_observed | fix | CWE-89 / ASVS V1 / A05 / IPA 1.1 / ATT&CK T1190 |
| 4 | P1 | Critical | `GET /api/v0/members/{id}/profile` | F8 | 20 (5×4) | none | not observed | not_observed | fix | CWE-213 / CWE-770 / ASVS V14 / ASVS V2 / A06 / API3 / API4 / ATT&CK T1190 |
| 5 | P1 | Critical | `PUT /api/admin/users/{id}/role` | F5 | 20 (5×4) | none | not observed | not_observed | fix | CWE-285 / ASVS V8 / A01 / API5 / IPA 1.11 / ATT&CK T1190 / ATT&CK T1098 |
| 6 | P2 | High | `POST /api/v1/orders/{id}/cancel` | F3 | 12 (3×4) | none | not observed | not_observed | fix | CWE-863 / ASVS V8 / ASVS V10 / A01 / API5 / IPA 1.11 / ATT&CK T1190 |
| 7 | P2 | High | `GET /api/v1/orders/{id}` | F4 | 15 (3×5) | none | not observed | not_observed | fix | CWE-639 / ASVS V8 / A01 / API1 / IPA 1.11 / ATT&CK T1190 |
| 8 | P2 | High | `GRAPHQL Query.order` | F4 | 15 (3×5) | none | not observed | not_observed | fix | CWE-639 / ASVS V8 / A01 / API1 / IPA 1.11 / ATT&CK T1190 |
| 9 | P3 | Medium | `WS CONNECT /ws` | F12 | 5 (1×5) | none | not observed | not_observed | fix | CWE-1385 / CWE-613 / ASVS V4 / A01 / A07 / API2 / API8 / ATT&CK T1185 / ATT&CK T1550.004 |
| 10 | P3 | Medium | `GRAPHQL /graphql` | F11 | 4 (1×4) | none | not observed | not_observed, needs_review | fix | CWE-770 / CWE-200 / ASVS V4 / A06 / API4 / API8 / ATT&CK T1499.003 |
