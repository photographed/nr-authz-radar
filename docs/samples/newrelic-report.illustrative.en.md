# Sample: New Relic report (readiness + hunt)

> ⚠️ **Illustrative data.** This was written without a New Relic connection, so every count and percentage is made up for explanation.
> It shows the format (current data vs recommendations, "cannot determine" stated explicitly) and the reasoning.
> Only the last section, "Effect on the ranking", is real: `risk_score.py` was run on illustrative inputs
> ([`findings-with-newrelic.illustrative.json`](findings-with-newrelic.illustrative.json)).

Scenario: [`examples/sample-app/`](../../examples/sample-app/) is monitored with the Java agent. No custom attributes yet.

Example request: "Check shop-api in New Relic. What attacks can we notice today, and is anything happening now?"

---

## What the current data tells us

### Current stage and data sources
- **Stage: S0** (APM agent only; no `authz.decision`, `resource.owner_match` or `enduser.id` — R02)
- Data sources: APM ✅, distributed tracing ✅, Browser ✅, Logs ❌, Change Tracking ❌
- API styles (R15): REST, **GraphQL**, **WebSocket (handshakes with 101 exist, but no transactions for messages)**
- Autopilot / iRCA: off (R09, confirmed with the user)

### Status per goal
| Goal | Status | Why |
|---|---|---|
| ① Inventory | ⚠️ partial | REST transaction names are per API (R12 OK). GraphQL collapses into one endpoint, named after the client's operation name (spoofable) |
| ② Usage | ✅ | U01, U02, U03 run |
| ③ Detection | ⚠️ partial | Stage S0, so **D01 (evidence of a successful IDOR) cannot be determined**. D04, D06, D10, D12 and others run |
| ④ Investigation | ❌ mostly not possible | No logs (R14). Only about 62% of transactions are kept over the last day (R13, sampling) |

### Detection results
| Threat | Detection | Result | Notes |
|---|---|---|---|
| Successful IDOR | D01 | ❌ cannot determine | no `resource.owner_match` |
| ID enumeration | D03 | ❌ cannot determine | no `enduser.id` |
| Surge in 403/404 | D04 | ⚠️ `weak` | 404 ratio on `/api/v0/members/{id}/profile` is 2.6× normal (trying IDs in sequence hits missing IDs) |
| SQL injection | D06, D07 | `none` | no syntax errors or injected-looking statements (**this does not mean there is no vulnerability**: code review found F7) |
| Authentication failures | D10 | `none` | — |
| Calls that bypass the browser | D12 | ⚠️ `weak` | 100% of `/api/v0/...` calls have no trace parent (not called from the web or current app); normally 92% |
| RCE attempts | D21 | `none` | — |
| Denials on GraphQL / WebSocket | D22 | ❌ cannot determine | below S2. **D04 and D10 do not react on GraphQL or WebSocket**, so `none` above does not mean safe |

### Usage (excerpt)
| API | rpm | Caller (U03) | Note |
|---|---|---|---|
| `GET /api/v1/orders/{id}` | 120 | Browser 88% / Mobile 11% | main API |
| `GET /api/v1/products/search` | 40 | Browser 97% | |
| `GET /api/v0/members/{id}/profile` | 3.2 | **no parent 100%** | old API the current app should not use |
| `PUT /api/admin/users/{id}/role` | **0** (30 days) | — | unused |

### What we could not determine
- Whether the extra 404s and direct calls on the old API are **ID enumeration** (no `enduser.id`, so no per-user view; the API has no authentication anyway)
- **Whether other members' profiles were actually returned** (no stage S2 attributes, no logs)
- What happens over WebSocket messages (messages are not instrumented)

---

## Recommendations (step by step)

1. **Now**: shut down `/api/v0/**` (code review #1: member profiles including My Number are returned without authentication). Together with the D04 and D12 signals, it may already be enumerated
   → Goal: ③ / share with the relevant teams following your internal procedure for personal data
2. **Now**: before and after the shutdown, check the **responses returned with 200** on `/api/v0` in the load balancer or CDN logs (APM is sampled and has only part of them)
   → What you learn: how many profiles were returned / Goal: ④
3. **This week**: send logs (access logs, application logs) to New Relic
   → What you learn: investigations can be confirmed against every request (I04) / Goal: ④
4. **Next release**: the two stage S2 attributes (Java library, OBSERVE mode)
   → What you learn: D01 (evidence of a successful IDOR), D22 (denials that also work for GraphQL and WebSocket) / Goal: ③
5. **Next release**: make WebSocket messages transactions (the Java library handles STOMP automatically)
   → What you learn: access and IDOR over WebSocket / Goal: ②③
6. **Alerts**: generate the 3 alerts available at S0 with spans (evidence D07; strong signals D06, D21 — [`alerts-SKIPPED-S0.en.md`](alerts-SKIPPED-S0.en.md) lists the rest and what they need). Volume or ratio anomalies (D04, D10, …) are not notified because they produce many false positives. Regenerate after reaching S2 to add D01 (evidence) and D02 (strong)

## Effect on the ranking (real computation)

The code-review ranking was recomputed with the usage and signals above ([`ranking-with-newrelic.illustrative.md`](ranking-with-newrelic.illustrative.md)).

| Endpoint | Without New Relic | With New Relic | Why |
|---|---|---|---|
| `GET /api/v0/members/{id}/profile` (F1, F4, F8) | P1 | **P0** | attack signal (D04, D12 `weak`) × Critical |
| `PUT /api/admin/users/{id}/role` (F5) | P1 | P1, **`dormant_critical`** | zero traffic for 30 days → **first action becomes "disable or remove"** |
| `GET /api/v1/products/search` (F7) | P1 | P1 | no signal; traffic only orders items within the same tier |
