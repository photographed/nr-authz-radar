# nr-authz-radar

日本語: [README.md](README.md)

**A Claude Code plugin that notices and ranks IDOR / BOLA, SQL injection, RCE and AI-agent-like API attacks using New Relic Ground Truth (MCP), and audits API authorization in source code.**

> Community project — not affiliated with or endorsed by New Relic.

**New here? Start with [Getting started](docs/getting-started.en.md)** (installation, what is automatic, example requests, sample reports).

## Why not a SIEM?

A successful IDOR returns **200 OK**. Collecting and correlating logs only shows "normal traffic".
To get **evidence** of a successful IDOR, the application itself must report whose data it touched (two attributes are enough).
Most other things — API inventory, usage, SQL injection and RCE signals, authentication attacks — work **with just the APM agent installed**.

## What is integrated today

| New Relic capability | Status | Notes |
|---|---|---|
| APM (Transaction, TransactionError), distributed tracing (Span) | ✅ used | the basis of detection, usage and investigation |
| Browser | ⚠️ partial | `AjaxRequest` (U02), browser-originated trace parents (`parent.type`, D12, U03), **users calling APIs without any browser session (D24)**; `JavaScriptError` and others unused |
| Logs (Logs in context, access logs) | ✅ last mile | **never scanned**; fetched only within the scope of APM evidence (trace ID, user, time window) — L01–L04, R16 |
| Errors Inbox | ⚠️ indirect | uses `TransactionError`, its underlying data (D06, D17, D21). **Error group states (unresolved / resolved / ignored) are not integrated yet** (design: [`shared/inbox-integration.md`](shared/inbox-integration.md), Japanese) |
| Performance Risks Inbox | ❌ not implemented | the security reading of each risk type is designed (same file); implementation waits until the data access can be checked against a real account |
| Autopilot, iRCA | ⚠️ draft | called from a Workflow Automation draft (unvalidated) |

## Four goals

| Goal | Question | With APM only (stage S0) | What the recommendations add |
|---|---|---|---|
| **① Inventory** | How many APIs do we have, and how is each one authorized? | **All of the code review** (no New Relic needed); comparison with observed APIs | Per-API transaction names make the comparison exact |
| **② Usage** | Which APIs are used, from where, how much? | Requests, status codes and callers (browser / mobile / direct) per API | S1: per-user usage |
| **③ Detection** | Are we being attacked right now? | 403/404 surges, SQL injection and RCE signals, authentication failure surges, calls that bypass the browser, new outbound destinations | S1: ID enumeration, **S2: evidence of a successful IDOR**, S3: scope misuse, API key anomalies |
| **④ Investigation** | What was done, and what data was taken (including 200 responses)? | Timeline, APIs touched, paths returned with 200 (**partial: APM may sample**) | Logs for **complete** answers, longer retention |

### Stages (how much you instrument the application)

| Stage | What you do | What you get |
|---|---|---|
| **S0** | Install the APM agent (with distributed tracing) | the "APM only" column above |
| **S1** | Send a pseudonymous `enduser.id` | per-user usage, detection and investigation |
| **S2** | **Two attributes: `resource.owner_match` and `authz.decision`** (+ `api.protocol` / `api.operation` for non-REST APIs) | **Evidence of a successful IDOR (D01)** — the only code-level instrumentation that is truly required |
| **S3** | The remaining attributes | scope misuse, API key anomalies, token lifetime, and more |

**Every report keeps "what the current data tells us" and "recommendations" in separate sections.** Each recommendation states what it lets you see and which goal it serves.

## What's inside

| Part | Description |
|---|---|
| `api-authz-review` (Skill) | Code review: endpoints and scopes (REST, GraphQL, SOAP, gRPC, WebSocket), IDOR/BOLA, BFLA, mass assignment, SQL injection, OS command injection, unsafe deserialization, GraphQL and WebSocket hardening; deterministic ranking |
| `nr-appsec-guard` (Skill) | With New Relic: readiness (R01–R15), usage (U01–U06), detection (D01–D23), investigation (I01–I07), instrumentation advice, alert / Workflow Automation / Slack generation; adapts to Autopilot and iRCA being on or off |
| `instrumentation/` | Code for your application: a Java (Spring Boot / Spring Security) library for REST, GraphQL and STOMP, tested on Spring Boot 3.5 and 4.1; small files for Python, Node.js, Ruby, Go (tested), PHP (API names unverified) and .NET (not compiled). Pseudonymous user IDs are identical across all languages |
| `scripts/` | `risk_score.py` (ranking), `gen_alerts.py` (Terraform routed by evidence level; `--lang en`), `hunt.py` (detections via NerdGraph, no AI), `inventory_java.py` (endpoint inventory), `catalog.py` (read only what you need), `gen_xml_candidates.py` (Java agent XML candidates) |
| `templates/` | Terraform, Workflow Automation (draft), Slack message format, Autopilot prompt, six New Relic Knowledge runbooks |

## Logs as the last mile

**Logs are never scanned.** Starting from APM evidence (trace ID, user, time window), the plugin fetches only the lines it needs: L01 the log lines behind a D01 (whose record was returned), L02 the full set of accesses for an investigation (query strings APM does not record, requests lost to sampling), L03 requests blocked at the edge, L04 structured authorization log lines where custom attributes cannot be sent (high-security mode). For CRITICAL evidence, Workflow Automation fetches the L01 lines (`logsEnabled`). The Java library can write those structured lines (`log-decisions: true`, no user IDs). Readiness check R16 verifies that logs carry trace IDs.

## False positives, cost and tokens

**Evidence levels.** Every detection is labelled *evidence* (D01: the app returned someone else's data; D07: an injected-looking SQL statement ran), *strong signal* (D02, D06, D21, D23) or *anomaly* (D03, D04, D10, D12, …). Only evidence pages (CRITICAL, and may call Autopilot); strong signals go to a quiet channel and stay muted during a learning period; anomalies are not generated as alerts by default and are never called attacks. Like IAST, the evidence level relies on what the application itself observed, not on traffic patterns.

**Cost.** Scheduled hunts run through `scripts/hunt.py` (NerdGraph, no AI): a light daily run (`--levels evidence,strong`, up to 7 queries) and a full weekly run (up to 21). Use the Ground Truth MCP for interactive investigation with its NRQL tools only; Autopilot is called only from evidence-level alerts. Pricing depends on your contract — see [`shared/cost.md`](shared/cost.md) (Japanese) for what to confirm with New Relic.

**Tokens.** Short SKILL.md routers (24.5KB → 9.4KB), `catalog.py` (read only the sections you need; the index is 2.4KB versus 40.7KB of catalogs), `hunt.py` summaries, `inventory_java.py` (read only flagged methods; `--changed-since` for PRs) and reusable work files in `.authz-radar/`.

```bash
NEW_RELIC_API_KEY=... python3 scripts/hunt.py --app shop-api --account-id 1234567 --stage S2 --sources spans --levels evidence,strong --lang en
python3 scripts/inventory_java.py src/main/java --changed-since origin/main
python3 scripts/catalog.py index --stage S2 --lang en
```

## How the ranking works

```
priority = inherent risk (from code, the main axis) + attack signal (lifts to P0) + traffic (orders items within a tier only)
```

Unused but critical APIs stay at the top (attackers like forgotten APIs), and get "disable or remove" as the first action.
The ranking is computed by a script, so the same input always gives the same order.

## Coverage (summary)

| Standard | Strong | Partial | Out of scope |
|---|---|---|---|
| OWASP Top 10:2025 | A01 Broken Access Control, A09 Logging and Alerting Failures | A05 (SQL / OS command injection, RCE signals), A07, A02, A06, A08 (deserialization), A10 | A03, A04 |
| OWASP API Top 10:2023 | API1 BOLA, API5 BFLA | API2, API3, API4, API6, API8, API9 | API7 SSRF, API10 |
| Others | CWE on every finding | ASVS 5.0 (chapter level), OWASP OAT (automation), IPA "安全なウェブサイトの作り方", CIS Controls v8 (reference only), MITRE ATT&CK v20.0 (all findings and detections; plugin's interpretation) | CIS Benchmarks, OWASP LLM / Agentic Top 10 (they protect your own AI apps, the opposite direction) |

MITRE ATT&CK: IDOR, SQLi and broken authorization all map to T1190 (ATT&CK does not distinguish vulnerability classes; use CWE / OWASP for that). Enumeration maps to T1119, scanning to T1595, credential stuffing to T1110.004, stolen tokens to T1550.001. To see what you can notice at your stage in ATT&CK Navigator:

```bash
python3 scripts/attack_layer.py --stage S2 --sources spans --findings --out .authz-radar/attack-layer.json
```

Details (Japanese): the "対応範囲" section of [README.md](README.md) and [`shared/standards.json`](shared/standards.json).

## Principles

- **Generate only**: New Relic configuration and application changes are written as files or patches; people apply them.
- **No overclaiming**: "AI agent attack" is reported as automation-like behaviour with evidence; uncertain code findings are marked `needs_review`.
- **Data minimization**: IP addresses are not sent to New Relic by default (personal data under GDPR, possibly "personal-related information" under Japan's APPI). IP-level analysis is left to the WAF / CDN. See [`shared/privacy.md`](shared/privacy.md) (Japanese).

## Status

Version **0.13.0**. Scripts and instrumentation code are tested. **NRQL queries, Terraform and Workflow Automation have not been validated against a real New Relic account yet** (Phase 5). 1.0.0 will be tagged on an explicit release decision. See [CHANGELOG.md](CHANGELOG.md) (Japanese).

## Language

Ask Claude in English and the output is in English. The reference specifications under `shared/` and `skills/` are written in Japanese; Claude reads them regardless of the language you use.

## License

MIT
