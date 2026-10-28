# Getting started: installation and usage

日本語: [getting-started.md](getting-started.md)

## 1. The big picture

This repository is a **Claude Code plugin**. It contains instructions (Skills) that tell Claude what to check, in what order and how to judge it,
scripts that do the fixed calculations, templates for New Relic configuration, and **code you add to your own application**.

```
You ── "Review the authorization of our APIs" / "Check New Relic for attack signals"
  │
  ▼
Claude Code ── reads the Skill (instructions)
  ├─ reads your source code ........... code review
  ├─ runs NRQL against New Relic ...... through the New Relic MCP (Ground Truth), read-only
  ├─ runs scripts ..................... ranking, alert generation, XML candidates
  └─ writes the report and files
  │
  ▼
You ── read the report, review the files (configuration, patches) and **apply them yourself**
```

### What each folder is for

| Folder | Contents | Used by |
|---|---|---|
| `skills/` | Instructions for Claude: `api-authz-review` (code review) and `nr-appsec-guard` (readiness, detection, investigation, instrumentation advice and alert generation with New Relic) | Claude |
| `shared/` | Shared specifications (attributes, goals and stages, data sources, API styles, ranking, privacy, standards mapping). Written in Japanese; Claude reads them in any language | Claude and people |
| `scripts/` | Deterministic tools: `risk_score.py` (ranking), `gen_alerts.py` (alerts), `hunt.py` (detections via NerdGraph, no AI), `inventory_{java,php,python,node,ruby,go}.py` (endpoint inventory), `catalog.py` (print only the sections you need), `gen_xml_candidates.py` (XML candidates), `attack_layer.py` (ATT&CK layer), `ip_reputation.py` (IP reputation, local) | **Run by Claude** (you can run them too) |
| `templates/` | Templates for New Relic (Terraform, Workflow Automation, Slack, Autopilot prompt, runbooks) | Filled in by Claude → **applied by you** |
| `instrumentation/` | **Code you add to your application**: a Java library, and small files for Python, Node.js, Ruby, Go, PHP and .NET | **Developers** (Claude does not run it; it proposes patches that use it) |
| `examples/`, `docs/samples/` | A sample application, and real outputs and example reports | People |

### What is automatic and what you do

| Task | Who | Notes |
|---|---|---|
| Read the source code and find issues | **Claude (automatic)** | |
| Query New Relic | **Claude (automatic)** | read-only |
| Compute the ranking | **Claude runs a script (automatic)** | same input, same order, every time |
| Write the report | **Claude (automatic)** | keeps "what the current data tells us" and "recommendations" apart |
| Create alert Terraform, XML and fix patches | **Claude (automatic)** | written as files only |
| **Apply to New Relic** (`terraform apply` etc.) | **You** | the Skills never change New Relic configuration |
| **Add to your application** (patches, instrumentation) | **You** (developers) | the Skills never rewrite your code; they propose patches |
| Create the Slack destination | **You** | needs OAuth in the New Relic UI |

## 2. Installation

### Requirements
- Claude Code (CLI, desktop app or web)
- Python 3.10 or later (for the scripts; no extra packages)
- A New Relic account (only for the New Relic features; code review works without it)

### Option A: Claude Code on your machine (CLI, desktop)
```text
/plugin marketplace add photographed/nr-authz-radar
/plugin install nr-authz-radar@nr-authz-radar
```
Connect to New Relic (OAuth in the browser the first time):
```text
/mcp
```
Pick `newrelic-us` and authenticate. For a **JP region** account, look up the JP MCP endpoint in the official docs and add it:
```bash
claude mcp add --transport http newrelic-jp <JP region MCP endpoint URL>
```

### Option B: Claude Code on the web (cloud sessions)
1. Add the New Relic MCP as a **connector** (Connectors settings on claude.ai; URL `https://mcp.newrelic.com/mcp/`, OAuth). Connectors load when a session starts, so start a new session afterwards
2. Allow `mcp.newrelic.com` in the cloud environment's network access settings
3. Register the marketplace and plugin in `.claude/settings.json` of the repository you work on (check the key names in the Claude Code docs):
   ```json
   {
     "extraKnownMarketplaces": {
       "nr-authz-radar": { "source": { "source": "github", "repo": "photographed/nr-authz-radar" } }
     },
     "enabledPlugins": { "nr-authz-radar@nr-authz-radar": true }
   }
   ```

### Check that it works
Ask Claude "What can nr-authz-radar do?". If it describes the two Skills (`api-authz-review`, `nr-appsec-guard`), they are loaded.

## 3. Usage (example requests)

Ask in plain language; Claude picks the right Skill. **Ask in English and the output is in English** (Japanese in, Japanese out).

| You want to | Example request | What Claude does | Output (samples) |
|---|---|---|---|
| **Review code** (① inventory) | "Review the authorization of the APIs in this repository and rank the issues" | inventories endpoints and scopes → finds issues → ranks them with `risk_score.py` | [code review report](samples/code-review-report.en.md), [ranking](samples/ranking.md) |
| **Check readiness** | "For the New Relic app shop-api, what attacks can we notice today?" | runs R01–R15 and decides the stage (S0–S3) and data sources | [New Relic report (illustrative)](samples/newrelic-report.illustrative.en.md) |
| **Hunt for attack signals** (③) | "Check shop-api for signs of IDOR or SQL injection in the last 24 hours" | runs only the detections (D01–D23) the current stage supports | same as above |
| **Understand usage** (②) | "Show API usage for shop-api and the APIs nobody uses" | runs U01–U06 and compares with the code | — |
| **Investigate** (④) | "Investigate pseudonymous user u_3f9a… between 10:00 and 12:00 yesterday" | first checks what was recorded (I05–I07), then I01–I04 | — |
| **Create alerts** | "Generate the alerts we can use at our current stage as Terraform" | runs `gen_alerts.py`; lists what it could not create and why | [alerts not generated](samples/alerts-SKIPPED-S0.en.md), [Terraform excerpt](samples/alerts-excerpt-S0.tf) |
| **Instrumentation patches** | "Create patches that add instrumentation to the IDOR candidates" | proposes `@CheckOwnership` (or the per-language function) patches | "Recommendations" in the code review report |
| **XML candidates** (no code change) | "Suggest XML instrumentation for our authorization check methods" | runs `gen_xml_candidates.py` | [XML candidates](samples/xml-candidates.en.md) |

**When to use it** (cadence): see "When to use" in the README. The single most effective moment is **code review before a PR or release**.

### About the samples
- [`docs/samples/code-review-report.en.md`](samples/code-review-report.en.md) — **real output** (review of `examples/sample-app/`)
- [`docs/samples/newrelic-report.illustrative.en.md`](samples/newrelic-report.illustrative.en.md) — **illustrative data** (no New Relic connection); only the ranking effect is a real computation

## 4. Adding `instrumentation/` to your application

Only the application knows whether an IDOR succeeded. Add the code that sends **`resource.owner_match` and `authz.decision`**, and D01 (evidence of a successful IDOR) becomes available (stage S2).

| Language | How |
|---|---|
| Java (Spring Boot) | build `instrumentation/java/`, add it as a dependency, put `@CheckOwnership(type = "order")` on the data-access method. Details (Japanese): [`instrumentation-java.md`](../skills/nr-appsec-guard/references/instrumentation-java.md), English summary: [`instrumentation/java/README.md`](../instrumentation/java/README.md) |
| Python, Node.js, Ruby, Go, PHP, .NET | copy the file in `instrumentation/<language>/` into your project and call the check function right after loading the resource. Details (Japanese): [`instrumentation-other-languages.md`](../skills/nr-appsec-guard/references/instrumentation-other-languages.md); each file has English comments |

Ship it in **OBSERVE mode** first (record only), confirm what real IDORs look like, then switch to ENFORCE (deny).

## 5. Running the scripts directly (without Claude)

```bash
# ranking
python3 scripts/risk_score.py docs/samples/findings.json --format md

# alerts for your stage and data sources (--lang en for an English report)
python3 scripts/gen_alerts.py --stage S0 --sources spans --out out/terraform --lang en

# XML instrumentation candidates
python3 scripts/gen_xml_candidates.py path/to/src/main/java --xml out/authz-extension.xml --report out/xml-candidates.md --lang en
```

### Scheduled runs (hunts without AI)
```bash
export NEW_RELIC_API_KEY=...   # a User key
python3 scripts/hunt.py --app shop-api --account-id 1234567 --stage S2 --sources spans --levels evidence,strong --lang en
# output: .authz-radar/hunt/hunt-summary.md (summary grouped by evidence level)
```
Run it from cron or CI. You can let Claude read the summary to interpret it (cheap, because it is short).

## 6. FAQ

| Question | Answer |
|---|---|
| Does it change my New Relic configuration? | No. Queries are read-only and configuration is only written to files |
| Does it rewrite my code? | No. Fixes are proposed as patches |
| Can I use it without New Relic? | Yes, code review (`api-authz-review`) works on its own. With New Relic, usage and attack signals adjust the ranking |
| Is it useless without custom attributes? | No. Much works at stage S0 (inventory, usage, SQL injection and RCE signals, and more). **Only evidence of a successful IDOR needs the two stage S2 attributes** |
| What about GraphQL, WebSocket and others? | Supported, but status-code based detections are REST-only. Details: [`shared/protocols.md`](../shared/protocols.md) (Japanese) |
| Can I use it in English? | Yes. Ask in English and Claude answers in English. Script reports take `--lang en`. The reference specs are in Japanese, which Claude reads fine |
| Does it use logs? | As the last mile only. **Never scanned**: fetched within the scope of APM evidence (trace ID, user, time window) — L01–L04 |
| Won't it produce lots of false positives? | Results are split by evidence level. Only *evidence* (D01, D07) and *strong signals* notify; volume or ratio *anomalies* do not notify by default. See [`docs/how-it-works.md`](how-it-works.md) (Japanese) |
| What about cost? | Scheduled hunts use `hunt.py` without AI; Autopilot is called only from evidence-level alerts. See [`shared/cost.md`](../shared/cost.md) (Japanese) |
| How well is it validated? | Scripts and instrumentation code are tested. **NRQL, Terraform and Workflow Automation have not been validated against a real New Relic account yet** (planned in Phase 5) |
