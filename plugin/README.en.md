# nr-authz-radar

日本語: [README.md](README.md)

**A Claude Code plugin that notices API authorization attacks (IDOR / BOLA, SQL injection, and more) using New Relic, and audits API authorization in source code.**

When an app returns someone else's data (an IDOR), logs look just like normal traffic. This plugin has Claude read both your New Relic data and your source code to **find risky APIs, rank them, and surface leads for investigation**.

> Community project — not affiliated with or endorsed by New Relic.

## What it does

- **Code authorization review** — reads your source to find missing owner checks (IDOR), scope gaps, SQL-injection-prone spots, and more, ranked by risk. Works without New Relic.
- **Attack detection** — from New Relic APM data: authorization failures, SQL injection and RCE signals, authentication attacks, and automated suspicious access.
- **Evidence of a successful IDOR** — send two attributes from your app and it can catch "someone's data really was returned to the wrong user" (impossible from logs alone).
- **Alerts and notifications, prepared** — generates New Relic alerts, Slack messages and runbooks ready to use (people apply them).
- **Investigation help** — starts from the user, API and time window to trace what happened.

It deliberately avoids SIEM-style full-text log scanning for attack strings, to keep false positives down.

## Try it

```
/plugin marketplace add photographed/nr-authz-radar
/plugin install nr-authz-radar
```

Then just ask Claude in plain language: `Check New Relic for signs of attacks`, or `Review this repository's API authorization`.

**Start with [Getting started](docs/getting-started.en.md)** (installation, what is automatic, example requests, sample reports).

## What's inside

| Skill | Role |
|---|---|
| `nr-appsec-guard` | Runtime: readiness, usage, attack detection, investigation, instrumentation advice, alert / Slack generation |
| `api-authz-review` | Code: endpoints and scopes, IDOR/BOLA, BFLA, SQL injection and more, ranking corrected with real traffic |

## Documentation

The getting-started guide is available in English ([docs/getting-started.en.md](docs/getting-started.en.md)). The detailed reference docs ([concepts](docs/concepts.md), [how it works](docs/how-it-works.md), [reference](docs/reference.md), [coverage](docs/coverage.md)) are in Japanese; Claude reads them regardless of the language you ask in. See also [CHANGELOG.md](CHANGELOG.md).

## Status

Scripts and instrumentation code are tested. **NRQL, Terraform and Workflow Automation have not been validated against a real New Relic account yet** (Phase 5). 1.0.0 will be tagged on an explicit release decision.

## License

MIT
