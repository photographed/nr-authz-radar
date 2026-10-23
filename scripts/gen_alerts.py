#!/usr/bin/env python3
"""Generate New Relic alert conditions (Terraform) for the current stage and data sources.

Only alerts that can work with what the account has today are generated. The rest are listed
in SKIPPED.md with what would enable them, so reports can keep "what works now" and
"recommendations" apart (shared/goals.md).

Usage:
  python3 scripts/gen_alerts.py --stage S2 --sources spans,browser_dt --out out/terraform
"""
from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CATALOG = ROOT / "shared" / "alerts.json"
STATIC = ROOT / "templates" / "terraform"
STAGES = ["S0", "S1", "S2", "S3"]
SOURCES = {"spans": "分散トレーシング（Span）", "browser_dt": "Browser + 分散トレーシング"}
SOURCES_EN = {"spans": "distributed tracing (spans)", "browser_dt": "Browser + distributed tracing"}
TEXT = {
    "ja": {"title": "# 生成しなかったアラート（現在の段階: {stage}）",
           "rec": "## 推奨: これを満たすと追加できるアラート",
           "head": "| 検知 | 名前 | 必要なこと |", "none": "| — | — | なし |",
           "hunt": "## アラートにしない検知（Hunt で確認する）", "hunt_head": "| 検知 | 理由 |",
           "stage": "段階 {need} が必要（現在 {stage}）", "source": "データソースが必要: "},
    "en": {"title": "# Alerts not generated (current stage: {stage})",
           "rec": "## Recommendations: alerts you can add once these are in place",
           "head": "| Detection | Name | Needs |", "none": "| — | — | none |",
           "hunt": "## Detections that are not alerts (run them in Hunt)", "hunt_head": "| Detection | Why |",
           "stage": "stage {need} (now {stage})", "source": "data source: "},
}
DEFAULT_RUNBOOK_BASE = "https://github.com/photographed/nr-authz-radar/blob/main/templates/knowledge-runbooks"
PLACEHOLDERS = {"{appName}": "${var.app_name}", "{bypassScopePattern}": "${var.bypass_scope_pattern}"}


def hcl_string(text: str) -> str:
    """Quote a literal for HCL: escape quotes/backslashes and template sequences (${ and %{)."""
    escaped = text.replace("\\", "\\\\").replace('"', '\\"').replace("${", "$${").replace("%{", "%%{")
    return f'"{escaped}"'


def nrql_expression(nrql: str) -> str:
    quoted = hcl_string(nrql)
    for placeholder, ref in PLACEHOLDERS.items():
        quoted = quoted.replace(placeholder, ref)
    return quoted


def threshold_block(kind: str, t: dict, window: int) -> str:
    return (f"  {kind} {{\n"
            f"    operator              = \"{t['operator']}\"\n"
            f"    threshold             = {t['threshold']}\n"
            f"    threshold_duration    = {window}\n"
            f"    threshold_occurrences = \"at_least_once\"\n"
            f"  }}\n")


def condition(alert: dict) -> str:
    rid = alert["id"].lower()
    window = alert["window_seconds"]
    lines = [
        f'resource "newrelic_nrql_alert_condition" "{rid}" {{',
        "  account_id                   = var.account_id",
        "  policy_id                    = newrelic_alert_policy.authz_radar.id",
        f'  type                         = "{alert["type"]}"',
        f'  name                         = {hcl_string("[authz-radar] " + alert["id"] + " " + alert["name"])}',
        f'  description                  = {hcl_string("nr-authz-radar " + alert["id"] + " / stage " + alert["stage"])}',
        f'  runbook_url                  = "${{var.runbook_base_url}}/{alert["runbook"]}"',
        "  enabled                      = true",
        "  violation_time_limit_seconds = 86400",
        f"  aggregation_window           = {window}",
        '  aggregation_method           = "event_flow"',
        "  aggregation_delay            = 120",
    ]
    if alert["type"] == "baseline":
        lines.append('  baseline_direction           = "upper_only"')
    lines += ["", "  nrql {", f"    query = {nrql_expression(alert['nrql'])}", "  }", ""]
    body = "\n".join(lines) + "\n"
    for kind in ("critical", "warning"):
        if kind in alert:
            body += threshold_block(kind, alert[kind], window)
    return body + "}\n"


def select(alerts: list[dict], stage: str, sources: set[str], lang: str = "ja") -> tuple[list[dict], list[tuple[dict, str]]]:
    t, names, sep = TEXT[lang], (SOURCES if lang == "ja" else SOURCES_EN), ("、" if lang == "ja" else ", ")
    chosen, skipped = [], []
    for a in alerts:
        if STAGES.index(a["stage"]) > STAGES.index(stage):
            skipped.append((a, t["stage"].format(need=a["stage"], stage=stage)))
        elif missing := [s for s in a["requires"] if s not in sources]:
            skipped.append((a, t["source"] + sep.join(names[s] for s in missing)))
        else:
            chosen.append(a)
    return chosen, skipped


def skipped_report(skipped: list[tuple[dict, str]], hunt_only: dict, stage: str, lang: str = "ja") -> str:
    t = TEXT[lang]
    name = (lambda a: a["name"]) if lang == "ja" else (lambda a: a.get("name_en", a["name"]))
    out = [t["title"].format(stage=stage), "", t["rec"], "", t["head"], "|---|---|---|"]
    out += [f"| {a['id']} | {name(a)} | {why} |" for a, why in skipped] or [t["none"]]
    out += ["", t["hunt"], "", t["hunt_head"], "|---|---|"]
    out += [f"| {k} | {v if lang == 'ja' else HUNT_ONLY_EN.get(k, v)} |" for k, v in hunt_only.items()]
    return "\n".join(out) + "\n"


HUNT_ONLY_EN = {
    "D05": "needs stage S3 attributes and thresholds differ widely between organizations",
    "D08": "needs a comparison with the normal period (COMPARE WITH), which alerts cannot do",
    "D09": "looks at the shape of a distribution (two peaks), not a simple threshold",
    "D13": "uses a nested query, likely unsupported in alert conditions",
    "D14": "needs a comparison with the normal period",
    "D15": "a configuration risk, not an attack signal (better in a periodic report)",
    "D17": "needs 'first seen' (earliest), which alerts cannot do",
    "D18": "a reference query for correlation",
    "D20": "needs 'first seen destination' (earliest); run it in Hunt when D21 fires",
}


def generate(stage: str, sources: set[str], out: Path, lang: str = "ja") -> tuple[list[dict], list[tuple[dict, str]]]:
    catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
    chosen, skipped = select(catalog["alerts"], stage, sources, lang)
    out.mkdir(parents=True, exist_ok=True)
    for f in STATIC.glob("*.tf"):
        shutil.copy(f, out / f.name)
    header = (f"# Generated by scripts/gen_alerts.py --stage {stage} --sources {','.join(sorted(sources)) or '-'}\n"
              "# Do not edit by hand: change shared/alerts.json and regenerate.\n\n")
    (out / "alerts.tf").write_text(header + "\n".join(condition(a) for a in chosen), encoding="utf-8")
    (out / "SKIPPED.md").write_text(skipped_report(skipped, catalog["hunt_only"], stage, lang), encoding="utf-8")
    return chosen, skipped


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--stage", choices=STAGES, required=True)
    ap.add_argument("--sources", default="", help="comma separated: " + ", ".join(SOURCES))
    ap.add_argument("--out", required=True)
    ap.add_argument("--lang", choices=["ja", "en"], default="ja", help="language of SKIPPED.md")
    args = ap.parse_args()
    sources = {s for s in args.sources.split(",") if s}
    unknown = sources - set(SOURCES)
    if unknown:
        ap.error(f"unknown sources: {', '.join(sorted(unknown))}")
    chosen, skipped = generate(args.stage, sources, Path(args.out), args.lang)
    print(f"generated {len(chosen)} alert conditions, skipped {len(skipped)} (see SKIPPED.md)")


if __name__ == "__main__":
    main()
