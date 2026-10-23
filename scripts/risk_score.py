#!/usr/bin/env python3
"""Deterministic risk ranking for nr-authz-radar findings.

Claude extracts *features* from source code and New Relic; this script turns
them into a reproducible ranking. Same input -> same order, every time.

Spec: shared/risk-scoring.md

Usage:
  python3 scripts/risk_score.py findings.json [--overrides criticality.yaml|json] [--format json|md]
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import sys
from pathlib import Path

SENSITIVITY = {"none": 0, "internal": 1, "personal": 3,
               "sensitive_personal": 5, "credential": 5, "payment": 5}
PRIVILEGE = {"none": 0, "user": 1, "elevated": 3, "admin": 5}

# Base exploitability per finding type (see shared/risk-scoring.md)
BASE_EXPLOIT = {"F1": 5, "F2": 3, "F3": 3, "F4": 4,
                "F5": 4, "F6": 3, "F7": 5, "F8": 2}
# Minimum impact regardless of the endpoint's own data (SQLi reaches the whole DB)
IMPACT_FLOOR = {"F7": 4}
# Finding types that an API gateway can mitigate
GATEWAY_MITIGATED = {"F1", "F2", "F3", "F5"}

CRITICALITY_FLOOR = {"critical": 5, "high": 4}
ATTACK_RANK = {"none": 0, "weak": 1, "strong": 2}
CONFIDENCE_RANK = {"needs_review": 0, "likely": 1, "confirmed": 2}
TIER_PRIORITY = {"Critical": 1, "High": 2, "Medium": 3, "Low": 4}

STANDARDS_PATH = Path(__file__).resolve().parent.parent / "shared" / "standards.json"


def load_standards() -> dict:
    """Finding type -> CWE / ASVS / OWASP / OAT / IPA labels (shared/standards.json)."""
    return json.loads(STANDARDS_PATH.read_text(encoding="utf-8"))["findings"]


STANDARDS = load_standards()


def standards_label(ftype: str) -> str:
    s = STANDARDS.get(ftype, {})
    parts = list(s.get("cwe", []))
    parts += [f"ASVS {c}" for c in s.get("asvs", [])]
    parts += s.get("owasp_top10", []) + s.get("owasp_api", []) + s.get("oat", [])
    parts += [f"IPA {n}" for n in s.get("ipa", [])]
    return " / ".join(parts)


def clamp(v: int, lo: int = 0, hi: int = 5) -> int:
    return max(lo, min(hi, v))


def endpoint_path(endpoint: str) -> str:
    """'GET /api/v1/orders/{id}' -> '/api/v1/orders/{id}'"""
    parts = endpoint.split(None, 1)
    return parts[1] if len(parts) == 2 else parts[0]


def load_overrides(path: str | None) -> list[dict]:
    if not path:
        return []
    text = Path(path).read_text(encoding="utf-8")
    if path.endswith((".yaml", ".yml")):
        try:
            import yaml  # type: ignore
        except ImportError:
            sys.exit("PyYAML is not installed. Use a .json overrides file or `pip install pyyaml`.")
        data = yaml.safe_load(text) or []
    else:
        data = json.loads(text)
    if not isinstance(data, list):
        sys.exit("overrides must be a list of {path, ...} entries")
    return data


def apply_overrides(finding: dict, overrides: list[dict]) -> dict:
    """Later entries win. Matching uses glob on the endpoint path."""
    features = dict(finding.get("features", {}))
    path = endpoint_path(finding.get("endpoint", ""))
    for ov in overrides:
        if fnmatch.fnmatchcase(path, ov.get("path", "")):
            for key in ("business_criticality", "exposure", "gateway_enforced", "data_sensitivity"):
                if key in ov:
                    features[key] = ov[key]
    return features


def score(finding: dict, overrides: list[dict]) -> dict:
    ftype = finding["finding_type"]
    if ftype not in BASE_EXPLOIT:
        raise ValueError(f"{finding.get('id')}: unknown finding_type {ftype!r}")
    f = apply_overrides(finding, overrides)
    breakdown: list[str] = []

    # --- Impact (0-5) ---
    sens = SENSITIVITY.get(f.get("data_sensitivity", "none"), 0)
    priv = PRIVILEGE.get(f.get("privilege", "user"), 1)
    impact = max(sens, priv)
    breakdown.append(f"impact: max(data={sens}, privilege={priv})={impact}")
    if f.get("bulk"):
        impact += 1
        breakdown.append("impact: +1 bulk/list endpoint")
    if ftype in IMPACT_FLOOR and impact < IMPACT_FLOOR[ftype]:
        impact = IMPACT_FLOOR[ftype]
        breakdown.append(f"impact: floor {impact} for {ftype}")
    crit = f.get("business_criticality")
    if crit in CRITICALITY_FLOOR and impact < CRITICALITY_FLOOR[crit]:
        impact = CRITICALITY_FLOOR[crit]
        breakdown.append(f"impact: floor {impact} (business_criticality={crit})")
    impact = clamp(impact)

    # --- Exploitability (0-5) ---
    exploit = BASE_EXPLOIT[ftype]
    breakdown.append(f"exploit: base {exploit} ({ftype})")
    if ftype != "F1" and f.get("auth_required") is False:
        exploit += 1
        breakdown.append("exploit: +1 no authentication")
    if ftype == "F4":
        id_type = f.get("id_type")
        if id_type == "sequential":
            exploit += 1
            breakdown.append("exploit: +1 sequential IDs (easy enumeration)")
        elif id_type == "uuid":
            exploit -= 1
            breakdown.append("exploit: -1 UUID IDs (harder, not safe)")
    exposure = f.get("exposure", "unknown")
    if exposure in ("external", "mobile"):
        exploit += 1
        breakdown.append(f"exploit: +1 exposure={exposure}")
    elif exposure == "internal_only":
        exploit -= 1
        breakdown.append("exploit: -1 internal only")
    if f.get("gateway_enforced") and ftype in GATEWAY_MITIGATED:
        exploit -= 2
        breakdown.append("exploit: -2 enforced at API gateway")
    # Never 0: internal APIs are attacked too (lateral movement, JPCERT-AT-2026-0030)
    exploit = clamp(exploit, lo=1)

    inherent = impact * exploit
    if inherent >= 16:
        tier = "Critical"
    elif inherent >= 9:
        tier = "High"
    elif inherent >= 4:
        tier = "Medium"
    else:
        tier = "Low"

    # --- Runtime adjustment (never demotes) ---
    runtime = finding.get("runtime", {}) or {}
    attack = runtime.get("attack_signal", "none")
    if attack not in ATTACK_RANK:
        raise ValueError(f"{finding.get('id')}: unknown attack_signal {attack!r}")
    traffic = runtime.get("traffic_rpm")  # None = not observed in New Relic

    priority = TIER_PRIORITY[tier]
    if (attack == "strong" and tier != "Low") or (attack == "weak" and tier in ("Critical", "High")):
        priority = 0
        breakdown.append(f"priority: P0 (attack_signal={attack})")

    flags: list[str] = []
    first_action = "fix"
    if traffic is None:
        flags.append("not_observed")  # may be uninstrumented, not necessarily unused
    elif traffic == 0 and tier == "Critical":
        flags.append("dormant_critical")
        first_action = "disable_or_remove"
    if finding.get("confidence") == "needs_review":
        flags.append("needs_review")

    return {
        "id": finding.get("id"),
        "endpoint": finding.get("endpoint"),
        "finding_type": ftype,
        "priority": f"P{priority}",
        "tier": tier,
        "inherent": inherent,
        "impact": impact,
        "exploitability": exploit,
        "attack_signal": attack,
        "traffic_rpm": traffic,
        "confidence": finding.get("confidence", "likely"),
        "flags": flags,
        "first_action": first_action,
        "breakdown": breakdown,
        "standards": STANDARDS.get(ftype, {}),
        "evidence": finding.get("evidence", []),
        "_sort": (
            priority,
            -ATTACK_RANK[attack],
            -CONFIDENCE_RANK.get(finding.get("confidence", "likely"), 1),
            -inherent,
            -(traffic or 0),
            str(finding.get("id")),
        ),
    }


def rank(findings: list[dict], overrides: list[dict] | None = None) -> list[dict]:
    scored = [score(f, overrides or []) for f in findings]
    scored.sort(key=lambda r: r["_sort"])
    for i, r in enumerate(scored, 1):
        r["rank"] = i
        del r["_sort"]
    return scored


def to_markdown(rows: list[dict]) -> str:
    out = ["| # | Priority | Tier | Endpoint | Type | Score (I×E) | Attack | Traffic (rpm) | Flags | First action | Standards |",
           "|---|---|---|---|---|---|---|---|---|---|---|"]
    for r in rows:
        traffic = "not observed" if r["traffic_rpm"] is None else r["traffic_rpm"]
        out.append(
            f"| {r['rank']} | {r['priority']} | {r['tier']} | `{r['endpoint']}` | {r['finding_type']} "
            f"| {r['inherent']} ({r['impact']}×{r['exploitability']}) | {r['attack_signal']} "
            f"| {traffic} | {', '.join(r['flags']) or '-'} | {r['first_action']} | {standards_label(r['finding_type'])} |")
    return "\n".join(out)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("findings")
    ap.add_argument("--overrides")
    ap.add_argument("--format", choices=["json", "md"], default="json")
    args = ap.parse_args()

    data = json.loads(Path(args.findings).read_text(encoding="utf-8"))
    findings = data["findings"] if isinstance(data, dict) else data
    rows = rank(findings, load_overrides(args.overrides))
    if args.format == "md":
        print(to_markdown(rows))
    else:
        print(json.dumps(rows, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
