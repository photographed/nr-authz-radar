#!/usr/bin/env python3
"""Build a MITRE ATT&CK Navigator layer showing what this plugin can notice at your stage.

Each technique gets the strongest evidence level among the detections that map to it and can run
with your stage and data sources: 3 = evidence, 2 = strong signal, 1 = anomaly only.
Code-review findings (F1-F12) can be added with --findings (score 1: "a hole may exist").

  python3 scripts/attack_layer.py --stage S2 --sources spans --out .authz-radar/attack-layer.json

Open the JSON in ATT&CK Navigator ("Open Existing Layer" -> "Upload from local").
The mapping is this plugin's interpretation (shared/standards.json, ATT&CK v20.0).
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STANDARDS = ROOT / "shared" / "standards.json"
DETECTIONS = ROOT / "shared" / "detections.json"
STAGES = ["S0", "S1", "S2", "S3"]
SCORES = {"evidence": 3, "strong": 2, "anomaly": 1}
LEGEND = {3: ("evidence", "#c0392b"), 2: ("strong signal", "#e67e22"), 1: ("anomaly / code finding", "#f4d03f")}


def runnable(meta: dict, stage: str, sources: set[str]) -> bool:
    return STAGES.index(meta["stage"]) <= STAGES.index(stage) and all(s in sources for s in meta["requires"])


def coverage(stage: str, sources: set[str], findings: bool = False) -> dict[str, dict]:
    std = json.loads(STANDARDS.read_text(encoding="utf-8"))
    det = json.loads(DETECTIONS.read_text(encoding="utf-8"))["detections"]
    out: dict[str, dict] = {}

    def add(tech: str, score: int, source: str):
        entry = out.setdefault(tech, {"score": 0, "sources": []})
        entry["score"] = max(entry["score"], score)
        entry["sources"].append(source)

    for d, meta in det.items():
        score = SCORES.get(meta["evidence"])
        if not score or not runnable(meta, stage, sources):
            continue
        for tech in std["detections"][d].get("attack", []):
            add(tech, score, f"{d} ({meta['evidence']})")
    if findings:
        for f, meta in std["findings"].items():
            for tech in meta.get("attack", []):
                add(tech, 1, f"{f} (code)")
    return out


def layer(stage: str, sources: set[str], findings: bool = False) -> dict:
    std = json.loads(STANDARDS.read_text(encoding="utf-8"))
    names = std["attack_techniques"]
    cov = coverage(stage, sources, findings)
    srcs = ",".join(sorted(sources)) or "none"
    return {
        "name": f"nr-authz-radar {stage}",
        "versions": {"attack": std["attack_version"].split(".")[0], "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": (f"What nr-authz-radar can notice at stage {stage} with data sources: {srcs}. "
                        "3 = evidence, 2 = strong signal, 1 = anomaly only"
                        + (" or code-review finding" if findings else "")
                        + ". Mapping is the plugin's interpretation (shared/standards.json)."),
        "techniques": [
            {"techniqueID": t, "score": c["score"], "enabled": True,
             "comment": f"{names[t]['name']}: " + ", ".join(sorted(set(c["sources"])))}
            for t, c in sorted(cov.items())
        ],
        "gradient": {"colors": ["#f4d03f", "#e67e22", "#c0392b"], "minValue": 1, "maxValue": 3},
        "legendItems": [{"label": label, "color": color} for _, (label, color) in sorted(LEGEND.items(), reverse=True)],
        "showTacticRowBackground": True,
        "selectSubtechniquesWithParent": False,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--stage", choices=STAGES, required=True)
    ap.add_argument("--sources", default="", help="comma separated, e.g. spans,browser_dt,browser_user,deployments,logs")
    ap.add_argument("--findings", action="store_true", help="also mark techniques covered by code-review findings")
    ap.add_argument("--out", default=".authz-radar/attack-layer.json")
    args = ap.parse_args()
    data = layer(args.stage, {s for s in args.sources.split(",") if s}, args.findings)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    by = {s: sum(t["score"] == s for t in data["techniques"]) for s in (3, 2, 1)}
    print(f"{len(data['techniques'])} techniques (evidence {by[3]}, strong {by[2]}, anomaly/code {by[1]}): {out}")


if __name__ == "__main__":
    main()
