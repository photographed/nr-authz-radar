#!/usr/bin/env python3
"""Print only the parts of the query catalogs you need (saves reading whole reference files).

  python3 scripts/catalog.py index                 # one line per item: ID, stage, evidence level, name
  python3 scripts/catalog.py index --stage S0      # only what runs at this stage
  python3 scripts/catalog.py show D01 D20 I05 R15  # full sections for these IDs only

IDs: D = detections, U = usage, I = investigation, R = readiness.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REFS = ROOT / "skills" / "nr-appsec-guard" / "references"
FILES = {"D": "detections.nrql.md", "U": "usage.nrql.md", "I": "investigation.nrql.md", "R": "readiness-checks.md"}
STAGES = ["S0", "S1", "S2", "S3"]
SECTION = re.compile(r"^### ([DUIR]\d{2}) (.*?)$(.*?)(?=^### |^## |\Z)", re.M | re.S)


def sections() -> dict[str, tuple[str, str]]:
    """ID -> (header line, full section text)."""
    out = {}
    for prefix, name in FILES.items():
        text = (REFS / name).read_text(encoding="utf-8")
        for m in SECTION.finditer(text):
            if m.group(1).startswith(prefix):
                out[m.group(1)] = (m.group(2).strip(), f"### {m.group(1)} {m.group(2)}{m.group(3)}".rstrip() + "\n")
    return out


def index(stage: str | None = None, lang: str = "ja") -> str:
    meta = json.loads((ROOT / "shared" / "detections.json").read_text(encoding="utf-8"))
    det, levels = meta["detections"], meta["levels"]
    lines = []
    for sid, (header, _) in sorted(sections().items(), key=lambda kv: ("RDUI".index(kv[0][0]), kv[0])):
        st = re.search(r"段階 (S\d)", header)
        st = st.group(1) if st else None
        if stage and st and STAGES.index(st) > STAGES.index(stage):
            continue
        if sid in det:
            m = det[sid]
            level = levels[m["evidence"]]["ja" if lang == "ja" else "en"]
            name = m["name"] if lang == "ja" else m["name_en"]
            req = ("+" + ",".join(m["requires"])) if m["requires"] else ""
            lines.append(f"{sid} {m['stage']}{req} [{level}] {name}")
        else:
            title = header.split(" — ")[0]
            lines.append(f"{sid} {st or '-'} {title}")
    return "\n".join(lines) + "\n"


def show(ids: list[str]) -> str:
    sec = sections()
    missing = [i for i in ids if i not in sec]
    if missing:
        sys.exit(f"unknown IDs: {', '.join(missing)}")
    return "\n".join(sec[i][1] for i in ids)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("index")
    p.add_argument("--stage", choices=STAGES)
    p.add_argument("--lang", choices=["ja", "en"], default="ja")
    s = sub.add_parser("show")
    s.add_argument("ids", nargs="+")
    args = ap.parse_args()
    print(index(args.stage, args.lang) if args.cmd == "index" else show([i.upper() for i in args.ids]), end="")


if __name__ == "__main__":
    main()
