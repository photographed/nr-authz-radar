#!/usr/bin/env python3
"""Find the New Relic appName(s) this repository reports as (repo -> appName binding for the IDE).

To run any detection or usage query you need the New Relic `appName`, but a checkout does not
obviously say which entity it is. Every APM agent, though, keeps the name in a config file or an
env var. This scans the repo and reports candidate app names with where each came from and how
confident we are, so the review flow can bind repo -> appName (and ask you when it is ambiguous).

  python3 scripts/find_appname.py .            # scan the repo, print candidates
  python3 scripts/find_appname.py . --format json

Confidence: "high" = a literal name in an agent config; "medium" = an env var with a literal
default; "low" = only an env-var reference (the value lives outside the repo — ask).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SKIP_DIRS = ("/node_modules/", "/vendor/", "/.git/", "/build/", "/dist/", "/.next/", "/target/", "/__pycache__/")
# agents whose config carries app_name, by filename
YAML_NAMES = ("newrelic.yml", "newrelic.yaml")          # Java, Ruby
INI_NAMES = ("newrelic.ini",)                           # Python, PHP
JS_NAMES = ("newrelic.js", "newrelic.cjs", "newrelic.mjs")  # Node
DOTNET_NAMES = ("newrelic.config",)                     # .NET (XML)
ENV_FILES = ("dockerfile", "docker-compose.yml", "docker-compose.yaml", "compose.yml", ".env", ".env.example", "values.yaml", "values.yml")
ENV_KEYS = ("NEW_RELIC_APP_NAME", "NEW_RELIC_APPNAME", "NEWRELIC_APPNAME", "NEWRELIC_APP_NAME")

INTERP = re.compile(r"\$\{?[A-Za-z(]")  # ${VAR}, $VAR, $(...), %(...)


def unquote(v: str) -> str:
    v = v.strip().strip(",")
    if len(v) >= 2 and v[0] in "\"'" and v[-1] == v[0]:
        v = v[1:-1]
    return v.strip()


def split_multi(name: str) -> list[str]:
    # the agents treat ';' as "report to several apps"; a repo may also list them comma-separated
    parts = [p.strip() for p in re.split(r";", name) if p.strip()]
    return parts or [name]


def looks_interpolated(v: str) -> bool:
    return bool(INTERP.search(v)) or "process.env" in v or "ENV[" in v or "<%=" in v


def add(out, name, agent, source, confidence, note=""):
    name = name.strip()
    if not name:
        return
    out.append({"app_name": name, "agent": agent, "source": source, "confidence": confidence, "note": note})


def from_yaml(text: str, rel: str, out: list):
    # app_name: scalar  |  app_name: [a, b]  |  app_name:\n  - a
    for m in re.finditer(r"^[ \t]*app_name:[ \t]*(.*)$", text, re.M):
        val = m.group(1).strip()
        if not val:  # block list on following lines
            continue
        if val.startswith("["):
            for item in re.findall(r"[\"']?([^,\[\]\"']+)[\"']?", val):
                if item.strip():
                    _emit(unquote(item), "java/ruby", rel, out)
        else:
            for n in split_multi(unquote(val)):
                _emit(n, "java/ruby", rel, out)


def from_ini(text: str, rel: str, out: list):
    for m in re.finditer(r"^[ \t]*(?:newrelic\.)?app_?name[ \t]*=[ \t]*(.*)$", text, re.M | re.I):
        for n in split_multi(unquote(m.group(1))):
            _emit(n, "python/php", rel, out)


def from_js(text: str, rel: str, out: list):
    m = re.search(r"app_name\s*:\s*(\[[^\]]*\]|[\"'][^\"']*[\"'])", text)
    if not m:
        return
    val = m.group(1)
    if val.startswith("["):
        # keep literal strings; note if an env default is present
        for item in re.findall(r"[\"']([^\"']+)[\"']", val):
            _emit(item, "node", rel, out)
        if "process.env" in val and not re.search(r"[\"'][^\"']+[\"']", val):
            add(out, "(set via NEW_RELIC_APP_NAME)", "node", rel, "low", "app_name is env-only")
    else:
        _emit(unquote(val), "node", rel, out)


def from_dotnet(text: str, rel: str, out: list):
    for m in re.finditer(r"<application>\s*<name>([^<]+)</name>", text, re.I | re.S):
        for n in split_multi(m.group(1).strip()):
            _emit(n, "dotnet", rel, out)


def from_go(text: str, rel: str, out: list):
    for m in re.finditer(r"ConfigAppName\s*\(\s*[\"']([^\"']+)[\"']\s*\)", text):
        _emit(m.group(1), "go", rel, out)


def from_env(text: str, rel: str, out: list):
    for key in ENV_KEYS:
        # KEY=val | KEY: val | KEY "val" (Dockerfile ENV) | - KEY=val (compose list)
        for m in re.finditer(rf"{key}\s*[:=]\s*(.+)", text):
            raw = m.group(1).strip().strip(",")
            # Dockerfile ENV KEY "v" or KEY v
            val = unquote(raw.split("#", 1)[0])
            if not val:
                continue
            if looks_interpolated(val):
                add(out, f"(set via {key})", "env", rel, "low", f"{key} resolves at runtime: {val}")
            else:
                for n in split_multi(val):
                    add(out, n, "env", rel, "medium", f"from {key}")


def _emit(name: str, agent: str, rel: str, out: list):
    if looks_interpolated(name):
        add(out, "(set via env)", agent, rel, "low", f"config value is interpolated: {name}")
    else:
        add(out, name, agent, rel, "high")


def scan_file(path: Path, rel: str, out: list):
    lower = path.name.lower()
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    if lower in YAML_NAMES:
        from_yaml(text, rel, out)
    elif lower in INI_NAMES:
        from_ini(text, rel, out)
    elif lower in JS_NAMES:
        from_js(text, rel, out)
    elif lower in DOTNET_NAMES:
        from_dotnet(text, rel, out)
    if lower in ENV_FILES:
        from_env(text, rel, out)
    if path.suffix == ".go":
        from_go(text, rel, out)


def find(src: Path) -> dict:
    out: list[dict] = []
    for f in sorted(src.rglob("*")):
        if not f.is_file():
            continue
        posix = "/" + str(f).replace("\\", "/") + "/"
        if any(k in posix for k in SKIP_DIRS):
            continue
        name = f.name.lower()
        if name in YAML_NAMES + INI_NAMES + JS_NAMES + DOTNET_NAMES + ENV_FILES or f.suffix == ".go":
            scan_file(f, str(f.relative_to(src)) if src in f.parents else str(f), out)
    # dedupe by (app_name, source), keep the highest confidence
    rank = {"high": 3, "medium": 2, "low": 1}
    best: dict[tuple, dict] = {}
    for c in out:
        key = (c["app_name"], c["source"])
        if key not in best or rank[c["confidence"]] > rank[best[key]["confidence"]]:
            best[key] = c
    cands = sorted(best.values(), key=lambda c: (-rank[c["confidence"]], c["app_name"]))
    distinct = sorted({c["app_name"] for c in cands if not c["app_name"].startswith("(")})
    return {"source": str(src), "candidates": cands,
            "summary": {"distinct_app_names": distinct, "count": len(distinct),
                        "needs_confirmation": len(distinct) != 1}}


def to_markdown(res: dict) -> str:
    s = res["summary"]
    out = ["# New Relic appName candidates (repo binding)", ""]
    if s["count"] == 1:
        out.append(f"**Best guess: `{s['distinct_app_names'][0]}`** — confirm it matches the entity in New Relic.")
    elif s["count"] == 0:
        out.append("**No appName found in the repo.** It is probably set only via `NEW_RELIC_APP_NAME` at "
                   "deploy time — ask which entity this service is, or run a `FACET appName` query (R17).")
    else:
        out.append(f"**{s['count']} candidate names** (prod/staging or several services). "
                   "Pick the entity you are reviewing; do not merge them.")
    out += ["", "| appName | Agent | Confidence | Source | Note |", "|---|---|---|---|---|"]
    for c in res["candidates"]:
        out.append(f"| `{c['app_name']}` | {c['agent']} | {c['confidence']} | `{c['source']}` | {c['note']} |")
    out += ["", "Names that differ only by `(Production)` / `(Staging)` are the same service per environment; "
            "query the one whose data you are looking at."]
    return "\n".join(out) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("src", nargs="?", default=".")
    ap.add_argument("--format", choices=["md", "json"], default="md")
    ap.add_argument("--out")
    args = ap.parse_args()
    res = find(Path(args.src))
    rendered = json.dumps(res, ensure_ascii=False, indent=1) if args.format == "json" else to_markdown(res)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(rendered + "\n", encoding="utf-8")
        print(f"{res['summary']['count']} distinct appName(s): {args.out}", file=sys.stderr)
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    sys.exit(main())
