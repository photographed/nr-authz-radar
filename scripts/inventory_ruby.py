#!/usr/bin/env python3
"""Inventory Ruby on Rails (and Sinatra) endpoints and flag spots worth reading.

Regex based, no Ruby parser. It lists controller actions with the `before_action` authorization
filters on them and suspicious patterns in the body, plus Sinatra route blocks. Routes in
`config/routes.rb` map actions to paths; the script lists those too. Every flag is a *candidate*.

  python3 scripts/inventory_ruby.py app --out .authz-radar/inventory.json
  python3 scripts/inventory_ruby.py . --changed-since origin/main
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

CLASS = re.compile(r"class\s+(\w+)\s*<\s*[\w:]")
ACTION = re.compile(r"^([ \t]*)def\s+(\w+)", re.M)
# before_action :authenticate_user!, only: [:show]  /  :require_admin
BEFORE_ACTION = re.compile(r"before_action\s+:(\w+)([^\n]*)")
SINATRA = re.compile(r"^\s*(get|post|put|patch|delete)\s+['\"]([^'\"]+)['\"]\s+do", re.M)
# Sinatra route in routes.rb: get '/x', to: 'ctrl#action'
RAILS_ROUTE = re.compile(r"\b(get|post|put|patch|delete)\s+['\"]([^'\"]+)['\"].*?to:\s*['\"](\w+)#(\w+)['\"]")
RAILS_RESOURCES = re.compile(r"\bresources?\s+:(\w+)")

AUTHZ_FILTERS = ("authenticate", "require_", "authorize", "verify_", "ensure_", "check_", "admin", "login")

FLAGS = {
    "find_by_id": re.compile(r"\b[A-Z]\w*\.find\s*\(\s*params\[|\b[A-Z]\w*\.find_by\s*\(\s*id:|\.find\s*\(\s*params\[:id\]"),
    "sql_concat": re.compile(r"(?:where|find_by_sql|execute|order|select|group|having)\s*\(?\s*\"[^\"]*#\{|(?:where|execute)\s*\(?\s*['\"][^'\"]*['\"]\s*[+%]"),
    "command_exec": re.compile(r"`[^`]*#\{|%x\[|\bsystem\s*\(|\bexec\s*\(|Open3\.|\beval\s*\("),
    "unsafe_deserialization": re.compile(r"Marshal\.load|YAML\.load\b(?!_safe)|Psych\.load\b"),
    "mass_assignment": re.compile(r"\.(?:new|create|update|update_attributes)\s*\(\s*params\[[^\]]*\]\s*\)|params\.permit!"),
}
OWNER_HINT = re.compile(r"current_user\.|\.where\([^)]*user|owner|tenant|account_id|scoped_to|policy_scope|authorize\s", re.I)


def strip_comments(text: str) -> str:
    return "\n".join(line.split("#", 1)[0] if not _in_string_hash(line) else line for line in text.split("\n"))


def _in_string_hash(line: str) -> bool:
    # keep lines where '#' is inside "#{...}" (interpolation) or a quoted string
    h = line.find("#")
    return h >= 0 and (h + 1 < len(line) and line[h + 1] == "{" or line[:h].count('"') % 2 == 1)


def line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def action_body(text: str, def_match: re.Match) -> str:
    """Rails action: lines until the matching `end` at the def's indent."""
    indent = len(def_match.group(1))
    lines = text[def_match.end():].split("\n")
    out = []
    for ln in lines:
        if ln.strip() == "end" and (len(ln) - len(ln.lstrip())) == indent:
            break
        out.append(ln)
    return "\n".join(out)


def scan_flags(body: str) -> list[str]:
    flags = [name for name, pat in FLAGS.items() if pat.search(body)]
    if "find_by_id" in flags and OWNER_HINT.search(body):
        flags.remove("find_by_id")
    return flags


def controller_actions(text: str, path: str) -> list[dict]:
    m = CLASS.search(text)
    if not m or "Controller" not in m.group(1):
        return []
    ctrl = m.group(1)
    base = ctrl[:-len("Controller")]
    resource = re.sub(r"(?<!^)(?=[A-Z])", "_", base).lower()  # OrdersController -> orders
    # before_action filters and their scope
    filters = []  # (name, only_set or None, except_set or None)
    for b in BEFORE_ACTION.finditer(text):
        name, rest = b.group(1), b.group(2)
        only = set(re.findall(r":(\w+)", rest.split("only:", 1)[1])) if "only:" in rest else None
        exc = set(re.findall(r":(\w+)", rest.split("except:", 1)[1])) if "except:" in rest else None
        filters.append((name, only, exc))
    out = []
    for dm in ACTION.finditer(text):
        action = dm.group(2)
        applied = [n for (n, only, exc) in filters if (only is None or action in only) and (exc is None or action not in exc)]
        authz = any(any(k in n for k in AUTHZ_FILTERS) for n in applied)
        body = action_body(text, dm)
        out.append({"protocol": "rest", "endpoint": f"{resource}#{action}", "handler": f"{ctrl}#{action}",
                    "authz": authz, "filters": applied, "flags": scan_flags(body), "file": path, "line": line_of(text, dm.start())})
    return out


def sinatra_routes(text: str, path: str) -> list[dict]:
    out = []
    for m in SINATRA.finditer(text):
        verb, route = m.group(1).upper(), m.group(2)
        body = text[m.end():m.end() + 500]
        out.append({"protocol": "rest", "endpoint": f"{verb} {route}", "handler": "(sinatra block)",
                    "authz": False, "filters": [], "flags": scan_flags(body), "file": path, "line": line_of(text, m.start())})
    return out


def routes_rb(text: str) -> list[dict]:
    routes = []
    for m in RAILS_ROUTE.finditer(text):
        routes.append({"verb": m.group(1).upper(), "path": m.group(2), "action": f"{m.group(3)}#{m.group(4)}"})
    for m in RAILS_RESOURCES.finditer(text):
        routes.append({"verb": "RESOURCES", "path": f"/{m.group(1)}", "action": f"{m.group(1)} (resourceful)"})
    return routes


def changed_files(ref: str, src: Path) -> set[Path]:
    out = subprocess.run(["git", "diff", "--name-only", ref, "--", str(src)], capture_output=True, text=True, check=True)
    top = Path(subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True, check=True).stdout.strip())
    return {(top / line).resolve() for line in out.stdout.splitlines() if line.endswith(".rb")}


def inventory(src: Path, only: set[Path] | None = None) -> dict:
    endpoints: list[dict] = []
    routes: list[dict] = []
    for f in sorted(src.rglob("*.rb")):
        if any(k in "/" + str(f).replace("\\", "/") + "/" for k in ("/vendor/", "/tmp/", "/node_modules/")):
            continue
        if only is not None and f.resolve() not in only:
            continue
        text = strip_comments(f.read_text(encoding="utf-8", errors="replace"))
        if f.name == "routes.rb":
            routes += routes_rb(text)
        if f.name.endswith("_controller.rb") or "Controller" in text:
            endpoints += controller_actions(text, str(f))
        else:
            endpoints += sinatra_routes(text, str(f))
    flagged = [e for e in endpoints if e["flags"] or not e["authz"]]
    return {"source": str(src), "endpoints": endpoints, "routes": routes,
            "summary": {"endpoints": len(endpoints), "to_read": len(flagged),
                        "no_authz": sum(not e["authz"] for e in endpoints), "routes": len(routes)}}


def to_markdown(inv: dict) -> str:
    s = inv["summary"]
    out = [f"# Ruby endpoint inventory ({s['endpoints']} actions, {s['to_read']} to read)", "",
           "Candidates only. Read the flagged actions (file:line) to confirm. A `before_action` that only",
           "authenticates (`authenticate_user!`) is not authorization.", "",
           "| Action | Controller | Authz filters | Flags | Location |", "|---|---|---|---|---|"]
    for e in inv["endpoints"]:
        out.append(f"| `{e['endpoint']}` | `{e['handler']}` | {', '.join(e['filters']) or '**none**'} | "
                   f"{', '.join(e['flags']) or '—'} | `{e['file']}:{e['line']}` |")
    if inv["routes"]:
        out += ["", "## Routes (config/routes.rb)", "", "| Verb | Path | Action |", "|---|---|---|"]
        out += [f"| {r['verb']} | `{r['path']}` | {r['action']} |" for r in inv["routes"]]
    return "\n".join(out) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("src")
    ap.add_argument("--out", default=".authz-radar/inventory.json")
    ap.add_argument("--changed-since")
    ap.add_argument("--files")
    args = ap.parse_args()
    src = Path(args.src)
    only = changed_files(args.changed_since, src) if args.changed_since else (
        {Path(f).resolve() for f in args.files.split(",") if f} if args.files else None)
    inv = inventory(src, only)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(inv, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    out.with_suffix(".md").write_text(to_markdown(inv), encoding="utf-8")
    print(f"{inv['summary']['endpoints']} actions, {inv['summary']['to_read']} to read "
          f"({inv['summary']['no_authz']} with no authz filter, {inv['summary']['routes']} routes): "
          f"{out.with_suffix('.md')}", file=sys.stderr)


if __name__ == "__main__":
    main()
