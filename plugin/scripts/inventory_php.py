#!/usr/bin/env python3
"""Inventory PHP endpoints and flag spots worth reading (saves reading the whole repository).

Regex based, no PHP parser. It finds Laravel routes (routes/*.php) with their controller, the
middleware on each route, and suspicious patterns in the controller bodies. It also scans plain
PHP for raw SQL built by string concatenation. Claude then reads only the flagged methods to
confirm. Every flag is a *candidate*, never a finding.

  python3 scripts/inventory_php.py examples/php-vuln-site --out .authz-radar/inventory.json
  python3 scripts/inventory_php.py app --changed-since origin/main      # PR review: changed files only
  python3 scripts/inventory_php.py app --files app/Http/Controllers/Api/OrderController.php
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

# Route::get('/orders/{id}', [OrderController::class, 'show'])  or  'OrderController@show'
ROUTE = re.compile(
    r"Route::(get|post|put|patch|delete|any|match)\s*\(\s*"
    r"(?:\[[^\]]*\]|['\"][^'\"]*['\"])\s*,\s*"
    r"(?:\[\s*([\w\\]+)::class\s*,\s*['\"](\w+)['\"]\s*\]|['\"]([\w\\]+)@(\w+)['\"])",
    re.I,
)
ROUTE_PATH = re.compile(r"Route::\w+\s*\(\s*['\"]([^'\"]*)['\"]")
# ->middleware('auth') / ->middleware(['auth','authz.owner:order'])
MIDDLEWARE = re.compile(r"->middleware\s*\(\s*(\[[^\]]*\]|['\"][^'\"]*['\"])\s*\)")
GROUP_MIDDLEWARE = re.compile(r"Route::middleware\s*\(\s*(\[[^\]]*\]|['\"][^'\"]*['\"])\s*\)\s*->group")
METHOD_DECL = re.compile(r"function\s+(\w+)\s*\(")

# Suspicious patterns in a controller / resolver body. Each is a candidate to read, not a finding.
FLAGS = {
    # a model loaded by a client-supplied id, with no owner column in sight
    "find_by_id": re.compile(r"::(?:find|findOrFail|findOne)\s*\(\s*\$\w+"),
    # SQL built by string concatenation or interpolation
    "sql_concat": re.compile(r"(?:DB::(?:select|statement|insert|update|delete|raw|unprepared)|->(?:selectRaw|whereRaw|havingRaw|orderByRaw)|->query)\s*\([^;)]*?(?:\.\s*\$|\$\w+(?:\[[^\]]*\])?\s*\.|\{\$)",
                             re.S),
    # mass assignment straight from request input
    "mass_assignment": re.compile(r"::(?:create|fill|update|forceFill)\s*\(\s*(?:\$request->(?:all|input)\s*\(|request\s*\(\s*\)\s*->(?:all|input))"),
    # command execution (RCE)
    "command_exec": re.compile(r"\b(?:shell_exec|exec|system|passthru|proc_open|popen|pcntl_exec)\s*\(|`[^`]*\$"),
    # unsafe deserialization (RCE / object injection)
    "unserialize": re.compile(r"\bunserialize\s*\(|phar://"),
    # dynamic include driven by input
    "dynamic_include": re.compile(r"\b(?:include|require)(?:_once)?\s*\(?\s*\$"),
}
# the check that would make find_by_id safe (an owner comparison or the library helpers)
OWNER_HINT = re.compile(r"ensureOwns|authz\.owner|->where\s*\(\s*['\"](?:user_id|owner_id|tenant_id)|->user\s*\(\s*\)\s*->\w*(?:orders|own)|Gate::|authorize\s*\(|policies?", re.I)
# a reference to Laravel's own authorization in a route/controller
AUTHZ_MIDDLEWARE = ("auth", "auth:", "can:", "authz.owner", "role", "admin", "scope", "ability", "abilities")
VERB = {"get": "GET", "post": "POST", "put": "PUT", "patch": "PATCH", "delete": "DELETE", "any": "ANY", "match": "MATCH"}


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), text, flags=re.S)
    return re.sub(r"(^|\s)(?://|#)[^\n]*", lambda m: m.group(1), text)


def line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def mw_list(raw: str) -> list[str]:
    return [m for m in re.findall(r"['\"]([^'\"]+)['\"]", raw)]


def is_authz(mws: list[str]) -> bool:
    return any(m.startswith(a) or m == a.rstrip(":") for m in mws for a in AUTHZ_MIDDLEWARE)


def routes_in(text: str) -> list[dict]:
    """Laravel routes with their controller and middleware (per route + nearest enclosing group)."""
    out: list[dict] = []
    # group middleware active at each offset: list of (start, end_of_group_is_unknown -> whole file, mws)
    groups = [(m.start(), mw_list(m.group(1))) for m in GROUP_MIDDLEWARE.finditer(text)]
    for m in ROUTE.finditer(text):
        verb = VERB.get(m.group(1).lower(), m.group(1).upper())
        ctrl = (m.group(2) or m.group(4) or "").split("\\")[-1]
        method = m.group(3) or m.group(5)
        path_m = ROUTE_PATH.search(text, m.start(), m.end() + 4) or ROUTE_PATH.search(text[m.start():m.start() + 200])
        path = path_m.group(1) if path_m else "?"
        # per-route middleware: look a little past the call for a chained ->middleware(...)
        tail = text[m.end():m.end() + 400]
        mws = mw_list(MIDDLEWARE.search(tail).group(1)) if MIDDLEWARE.search(tail) else []
        # nearest group opened before this route
        group_mws = next((g for s, g in reversed(groups) if s < m.start()), [])
        all_mws = group_mws + mws
        out.append({"protocol": "rest", "endpoint": f"{verb} {path}", "handler": f"{ctrl}@{method}",
                    "controller": ctrl, "method": method, "middleware": all_mws,
                    "authz": is_authz(all_mws), "line": line_of(text, m.start())})
    return out


def method_body(text: str, name: str) -> tuple[str, int] | None:
    for m in METHOD_DECL.finditer(text):
        if m.group(1) != name:
            continue
        brace = text.find("{", m.end())
        if brace < 0:
            continue
        depth, i = 0, brace
        while i < len(text):
            depth += (text[i] == "{") - (text[i] == "}")
            if depth == 0:
                return text[brace:i + 1], line_of(text, m.start())
            i += 1
    return None


def scan_controller(text: str, method: str) -> tuple[list[str], int | None]:
    body = method_body(text, method)
    if body is None:
        return [], None
    code, line = body
    flags = [name for name, pat in FLAGS.items() if pat.search(code)]
    if "find_by_id" in flags and OWNER_HINT.search(code):
        flags.remove("find_by_id")  # an owner check is present in the same method
    return flags, line


def changed_files(ref: str, src: Path) -> set[Path]:
    out = subprocess.run(["git", "diff", "--name-only", ref, "--", str(src)], capture_output=True, text=True, check=True)
    top = Path(subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True, check=True).stdout.strip())
    return {(top / line).resolve() for line in out.stdout.splitlines() if line.endswith(".php")}


def inventory(src: Path, only: set[Path] | None = None) -> dict:
    skip = ("/vendor/", "/node_modules/", "/storage/")
    files = [f for f in sorted(src.rglob("*.php")) if not any(k in "/" + str(f).replace("\\", "/") + "/" for k in skip)]
    texts = {f: strip_comments(f.read_text(encoding="utf-8", errors="replace")) for f in files}
    # map controller short name -> file text (last one wins; fine for a demo / typical layout)
    controllers = {f.stem: (f, t) for f, t in texts.items() if re.search(r"class\s+\w*Controller\b", t)}

    endpoints: list[dict] = []
    raw_sql: list[dict] = []
    for f, t in texts.items():
        if "vendor/" in str(f).replace("\\", "/"):
            continue
        if only is not None and f.resolve() not in only:
            continue
        for r in routes_in(t):
            flags, cline = ([], None)
            ctrl = controllers.get(r["controller"])
            if ctrl is not None:
                flags, cline = scan_controller(ctrl[1], r["method"])
                r["controller_file"] = f"{ctrl[0]}"
            r["flags"] = flags
            r["file"] = str(f)
            if cline is not None:
                r["handler_line"] = cline
            endpoints.append(r)
        # plain PHP SQL concatenation outside a known route (raw scripts, helpers)
        for m in FLAGS["sql_concat"].finditer(t):
            raw_sql.append({"file": str(f), "line": line_of(t, m.start())})

    flagged = [e for e in endpoints if e["flags"] or not e["authz"]]
    return {"source": str(src), "endpoints": endpoints, "raw_sql": raw_sql,
            "summary": {"endpoints": len(endpoints), "to_read": len(flagged),
                        "no_authz_middleware": sum(not e["authz"] for e in endpoints),
                        "raw_sql_spots": len(raw_sql)}}


def to_markdown(inv: dict) -> str:
    s = inv["summary"]
    out = [f"# PHP endpoint inventory ({s['endpoints']} endpoints, {s['to_read']} to read)", "",
           "Candidates only. Read the flagged methods (file:line) to confirm. Middleware that is not an",
           "authorization check (e.g. `throttle`) does not count as authorization.", "",
           "| Endpoint | Handler | Middleware | Flags | Handler location |", "|---|---|---|---|---|"]
    for e in inv["endpoints"]:
        mw = ", ".join(e["middleware"]) or "**none**"
        loc = f"{e.get('controller_file', e['file'])}:{e.get('handler_line', e['line'])}"
        out.append(f"| `{e['endpoint']}` | `{e['handler']}` | {mw} | {', '.join(e['flags']) or '—'} | `{loc}` |")
    if inv["raw_sql"]:
        out += ["", "## Raw SQL built by concatenation (possible SQL injection)", "",
                "| Location |", "|---|"]
        out += [f"| `{r['file']}:{r['line']}` |" for r in inv["raw_sql"]]
    return "\n".join(out) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("src")
    ap.add_argument("--out", default=".authz-radar/inventory.json")
    ap.add_argument("--changed-since", help="git ref: only endpoints in files changed since this ref")
    ap.add_argument("--files", help="comma separated: only endpoints in these files")
    args = ap.parse_args()
    src = Path(args.src)
    only = None
    if args.changed_since:
        only = changed_files(args.changed_since, src)
    elif args.files:
        only = {Path(f).resolve() for f in args.files.split(",") if f}
    inv = inventory(src, only)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(inv, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    out.with_suffix(".md").write_text(to_markdown(inv), encoding="utf-8")
    print(f"{inv['summary']['endpoints']} endpoints, {inv['summary']['to_read']} to read "
          f"({inv['summary']['no_authz_middleware']} with no authz middleware, "
          f"{inv['summary']['raw_sql_spots']} raw SQL spots): {out.with_suffix('.md')}", file=sys.stderr)


if __name__ == "__main__":
    main()
