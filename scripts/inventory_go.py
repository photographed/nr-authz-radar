#!/usr/bin/env python3
"""Inventory Go HTTP endpoints and flag spots worth reading (saves reading the whole repository).

Regex based, no Go parser. It finds routes registered with net/http, chi, gin, echo, gorilla
(`r.Get("/x", handler)`, `mux.HandleFunc("/x", h)`, `e.GET(...)`), the auth middleware passed with
them, and suspicious patterns in the handler body. Claude then reads only the flagged handlers.
Every flag is a *candidate*.

  python3 scripts/inventory_go.py . --out .authz-radar/inventory.json
  python3 scripts/inventory_go.py . --changed-since origin/main
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

# r.Get("/x", h) | mux.HandleFunc("/x", h) | e.GET("/x", h, mw...) | router.POST("/x", mw, h)
ROUTE = re.compile(r"\.(Get|Post|Put|Patch|Delete|GET|POST|PUT|PATCH|DELETE|Handle|HandleFunc|Methods)\s*\(\s*\"([^\"]*)\"\s*(,[^\n]*)?")
VERB_MAP = {"get": "GET", "post": "POST", "put": "PUT", "patch": "PATCH", "delete": "DELETE",
            "handle": "ANY", "handlefunc": "ANY", "methods": "MATCH"}
AUTHZ_MW = re.compile(r"(RequireAuth|Authenticated?|Authorize\w*|RequireRole|RequireScope|JWT\w*|Middleware\.Auth|Protected|EnsureAuth|CheckAuth|Guard)", re.I)

FLAGS = {
    "query_by_id": re.compile(r"(?:QueryRow|Query|Exec|Get|First|Find|Where)\s*\(\s*[\"`][^\"`]*(?:WHERE|where)[^\"`]*\bid\b"),
    "sql_concat": re.compile(r"(?:Query|QueryRow|Exec|QueryContext|ExecContext|Raw|db\.Select)\s*\(\s*(?:fmt\.Sprintf|[\"`][^\"`]*[\"`]\s*\+|[^,)]*\+\s*\w+)"),
    "command_exec": re.compile(r"exec\.Command\s*\(|exec\.CommandContext\s*\(|os/exec|syscall\.Exec"),
    "template_injection": re.compile(r"template\.HTML\s*\(|text/template.*Execute"),
    "path_from_request": re.compile(r"(?:PathValue|Param|Query|FormValue|Vars)\s*\([^)]*\)"),
}
OWNER_HINT = re.compile(r"(?:UserID|OwnerID|TenantID|userID|ctx\.Value|FromContext|currentUser|\.User\b|AND\s+user|and\s+user|owner\s*=)", re.I)


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), text, flags=re.S)
    return re.sub(r"(^|[^:\"'])//[^\n]*", lambda m: m.group(1), text)


def line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def body_after(text: str, start: int) -> str:
    """If the route registers an inline func literal, return its braced body; else a window."""
    window = text[start:start + 1200]
    fn = window.find("func(")
    if fn < 0:
        return window[:500]
    brace = window.find("{", fn)
    if brace < 0:
        return window[:500]
    depth, i = 0, brace
    while i < len(window):
        c = window[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return window[brace:i + 1]
        i += 1
    return window[brace:]


def scan_flags(body: str) -> list[str]:
    flags = [name for name, pat in FLAGS.items() if pat.search(body)]
    has_id_source = "path_from_request" in flags
    flags = [f for f in flags if f != "path_from_request"]
    # "query_by_id" is only interesting when the id came from the request and no owner column is used
    if "query_by_id" in flags and (OWNER_HINT.search(body) or not has_id_source):
        flags.remove("query_by_id")
    return flags


def changed_files(ref: str, src: Path) -> set[Path]:
    out = subprocess.run(["git", "diff", "--name-only", ref, "--", str(src)], capture_output=True, text=True, check=True)
    top = Path(subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True, check=True).stdout.strip())
    return {(top / line).resolve() for line in out.stdout.splitlines() if line.endswith(".go")}


def endpoints_in(text: str, path: str) -> list[dict]:
    out = []
    for m in ROUTE.finditer(text):
        verb = VERB_MAP.get(m.group(1).lower(), m.group(1).upper())
        route, rest = m.group(2), (m.group(3) or "")
        if not route.startswith("/"):
            continue
        authz = bool(AUTHZ_MW.search(rest))
        body = body_after(text, m.start())
        out.append({"protocol": "rest", "endpoint": f"{verb} {route}", "handler": "(inline/ref)",
                    "authz": authz, "flags": scan_flags(body), "file": path, "line": line_of(text, m.start())})
    return out


def inventory(src: Path, only: set[Path] | None = None) -> dict:
    endpoints: list[dict] = []
    for f in sorted(src.rglob("*.go")):
        if f.name.endswith("_test.go") or "/vendor/" in str(f).replace("\\", "/"):
            continue
        if only is not None and f.resolve() not in only:
            continue
        endpoints += endpoints_in(strip_comments(f.read_text(encoding="utf-8", errors="replace")), str(f))
    flagged = [e for e in endpoints if e["flags"] or not e["authz"]]
    return {"source": str(src), "endpoints": endpoints,
            "summary": {"endpoints": len(endpoints), "to_read": len(flagged),
                        "no_authz": sum(not e["authz"] for e in endpoints)}}


def to_markdown(inv: dict) -> str:
    s = inv["summary"]
    out = [f"# Go endpoint inventory ({s['endpoints']} endpoints, {s['to_read']} to read)", "",
           "Candidates only. Read the flagged handlers (file:line) to confirm. Auth middleware that only",
           "authenticates is not authorization.", "",
           "| Endpoint | Handler | Authz mw | Flags | Location |", "|---|---|---|---|---|"]
    for e in inv["endpoints"]:
        out.append(f"| `{e['endpoint']}` | `{e['handler']}` | {'yes' if e['authz'] else '**none**'} | "
                   f"{', '.join(e['flags']) or '—'} | `{e['file']}:{e['line']}` |")
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
    print(f"{inv['summary']['endpoints']} endpoints, {inv['summary']['to_read']} to read "
          f"({inv['summary']['no_authz']} with no authz middleware): {out.with_suffix('.md')}", file=sys.stderr)


if __name__ == "__main__":
    main()
