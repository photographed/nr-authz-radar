#!/usr/bin/env python3
"""Inventory Node.js endpoints and flag spots worth reading (saves reading the whole repository).

Regex based, no JS parser. It finds Express / Koa / Fastify routes (`app.get('/x', mw, handler)`)
and Next.js file-based routes (`app/**/route.{js,ts}` exporting GET/POST, and `pages/api/**`),
the authorization middleware on them, and suspicious patterns in the handler body. Claude then
reads only the flagged handlers to confirm. Every flag is a *candidate*.

  python3 scripts/inventory_node.py src --out .authz-radar/inventory.json
  python3 scripts/inventory_node.py . --changed-since origin/main
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

# app.get('/x', mwA, mwB, handler)   router.post("/x", handler)
EXPRESS = re.compile(r"\b(?:app|router|r|api)\.(get|post|put|patch|delete|all)\s*\(\s*([\"'`])([^\"'`]*)\2\s*(,[^\n]*)?")
# Next.js App Router: export (async) function GET / export const GET =
NEXT_EXPORT = re.compile(r"export\s+(?:async\s+function|const|function)\s+(GET|POST|PUT|PATCH|DELETE)\b")
NEXT_CJS = re.compile(r"\b(GET|POST|PUT|PATCH|DELETE)\b")  # for module.exports = { GET }
AUTHZ_MW = re.compile(r"(requireAuth|ensureAuth\w*|isAuth\w*|authenticate|authorize\w*|requireRole|requireScope|checkAuth|passport\.authenticate|jwt\w*|withAuthzRadar|canAccess|requirePermission|guard)", re.I)

FLAGS = {
    "find_by_id": re.compile(r"\.(?:findById|findByPk|findOne|get)\s*\(\s*(?:req\.params|params|id\b|\{\s*(?:where:\s*)?\{?\s*id\b)"),
    "sql_concat": re.compile(r"(?:query|execute|raw|\$queryRawUnsafe|executeRawUnsafe)\s*\(\s*`[^`]*\$\{|(?:query|execute|raw)\s*\(\s*[\"'][^\"']*[\"']\s*\+"),
    "command_exec": re.compile(r"\b(?:exec|execSync|spawn|spawnSync|execFile)\s*\(|child_process|\beval\s*\("),
    "unsafe_deserialization": re.compile(r"node-serialize|\bunserialize\s*\(|_\$\$ND_FUNC\$\$_|vm\.runIn"),
    "mass_assignment": re.compile(r"\.(?:create|update|build|save)\s*\(\s*req\.body\b|\{\s*\.\.\.req\.body\s*\}"),
}
OWNER_HINT = re.compile(r"req\.user|userId|owner(?:Id)?|tenant(?:Id)?|where:\s*\{[^}]*(?:user|owner|tenant)|ownership\s*\(|ensureOwns", re.I)
NEXT_PARAM = re.compile(r"\[\.{3}?(\w+)\]")  # [id] or [...slug]


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), text, flags=re.S)
    return re.sub(r"(^|[^:])//[^\n]*", lambda m: m.group(1), text)


def line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def balanced_body(text: str, start: int) -> str:
    """From the first '{' at/after start, return the braced block (string-aware-ish)."""
    brace = text.find("{", start)
    if brace < 0:
        return text[start:start + 400]
    depth, i = 0, brace
    while i < len(text):
        c = text[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[brace:i + 1]
        i += 1
    return text[brace:]


def scan_flags(body: str) -> list[str]:
    flags = [name for name, pat in FLAGS.items() if pat.search(body)]
    if "find_by_id" in flags and OWNER_HINT.search(body):
        flags.remove("find_by_id")
    return flags


def next_route_path(path: Path, src: Path) -> str:
    """app/api/orders/[id]/route.js -> /api/orders/[id] ; pages/api/x.js -> /api/x"""
    rel = path.relative_to(src) if src in path.parents or src == path.parent else path
    parts = list(rel.parts)
    name = parts[-1]
    segs = parts[:-1]
    if "app" in segs:
        segs = segs[segs.index("app") + 1:]
    elif "pages" in segs:
        segs = segs[segs.index("pages"):]
        segs = segs[1:] if segs[:1] == ["pages"] else segs
        if name not in ("route.js", "route.ts"):
            segs = segs + [re.sub(r"\.(js|ts|jsx|tsx)$", "", name)]
    return "/" + "/".join(segs)


def endpoints_in(text: str, path: Path, src: Path) -> list[dict]:
    out: list[dict] = []
    p = str(path)
    fname = path.name
    # Next.js file-based route handlers
    if fname in ("route.js", "route.ts", "route.jsx", "route.tsx") or ("/pages/api/" in p.replace("\\", "/")):
        route = next_route_path(path, src)
        verbs = []
        for m in NEXT_EXPORT.finditer(text):
            verbs.append((m.group(1), m.start()))
        if not verbs and "module.exports" in text:  # module.exports = { GET, POST }
            meq = text.find("module.exports")
            for m in NEXT_CJS.finditer(text[meq:meq + 200]):
                verbs.append((m.group(1), meq))
        if "/pages/api/" in p.replace("\\", "/") and not verbs:
            verbs = [("ANY", 0)]  # default export handler switches on req.method
        for verb, pos in verbs:
            body = text  # whole module is the handler scope here
            authz = bool(AUTHZ_MW.search(text))
            out.append({"protocol": "rest", "endpoint": f"{verb} {route}", "handler": f"{fname}:{verb}",
                        "authz": authz, "flags": scan_flags(body), "file": p, "line": line_of(text, pos)})
        return out
    # Express / Koa / Fastify
    for m in EXPRESS.finditer(text):
        verb, route, rest = m.group(1).upper(), m.group(3), (m.group(4) or "")
        authz = bool(AUTHZ_MW.search(rest))
        body = balanced_body(text, m.start())  # first '{' after the route call = the handler body
        out.append({"protocol": "rest", "endpoint": f"{verb} {route}", "handler": "(inline)",
                    "authz": authz, "flags": scan_flags(body), "file": p, "line": line_of(text, m.start())})
    return out


def changed_files(ref: str, src: Path) -> set[Path]:
    out = subprocess.run(["git", "diff", "--name-only", ref, "--", str(src)], capture_output=True, text=True, check=True)
    top = Path(subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True, check=True).stdout.strip())
    return {(top / line).resolve() for line in out.stdout.splitlines() if line.endswith((".js", ".ts", ".jsx", ".tsx"))}


SKIP = ("/node_modules/", "/.next/", "/dist/", "/build/", "/coverage/")


def inventory(src: Path, only: set[Path] | None = None) -> dict:
    endpoints: list[dict] = []
    for f in sorted(src.rglob("*.*")):
        if f.suffix not in (".js", ".ts", ".jsx", ".tsx") or f.name.endswith((".test.js", ".test.ts", ".spec.js", ".spec.ts", ".d.ts")):
            continue
        if any(k in "/" + str(f).replace("\\", "/") + "/" for k in SKIP):
            continue
        if only is not None and f.resolve() not in only:
            continue
        endpoints += endpoints_in(strip_comments(f.read_text(encoding="utf-8", errors="replace")), f, src)
    flagged = [e for e in endpoints if e["flags"] or not e["authz"]]
    return {"source": str(src), "endpoints": endpoints,
            "summary": {"endpoints": len(endpoints), "to_read": len(flagged),
                        "no_authz": sum(not e["authz"] for e in endpoints)}}


def to_markdown(inv: dict) -> str:
    s = inv["summary"]
    out = [f"# Node.js endpoint inventory ({s['endpoints']} endpoints, {s['to_read']} to read)", "",
           "Candidates only. Read the flagged handlers (file:line) to confirm. Middleware that only",
           "authenticates (requireAuth, passport) is not authorization. Next.js `middleware.ts` runs on",
           "the Edge runtime and is not instrumented — check owner rules in the route handler.", "",
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
