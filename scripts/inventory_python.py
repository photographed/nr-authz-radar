#!/usr/bin/env python3
"""Inventory Python endpoints and flag spots worth reading (saves reading the whole repository).

Regex based, no Python AST. It finds Flask / FastAPI route decorators (and DRF / Django class
views) with the authorization decorators or dependencies on them, and suspicious patterns in the
handler body. Claude then reads only the flagged handlers to confirm. Every flag is a *candidate*.

  python3 scripts/inventory_python.py app --out .authz-radar/inventory.json
  python3 scripts/inventory_python.py . --changed-since origin/main
  python3 scripts/inventory_python.py app --files app/views.py,app/api.py
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

# @app.route("/x", methods=["GET"]) | @bp.get("/x") | @router.post("/x") | @api_view(["GET"])
ROUTE_METHOD = re.compile(r"@(\w+)\.(route|get|post|put|patch|delete)\s*\(\s*([\"'])([^\"']*)\3([^)]*)\)")
API_VIEW = re.compile(r"@api_view\s*\(\s*\[([^\]]*)\]")
METHODS_KW = re.compile(r"methods\s*=\s*\[([^\]]*)\]")
DEF = re.compile(r"^(\s*)(?:async\s+)?def\s+(\w+)\s*\(([^)]*)\)", re.M)
CLASS = re.compile(r"^class\s+(\w+)", re.M)
# DRF / Django class-based view HTTP methods
HTTP_METHODS = {"get", "post", "put", "patch", "delete"}

AUTHZ_DECORATORS = re.compile(r"@(?:\w+\.)?(login_required|jwt_required|token_required|requires?_\w*|permission_\w*|authenticated|has_\w*|roles?_required|authorize\w*)", re.I)
AUTHZ_DEP = re.compile(r"(Depends|Security)\s*\(\s*([\w.]+)", re.I)
PERMISSION_CLASSES = re.compile(r"permission_classes\s*=\s*\[([^\]]*)\]")

FLAGS = {
    "get_by_id": re.compile(r"\.objects\.get\s*\(\s*(?:pk|id)\s*=|get_object_or_404\s*\([^,]+,\s*(?:pk|id)\s*=|\.query\.get\s*\(|session\.get\s*\(\s*\w+\s*,|\.get\s*\(\s*(?:pk|id)\s*="),
    "sql_concat": re.compile(r"(?:execute|executemany|\.raw|\.extra|text)\s*\(\s*(?:f[\"']|[\"'][^\"']*[\"']\s*(?:%|\.format|\+)|\w+\s*%)"),
    "command_exec": re.compile(r"os\.system\s*\(|subprocess\.\w+\([^)]*shell\s*=\s*True|\bos\.popen\s*\(|\beval\s*\(|\bexec\s*\("),
    "unsafe_deserialization": re.compile(r"pickle\.loads?\s*\(|yaml\.load\s*\((?![^)]*Safe)|\byaml\.unsafe_load\s*\(|marshal\.loads?\s*\("),
    "mass_assignment": re.compile(r"\(\s*\*\*request\.(?:json|data|form|args|POST|GET)|\.update\s*\(\s*\*\*request\."),
}
OWNER_HINT = re.compile(r"filter(?:_by)?\s*\([^)]*(?:user|owner|tenant|account)(?:_id)?\s*=|request\.user|current_user|\.owner|user_id\s*==|get_object_or_404\s*\([^)]*(?:user|owner)", re.I)


def strip_comments(text: str) -> str:
    out = []
    for line in text.split("\n"):
        h = line.find("#")
        out.append(line if h < 0 else line[:h])
    return "\n".join(out)


def line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def body_from_def(text: str, def_match: re.Match) -> str:
    """Lines more indented than the def line (Python block by indentation)."""
    indent = len(def_match.group(1))
    start = text.find("\n", def_match.end())
    if start < 0:
        return ""
    lines, out = text[start + 1:].split("\n"), []
    for ln in lines:
        if ln.strip() == "":
            out.append(ln)
            continue
        if len(ln) - len(ln.lstrip()) <= indent:
            break
        out.append(ln)
    return "\n".join(out)


def decorators_above(text: str, def_start: int) -> list[str]:
    """Contiguous @decorator lines directly above the def."""
    before = text[:def_start].rstrip("\n").split("\n")
    out = []
    for ln in reversed(before):
        s = ln.strip()
        if s.startswith("@"):
            out.insert(0, s)
        elif s == "":
            continue
        else:
            break
    return out


def scan_flags(body: str) -> list[str]:
    flags = [name for name, pat in FLAGS.items() if pat.search(body)]
    if "get_by_id" in flags and OWNER_HINT.search(body):
        flags.remove("get_by_id")
    return flags


def enclosing_class(text: str, pos: int) -> str | None:
    last = None
    for m in CLASS.finditer(text):
        if m.start() < pos:
            last = m.group(1)
        else:
            break
    return last


def endpoints_in(text: str, path: str) -> list[dict]:
    out: list[dict] = []
    for dm in DEF.finditer(text):
        name, params = dm.group(2), dm.group(3)
        decos = decorators_above(text, dm.start())
        body = body_from_def(text, dm)
        route = None
        verbs = []
        for d in decos:
            m = ROUTE_METHOD.search(d)
            if m:
                verb = m.group(2).upper()
                if verb == "ROUTE":
                    mk = METHODS_KW.search(m.group(5))
                    verbs = [v.strip().strip("\"'").upper() for v in mk.group(1).split(",")] if mk else ["GET"]
                else:
                    verbs = [verb]
                route = m.group(4)
                break
            av = API_VIEW.search(d)
            if av:
                verbs = [v.strip().strip("\"'").upper() for v in av.group(1).split(",")]
                route = "?"  # path is in urls.py; flag it for manual mapping
                break
        # DRF / Django class view method (get/post/...) inside a class
        cls = None
        if route is None and name.lower() in HTTP_METHODS:
            cls = enclosing_class(text, dm.start())
            if cls and (cls.endswith("View") or cls.endswith("ViewSet") or "APIView" in text):
                verbs = [name.upper()]
                route = "?"  # mapped in urls.py
        if route is None:
            continue
        authz = bool(AUTHZ_DECORATORS.search("\n".join(decos))) or bool(AUTHZ_DEP.search(params))
        if cls:  # class view: permission_classes on the class
            seg = text[:dm.start()]
            cls_start = seg.rfind(f"class {cls}")
            pc = PERMISSION_CLASSES.search(text[cls_start:dm.start()]) if cls_start >= 0 else None
            if pc and pc.group(1).strip():
                authz = True
        handler = f"{cls}.{name}" if cls else name
        for v in verbs:
            out.append({"protocol": "rest", "endpoint": f"{v} {route}", "handler": handler,
                        "authz": authz, "flags": scan_flags(body), "file": path, "line": line_of(text, dm.start())})
    return out


def changed_files(ref: str, src: Path) -> set[Path]:
    out = subprocess.run(["git", "diff", "--name-only", ref, "--", str(src)], capture_output=True, text=True, check=True)
    top = Path(subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True, check=True).stdout.strip())
    return {(top / line).resolve() for line in out.stdout.splitlines() if line.endswith(".py")}


SKIP = ("/venv/", "/.venv/", "/site-packages/", "/migrations/", "/node_modules/", "/__pycache__/")


def inventory(src: Path, only: set[Path] | None = None) -> dict:
    endpoints: list[dict] = []
    for f in sorted(src.rglob("*.py")):
        if any(k in "/" + str(f).replace("\\", "/") + "/" for k in SKIP):
            continue
        if only is not None and f.resolve() not in only:
            continue
        endpoints += endpoints_in(strip_comments(f.read_text(encoding="utf-8", errors="replace")), str(f))
    flagged = [e for e in endpoints if e["flags"] or not e["authz"]]
    unmapped = sum(e["endpoint"].endswith(" ?") for e in endpoints)
    return {"source": str(src), "endpoints": endpoints,
            "summary": {"endpoints": len(endpoints), "to_read": len(flagged),
                        "no_authz": sum(not e["authz"] for e in endpoints), "path_in_urls_py": unmapped}}


def to_markdown(inv: dict) -> str:
    s = inv["summary"]
    out = [f"# Python endpoint inventory ({s['endpoints']} endpoints, {s['to_read']} to read)", "",
           "Candidates only. Read the flagged handlers (file:line) to confirm. A path shown as `?` is",
           "routed in `urls.py` (Django / DRF) — map it there. Being authenticated is not authorization.", "",
           "| Endpoint | Handler | Authz | Flags | Location |", "|---|---|---|---|---|"]
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
          f"({inv['summary']['no_authz']} with no authz, {inv['summary']['path_in_urls_py']} routed in urls.py): "
          f"{out.with_suffix('.md')}", file=sys.stderr)


if __name__ == "__main__":
    main()
