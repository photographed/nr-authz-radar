#!/usr/bin/env python3
"""Inventory Java endpoints and flag spots worth reading (saves reading the whole repository).

Regex based, no Java parser: it finds endpoints (REST, GraphQL, STOMP / WebSocket, SOAP, gRPC),
their authorization annotations and suspicious patterns in the handler body. Claude then reads only
the flagged methods to confirm findings. Every flag is a *candidate*, never a finding.

  python3 scripts/inventory_java.py src/main/java --out .authz-radar/inventory.json
  python3 scripts/inventory_java.py src/main/java --changed-since origin/main   # PR review: changed files only
  python3 scripts/inventory_java.py src/main/java --files a/Foo.java,b/Bar.java
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import re
import subprocess
import sys
from pathlib import Path

REST = {"GetMapping": "GET", "PostMapping": "POST", "PutMapping": "PUT", "PatchMapping": "PATCH", "DeleteMapping": "DELETE"}
GRAPHQL = {"QueryMapping": "Query", "MutationMapping": "Mutation", "SubscriptionMapping": "Subscription", "SchemaMapping": None}
STOMP = {"MessageMapping": "SEND", "SubscribeMapping": "SUBSCRIBE"}
ANNOTATION = re.compile(r"@(\w+)(\((?:[^()]|\([^()]*\))*\))?")
METHOD_DECL = re.compile(r"(?:public|protected|private)?\s*[\w<>\[\], ?.]+\s+(\w+)\s*\(([^)]*)\)\s*(?:throws [\w., ]+)?\s*\{")
FIRST_STRING = re.compile(r'"([^"]*)"')

FLAGS = {
    "find_by_id_without_owner": re.compile(r"\.(?:findById|getById|getReferenceById|findOne)\s*\(\s*\w+\s*\)"),
    "sql_concat": re.compile(r"(?:query\w*|update|execute\w*|createNativeQuery|createQuery|prepareStatement)\s*\(\s*\"[^\"]*\"\s*\+"),
    "command_exec": re.compile(r"Runtime\.getRuntime\(\)\.exec|new\s+ProcessBuilder\s*\("),
    "unsafe_deserialization": re.compile(r"new\s+ObjectInputStream\s*\(|\.readObject\s*\(|new\s+XMLDecoder\s*\(|enableDefaultTyping"),
    "returns_entity_directly": re.compile(r"return\s+\w+\.(?:findById|findAll|getById)\b"),
}
CONFIG_FLAGS = {
    "permit_all": re.compile(r"requestMatchers\(\s*((?:\"[^\"]*\"\s*,?\s*)+)\)\s*\.permitAll\(\)"),
    "any_origin_websocket": re.compile(r"setAllowed(?:Origins|OriginPatterns)\(\s*\"\*\"\s*\)"),
}
OWNER_HINT = re.compile(r"(?:Owner|Tenant|User)Id|ByIdAnd\w*(?:Owner|Tenant|User)|@CheckOwnership|hasPermission|checkOwnership", re.I)


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


STRING = re.compile(r'"(?:\\.|[^"\\\n])*"')


def mask_strings(text: str) -> str:
    """Same length, string contents blanked: braces in "/{id}" must not look like code blocks."""
    return STRING.sub(lambda m: '"' + " " * (len(m.group(0)) - 2) + '"', text)


def body_end(masked: str, open_brace: int) -> int:
    depth = 0
    for i in range(open_brace, len(masked)):
        depth += (masked[i] == "{") - (masked[i] == "}")
        if depth == 0:
            return i
    return len(masked)


def annotations_before(text: str, masked: str, pos: int) -> dict[str, str]:
    start = max(masked.rfind(ch, 0, pos) for ch in ";{}") + 1
    return {m.group(1): (m.group(2) or "") for m in ANNOTATION.finditer(text[start:pos])}


def class_prefix(text: str, masked: str) -> tuple[str, str]:
    decl = re.search(r"\b(?:class|interface)\s+(\w+)", masked)
    if not decl:
        return "", ""
    head = annotations_before(text, masked, decl.start())
    prefix = ""
    for key in ("RequestMapping", "MessageMapping"):
        if key in head:
            s = FIRST_STRING.search(head[key])
            prefix = s.group(1) if s else ""
    return decl.group(1), prefix


def join_path(prefix: str, path: str) -> str:
    joined = "/" + "/".join(p.strip("/") for p in (prefix, path) if p and p.strip("/"))
    return joined if joined != "/" or not (prefix or path) else "/"


def endpoints_in(path: Path, root: Path) -> tuple[list[dict], list[dict]]:
    raw = path.read_text(encoding="utf-8", errors="replace")
    text = strip_comments(raw)
    masked = mask_strings(text)
    rel = str(path.relative_to(root))
    cls, prefix = class_prefix(text, masked)
    found, config = [], []
    for name, rx in CONFIG_FLAGS.items():
        for m in rx.finditer(text):
            entry = {"flag": name, "file": rel, "line": text.count("\n", 0, m.start()) + 1}
            if name == "permit_all":
                entry["patterns"] = FIRST_STRING.findall(m.group(1))
            config.append(entry)
    for m in METHOD_DECL.finditer(masked):
        method = m.group(1)
        if method in ("if", "for", "while", "switch", "catch", "synchronized"):
            continue
        ann = annotations_before(text, masked, m.start())
        protocol = kind = route = None
        for a, verb in REST.items():
            if a in ann:
                s = FIRST_STRING.search(ann[a])
                protocol, kind, route = "rest", verb, join_path(prefix, s.group(1) if s else "")
        if "RequestMapping" in ann and not protocol and cls:
            s = FIRST_STRING.search(ann["RequestMapping"])
            verb = re.search(r"RequestMethod\.(\w+)", ann["RequestMapping"])
            protocol, kind, route = "rest", verb.group(1) if verb else "ANY", join_path(prefix, s.group(1) if s else "")
        for a, typ in GRAPHQL.items():
            if a in ann:
                s = re.search(r'(?:name|value|field)\s*=\s*"([^"]+)"', ann[a]) or FIRST_STRING.search(ann[a])
                t = typ or (re.search(r'typeName\s*=\s*"([^"]+)"', ann[a]) or [None, "?"])[1]
                protocol, kind, route = "graphql", "GRAPHQL", f"{t}.{s.group(1) if s else method}"
        for a, verb in STOMP.items():
            if a in ann:
                s = FIRST_STRING.search(ann[a])
                protocol, kind, route = "websocket", f"WS {verb}", (prefix if verb == "SEND" else "") + (s.group(1) if s else method)
        if "PayloadRoot" in ann or "WebMethod" in ann:
            s = re.search(r'localPart\s*=\s*"([^"]+)"', ann.get("PayloadRoot", ""))
            protocol, kind, route = "soap", "SOAP", s.group(1) if s else method
        if not protocol:
            continue
        open_brace = m.end() - 1
        body = text[open_brace:body_end(masked, open_brace) + 1]
        params = text[m.start(2):m.end(2)]
        authz = {k: v for k, v in ann.items() if k in ("PreAuthorize", "PostAuthorize", "Secured", "RolesAllowed", "PermitAll", "DenyAll")}
        flags = [f for f, rx in FLAGS.items() if rx.search(body)]
        if "find_by_id_without_owner" in flags and OWNER_HINT.search(body + params):
            flags.remove("find_by_id_without_owner")
        expr = " ".join(authz.values())
        if kind in ("POST", "PUT", "PATCH", "DELETE") and ":read" in expr and ":write" not in expr:
            flags.append("write_with_read_scope")
        found.append({
            "endpoint": f"{kind} {route}", "protocol": protocol, "handler": f"{cls}#{method}",
            "file": rel, "line": text.count("\n", 0, m.start()) + 1,
            "authz": {k: v.strip("()") for k, v in authz.items()} or None,
            "params": " ".join(params.split())[:120], "flags": flags,
        })
    return found, config


def apply_permit_all(endpoints: list[dict], config: list[dict]) -> None:
    patterns = [p for c in config if c["flag"] == "permit_all" for p in c["patterns"]]
    for e in endpoints:
        path = e["endpoint"].split(" ", 1)[1] if e["protocol"] == "rest" else None
        if path and any(fnmatch.fnmatchcase(path, p.replace("/**", "*")) for p in patterns):
            e["flags"].append("permit_all")


def changed_files(ref: str, src: Path) -> set[Path]:
    out = subprocess.run(["git", "diff", "--name-only", ref, "--", str(src)], capture_output=True, text=True, check=True)
    top = Path(subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True, check=True).stdout.strip())
    return {(top / line).resolve() for line in out.stdout.splitlines() if line.endswith(".java")}


def inventory(src: Path, only: set[Path] | None = None) -> dict:
    endpoints, config = [], []
    for f in sorted(src.rglob("*.java")):
        e, c = endpoints_in(f, src)
        config += c
        if only is None or f.resolve() in only:
            endpoints += e
    apply_permit_all(endpoints, config)
    flagged = [e for e in endpoints if e["flags"] or not e["authz"]]
    return {"source": str(src), "endpoints": endpoints, "config": config,
            "summary": {"endpoints": len(endpoints), "to_read": len(flagged),
                        "by_protocol": {p: sum(e["protocol"] == p for e in endpoints)
                                        for p in sorted({e["protocol"] for e in endpoints})}}}


def to_markdown(inv: dict) -> str:
    out = [f"# Endpoint inventory ({inv['summary']['endpoints']} endpoints, {inv['summary']['to_read']} to read)", "",
           "Candidates only. Read the flagged methods (file:line) to confirm.", "",
           "| Endpoint | Handler | Authorization | Flags | Location |", "|---|---|---|---|---|"]
    for e in inv["endpoints"]:
        authz = "; ".join(f"@{k}({v})" for k, v in (e["authz"] or {}).items()) or "**none**"
        out.append(f"| `{e['endpoint']}` | `{e['handler']}` | {authz} | {', '.join(e['flags']) or '—'} | `{e['file']}:{e['line']}` |")
    if inv["config"]:
        out += ["", "| Config flag | Location | Detail |", "|---|---|---|"]
        out += [f"| {c['flag']} | `{c['file']}:{c['line']}` | {', '.join(c.get('patterns', [])) or '—'} |" for c in inv["config"]]
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
    s = inv["summary"]
    print(f"{s['endpoints']} endpoints ({s['by_protocol']}), {s['to_read']} to read: {out.with_suffix('.md')}", file=sys.stderr)


if __name__ == "__main__":
    main()
