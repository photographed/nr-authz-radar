#!/usr/bin/env python3
"""Run the detection catalog against New Relic through NerdGraph, without an LLM in the loop.

Why: scheduled hunts are cheaper and reproducible this way, they work unattended with an API key
(no OAuth), and Claude only has to read a short summary instead of every raw query result.

The queries come from skills/nr-appsec-guard/references/detections.nrql.md (first SQL block of
each detection). Detections the current stage or data sources cannot support are skipped, with
the reason.

Usage:
  NEW_RELIC_API_KEY=... python3 scripts/hunt.py --account-id 1234567 --app shop-api \\
      --stage S2 --sources spans,browser_dt --out .authz-radar/hunt
  python3 scripts/hunt.py --app shop-api --stage S0 --dry-run      # list the queries, no API call
  ... --levels evidence,strong                                        # cheap daily run; full run weekly

Outputs (in --out): hunt-results.json (compact, redacted) and hunt-summary.md (grouped by evidence level).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CATALOG_MD = ROOT / "skills" / "nr-appsec-guard" / "references" / "detections.nrql.md"
DETECTIONS = ROOT / "shared" / "detections.json"
STAGES = ["S0", "S1", "S2", "S3"]
SOURCES = ("spans", "browser_dt", "deployments", "logs")
ENDPOINTS = {"US": "https://api.newrelic.com/graphql", "EU": "https://api.eu.newrelic.com/graphql"}
LEVEL_ORDER = ["evidence", "strong", "anomaly", "risk", "context"]
# Values that identify people or resources: shown as a short prefix in the summary only.
REDACT_KEYS = ("enduser.id", "client.ip_hmac", "api.key_id", "request.uri", "db.statement")
GRAPHQL = ("query($accountId: Int!, $nrql: Nrql!) "
           "{ actor { account(id: $accountId) { nrql(query: $nrql, timeout: 60) { results } } } }")


def parse_catalog(text: str) -> dict[str, str]:
    """Detection ID -> first SQL block of its section."""
    queries = {}
    for m in re.finditer(r"^### (D\d{2}) .*?$(.*?)(?=^### |^## |\Z)", text, re.M | re.S):
        block = re.search(r"```sql\n(.*?)```", m.group(2), re.S)
        if block:
            sql = "\n".join(line for line in block.group(1).splitlines() if not line.strip().startswith("--"))
            queries[m.group(1)] = " ".join(sql.split())
    return queries


def fill(query: str, values: dict[str, str]) -> str:
    for key, value in values.items():
        query = query.replace("{" + key + "}", value)
    return query


def plan(stage: str, sources: set[str], only: set[str] | None, values: dict[str, str],
         levels: set[str] | None = None) -> list[dict]:
    meta = json.loads(DETECTIONS.read_text(encoding="utf-8"))["detections"]
    queries = parse_catalog(CATALOG_MD.read_text(encoding="utf-8"))
    items = []
    for d in sorted(queries):
        m = meta[d]
        item = {"id": d, "name": m["name"], "name_en": m["name_en"], "evidence": m["evidence"], "stage": m["stage"]}
        if only and d not in only:
            continue
        if levels and m["evidence"] not in levels:
            continue
        if STAGES.index(m["stage"]) > STAGES.index(stage):
            item.update(status="skipped", reason=f"stage {m['stage']} needed (now {stage})")
        elif missing := [s for s in m["requires"] if s not in sources]:
            item.update(status="skipped", reason="data source needed: " + ", ".join(missing))
        elif "browserAppName" in queries[d] and not values.get("browserAppName"):
            item.update(status="skipped", reason="--browser-app needed")
        else:
            item.update(status="planned", nrql=fill(queries[d], values))
        items.append(item)
    return items


def http_transport(endpoint: str, api_key: str, body: dict) -> dict:
    req = urllib.request.Request(endpoint, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "API-Key": api_key})
    with urllib.request.urlopen(req, timeout=90) as resp:
        return json.loads(resp.read().decode())


def redact(value):
    if isinstance(value, str) and len(value) > 10:
        return value[:8] + "…"
    return value


def compact(rows: list[dict], limit: int = 5) -> list[dict]:
    out = []
    for row in rows[:limit]:
        clean = {}
        for k, v in row.items():
            if k in ("timestamp",):
                continue
            if any(k == r or k.endswith("." + r) or r in k for r in REDACT_KEYS):
                v = redact(v)
            elif isinstance(v, list):  # facet tuples
                v = [redact(x) for x in v]
            elif isinstance(v, float):
                v = round(v, 3)
            clean[k] = v
        out.append(clean)
    return out


TIME_KEYS = re.compile(r"(timestamp|first_seen|last_seen|earliest|latest|begin|end)", re.I)


def numeric_max(rows: list[dict]) -> float | None:
    """Largest count-like value; timestamps (first_seen, earliest(...)) are not signals."""
    nums = [v for r in rows for k, v in r.items()
            if isinstance(v, (int, float)) and not isinstance(v, bool) and not TIME_KEYS.search(k)]
    return max(nums) if nums else None


def since_seconds(since: str) -> int | None:
    m = re.fullmatch(r"\s*(\d+)\s+(minute|hour|day|week)s?\s+ago\s*", since)
    if not m:
        return None
    return int(m.group(1)) * {"minute": 60, "hour": 3600, "day": 86400, "week": 604800}[m.group(2)]


def first_seen_within(rows: list[dict], seconds: int, now: float) -> int:
    """Rows whose first_seen (epoch ms) is within the window: new destinations / new exception types."""
    cutoff_ms = (now - seconds) * 1000
    count = 0
    for row in rows:
        for key, value in row.items():
            is_first_seen = "first_seen" in key or key.startswith("earliest")
            if is_first_seen and isinstance(value, (int, float)) and value >= cutoff_ms:
                count += 1
                break  # one row = one destination / exception type
    return count


NEW_SINCE = {"D17", "D20"}  # judged by "first seen within --since", not by counts


def run(items: list[dict], account_id: int, endpoint: str, api_key: str, transport=http_transport,
        pause: float = 0.2, since: str = "1 day ago", now: float | None = None) -> list[dict]:
    window = since_seconds(since)
    now = time.time() if now is None else now
    for item in items:
        if item["status"] != "planned":
            continue
        try:
            resp = transport(endpoint, api_key, {"query": GRAPHQL,
                                                 "variables": {"accountId": account_id, "nrql": item["nrql"]}})
            if resp.get("errors"):
                item.update(status="error", error=str(resp["errors"][0].get("message", resp["errors"][0]))[:200])
                continue
            rows = resp["data"]["actor"]["account"]["nrql"]["results"] or []
            item.update(status="ok", row_count=len(rows), max_value=numeric_max(rows), top=compact(rows))
            if item["id"] in NEW_SINCE and window:
                item["new_count"] = first_seen_within(rows, window, now)
        except Exception as e:  # network, auth, malformed response
            item.update(status="error", error=f"{type(e).__name__}: {e}"[:200])
        time.sleep(pause)
    return items


def has_hit(item: dict) -> bool:
    if item.get("status") != "ok":
        return False
    if item.get("id") in NEW_SINCE:
        return (item.get("new_count") or 0) > 0
    return (item.get("max_value") or 0) > 0


def correlations(items: list[dict]) -> list[str]:
    by_id = {i["id"]: i for i in items}
    notes = []
    if has_hit(by_id.get("D20", {})) and has_hit(by_id.get("D21", {})):
        notes.append("D20+D21")
    return notes


TEXT = {
    "ja": {"title": "# Hunt の結果: {app}", "levels": {"evidence": "証拠", "strong": "強い兆候", "anomaly": "異常（攻撃とは呼ばない）",
           "risk": "リスク", "context": "参考"}, "head": "| 検知 | 名前 | 結果 | 最大値 | 上位（要約・一部伏せ字） |",
           "skipped": "## 実行しなかった検知", "skip_head": "| 検知 | 理由 |",
           "corr": "**相関: D20（新しい外部通信）と D21（RCE の試み）が同時に出ている → RCE が成功した可能性（証拠として扱う）**",
           "note": "結果の解釈（しきい値・平常時との比較）は `detections.nrql.md` の各検知の「判定」を参照。異常は偽陽性が多いので、単独で攻撃と判断しない。",
           "nores": "該当なし", "err": "エラー"},
    "en": {"title": "# Hunt results: {app}", "levels": {"evidence": "Evidence", "strong": "Strong signals", "anomaly": "Anomalies (never called attacks)",
           "risk": "Risks", "context": "Context"}, "head": "| Detection | Name | Result | Max | Top rows (summarized, partly masked) |",
           "skipped": "## Detections not run", "skip_head": "| Detection | Why |",
           "corr": "**Correlation: D20 (new outbound destination) and D21 (RCE attempt) together → RCE may have succeeded (treat as evidence)**",
           "note": "Interpret results with the 'judgement' of each detection in `detections.nrql.md`. Anomalies produce many false positives; never conclude an attack from them alone.",
           "nores": "no rows", "err": "error"},
}


def summary(items: list[dict], app: str, lang: str = "ja") -> str:
    t = TEXT[lang]
    out = [t["title"].format(app=app), ""]
    if "D20+D21" in correlations(items):
        out += [t["corr"], ""]
    ran = [i for i in items if i["status"] in ("ok", "error")]
    for level in LEVEL_ORDER:
        group = [i for i in ran if i["evidence"] == level]
        if not group:
            continue
        out += [f"## {t['levels'][level]}", "", t["head"], "|---|---|---|---|---|"]
        for i in group:
            name = i["name"] if lang == "ja" else i["name_en"]
            if i["status"] == "error":
                out.append(f"| {i['id']} | {name} | {t['err']}: {i['error']} | — | — |")
            else:
                result = f"{i['row_count']} rows" if i["row_count"] else t["nores"]
                if "new_count" in i:
                    result += f" / new: {i['new_count']}"
                top = json.dumps(i["top"][:3], ensure_ascii=False)[:300] if i["row_count"] else "—"
                out.append(f"| {i['id']} | {name} | {result} | {i['max_value'] if i['max_value'] is not None else '—'} | `{top}` |")
        out.append("")
    skipped = [i for i in items if i["status"] == "skipped"]
    if skipped:
        out += [t["skipped"], "", t["skip_head"], "|---|---|"]
        out += [f"| {i['id']} | {i['reason']} |" for i in skipped]
        out.append("")
    out.append(t["note"])
    return "\n".join(out) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--app", required=True, help="APM appName / entity.name")
    ap.add_argument("--account-id", type=int)
    ap.add_argument("--stage", choices=STAGES, required=True)
    ap.add_argument("--sources", default="", help="comma separated: " + ", ".join(SOURCES))
    ap.add_argument("--browser-app", default="", help="Browser appName (for queries on AjaxRequest)")
    ap.add_argument("--since", default="1 day ago")
    ap.add_argument("--baseline", default="7 days ago")
    ap.add_argument("--only", default="", help="comma separated detection IDs")
    ap.add_argument("--levels", default="", help="comma separated evidence levels, e.g. evidence,strong for a cheap daily run")
    ap.add_argument("--region", choices=sorted(ENDPOINTS), default="US")
    ap.add_argument("--endpoint", help="NerdGraph endpoint (overrides --region, e.g. for other regions)")
    ap.add_argument("--out", default=".authz-radar/hunt")
    ap.add_argument("--lang", choices=["ja", "en"], default="ja")
    ap.add_argument("--dry-run", action="store_true", help="print the planned queries and exit")
    args = ap.parse_args()

    sources = {s for s in args.sources.split(",") if s}
    if unknown := sources - set(SOURCES):
        ap.error(f"unknown sources: {', '.join(sorted(unknown))}")
    values = {"appName": args.app, "since": args.since, "baseline": args.baseline,
              "browserAppName": args.browser_app, "bypassScopePattern": "admin:%"}
    only = {s.strip() for s in args.only.split(",") if s.strip()} or None
    levels = {s.strip() for s in args.levels.split(",") if s.strip()} or None
    if levels and (bad := levels - set(LEVEL_ORDER)):
        ap.error(f"unknown levels: {', '.join(sorted(bad))}")
    items = plan(args.stage, sources, only, values, levels)

    if args.dry_run:
        for i in items:
            print(f"{i['id']} [{i['evidence']}] {i['status']}: {i.get('nrql') or i.get('reason')}")
        print(f"# {sum(i['status'] == 'planned' for i in items)} queries would run")
        return
    api_key = os.environ.get("NEW_RELIC_API_KEY")
    if not api_key or not args.account_id:
        sys.exit("NEW_RELIC_API_KEY (a User key) and --account-id are required (or use --dry-run)")
    run(items, args.account_id, args.endpoint or ENDPOINTS[args.region], api_key, since=args.since)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for i in items:
        i.pop("nrql", None) if i["status"] == "skipped" else None
    (out / "hunt-results.json").write_text(json.dumps({"app": args.app, "stage": args.stage, "since": args.since,
                                                       "items": items}, ensure_ascii=False, indent=1) + "\n")
    (out / "hunt-summary.md").write_text(summary(items, args.app, args.lang), encoding="utf-8")
    ran = sum(i["status"] in ("ok", "error") for i in items)
    errors = sum(i["status"] == "error" for i in items)
    print(f"{ran} queries run ({errors} errors); summary: {out / 'hunt-summary.md'}")


if __name__ == "__main__":
    main()
