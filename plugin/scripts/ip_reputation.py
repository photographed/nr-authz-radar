#!/usr/bin/env python3
"""Check IP addresses against a threat-intel reputation database (opt-in, local).

This runs on YOUR machine, against IPs you already have (from a New Relic query, an access log,
an incident). It does NOT send anything to New Relic, and it only talks to the reputation service
you choose with your own API key. Use it to enrich an investigation: "this source IP has been
reported as an attack source before".

Privacy: an IP address is personal data in the GDPR sense (and a personal-related datum under
Japanese law). This tool reads IPs locally and sends each one only to the reputation API you
configure. Nothing is written back to New Relic. See shared/privacy.md. Keep the output with the
rest of the investigation's preserved evidence, not in a shared report.

  # IPs on stdin (one per line, or any text — IPv4/IPv6 are extracted), AbuseIPDB key from the env
  export ABUSEIPDB_KEY=...                       # https://www.abuseipdb.com (free tier available)
  nrql_result.txt | python3 scripts/ip_reputation.py --provider abuseipdb --min-score 25

  python3 scripts/ip_reputation.py --provider abuseipdb 203.0.113.4 198.51.100.9
  python3 scripts/ip_reputation.py --provider stdin-only --format md < ips.txt   # no network; just dedupe/count

Exit code is 0 normally; 2 if any IP meets --min-score (so it can gate a script).
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

# Extract IPv4 and bracketed/plain IPv6 from arbitrary text (log lines, NRQL output, JSON).
IPV4 = r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])"
IPV6 = r"(?<![\w:])(?:[A-Fa-f0-9]{0,4}:){2,7}[A-Fa-f0-9]{0,4}(?![\w:])"  # loose; ipaddress validates
IP_RE = re.compile(f"{IPV4}|{IPV6}")


def extract_ips(text: str) -> list[str]:
    seen, out = set(), []
    for m in IP_RE.finditer(text):
        raw = m.group(0)
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            continue
        key = str(ip)
        if key in seen:
            continue
        seen.add(key)
        out.append(key)
    return out


def is_public(ip: str) -> bool:
    a = ipaddress.ip_address(ip)
    return not (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_reserved or a.is_unspecified)


class AbuseIPDBClient:
    """Minimal AbuseIPDB /check client. Pass http=... in tests to avoid the network."""

    ENDPOINT = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, api_key: str, max_age_days: int = 90, http=None, pause: float = 0.0):
        self.api_key = api_key
        self.max_age_days = max_age_days
        self._http = http or self._urllib_get
        self.pause = pause

    def _urllib_get(self, url: str, headers: dict) -> dict:
        req = urllib.request.Request(url, headers=headers)  # honors HTTPS_PROXY in the env
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def check(self, ip: str) -> dict:
        q = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": str(self.max_age_days)})
        headers = {"Key": self.api_key, "Accept": "application/json"}
        if self.pause:
            time.sleep(self.pause)
        data = self._http(f"{self.ENDPOINT}?{q}", headers).get("data", {})
        return {
            "ip": ip,
            "score": data.get("abuseConfidenceScore"),
            "reports": data.get("totalReports"),
            "last_reported": data.get("lastReportedAt"),
            "country": data.get("countryCode"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "tor": data.get("isTor"),
        }


def lookup(ips: list[str], client, skip_private: bool = True) -> list[dict]:
    out = []
    for ip in ips:
        if skip_private and not is_public(ip):
            out.append({"ip": ip, "score": None, "note": "private/reserved, not checked"})
            continue
        try:
            out.append(client.check(ip))
        except urllib.error.HTTPError as e:
            out.append({"ip": ip, "score": None, "note": f"HTTP {e.code}"})
        except Exception as e:  # noqa: BLE001 - report the failure per IP, keep going
            out.append({"ip": ip, "score": None, "note": type(e).__name__})
    return out


def to_markdown(rows: list[dict], min_score: int) -> str:
    out = ["# IP reputation (local check, not sent to New Relic)", "",
           "Scores are from the reputation provider, not this tool. A high score means the IP was",
           "**reported** before, not that this request was malicious. Treat it as a lead, not proof.", "",
           "| IP | Score | Reports | Last reported | Country | ISP | Note |", "|---|---|---|---|---|---|---|"]
    for r in sorted(rows, key=lambda x: (x.get("score") or -1), reverse=True):
        flag = " ⚠️" if (r.get("score") or 0) >= min_score else ""
        out.append(f"| `{r['ip']}`{flag} | {r.get('score', '—') if r.get('score') is not None else '—'} | "
                   f"{r.get('reports', '—') or '—'} | {r.get('last_reported') or '—'} | {r.get('country') or '—'} | "
                   f"{r.get('isp') or '—'} | {r.get('note', '') or ''} |")
    flagged = [r for r in rows if (r.get("score") or 0) >= min_score]
    out += ["", f"**{len(flagged)} of {len(rows)} IP(s) at or above score {min_score}.**"]
    return "\n".join(out) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("ips", nargs="*", help="IPs to check; if omitted, read them from stdin")
    ap.add_argument("--provider", choices=["abuseipdb", "stdin-only"], default="abuseipdb")
    ap.add_argument("--api-key", default=os.environ.get("ABUSEIPDB_KEY", ""))
    ap.add_argument("--min-score", type=int, default=25, help="flag IPs at or above this abuse score (0-100)")
    ap.add_argument("--max-age-days", type=int, default=90)
    ap.add_argument("--pause", type=float, default=0.0, help="seconds between calls (rate limiting)")
    ap.add_argument("--format", choices=["md", "json"], default="md")
    ap.add_argument("--out")
    args = ap.parse_args()

    text = " ".join(args.ips) if args.ips else sys.stdin.read()
    ips = extract_ips(text)
    if not ips:
        print("no IP addresses found in input", file=sys.stderr)
        return 1

    if args.provider == "stdin-only":
        rows = [{"ip": ip, "score": None, "note": "public" if is_public(ip) else "private/reserved"} for ip in ips]
    else:
        if not args.api_key:
            print("set ABUSEIPDB_KEY (or pass --api-key). Get a free key at https://www.abuseipdb.com", file=sys.stderr)
            return 1
        rows = lookup(ips, AbuseIPDBClient(args.api_key, args.max_age_days, pause=args.pause))

    rendered = json.dumps(rows, ensure_ascii=False, indent=1) if args.format == "json" else to_markdown(rows, args.min_score)
    if args.out:
        from pathlib import Path
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(rendered + "\n", encoding="utf-8")
        print(f"{len(ips)} IP(s) checked: {args.out}", file=sys.stderr)
    else:
        print(rendered)
    return 2 if any((r.get("score") or 0) >= args.min_score for r in rows) else 0


if __name__ == "__main__":
    sys.exit(main())
