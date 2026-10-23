import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import hunt  # noqa: E402

VALUES = {"appName": "shop-api", "since": "1 day ago", "baseline": "7 days ago",
          "browserAppName": "", "bypassScopePattern": "admin:%"}
NOW = 1_800_000_000.0  # fixed clock (seconds)


def fake_transport(results_by_id, errors=()):
    """Returns NerdGraph-shaped responses keyed by detection ID (found in the query text)."""
    def transport(endpoint, api_key, body):
        nrql = body["variables"]["nrql"]
        for d, rows in results_by_id.items():
            if d in errors and errors[d] in nrql:
                return {"errors": [{"message": "NRQL Syntax Error"}]}
            if results_by_id[d]["match"] in nrql:
                return {"data": {"actor": {"account": {"nrql": {"results": rows["rows"]}}}}}
        return {"data": {"actor": {"account": {"nrql": {"results": []}}}}}
    return transport


class PlanTest(unittest.TestCase):
    def test_catalog_parses_every_detection(self):
        queries = hunt.parse_catalog(hunt.CATALOG_MD.read_text())
        meta = json.loads(hunt.DETECTIONS.read_text())["detections"]
        self.assertEqual(set(queries), set(meta))
        for d, q in queries.items():
            self.assertTrue(q.upper().startswith(("SELECT", "FROM")), d)

    def test_placeholders_are_filled(self):
        for item in hunt.plan("S3", {"spans", "browser_dt", "deployments"}, None, dict(VALUES, browserAppName="shop-web")):
            if item["status"] == "planned":
                left = [p for p in ("{appName}", "{since}", "{baseline}", "{browserAppName}") if p in item["nrql"]]
                self.assertFalse(left, f"{item['id']}: {left}")

    def test_stage_and_sources_are_respected(self):
        items = {i["id"]: i for i in hunt.plan("S0", set(), None, VALUES)}
        self.assertEqual(items["D01"]["status"], "skipped")       # needs S2
        self.assertEqual(items["D07"]["status"], "skipped")       # needs spans
        self.assertEqual(items["D04"]["status"], "planned")
        self.assertIn("stage S2", items["D01"]["reason"])

    def test_only_filter(self):
        items = hunt.plan("S3", {"spans"}, {"D01", "D07"}, VALUES)
        self.assertEqual({i["id"] for i in items}, {"D01", "D07"})

    def test_levels_filter_for_a_cheap_daily_run(self):
        items = hunt.plan("S3", {"spans", "browser_dt", "deployments"}, None, dict(VALUES, browserAppName="w"),
                          {"evidence", "strong"})
        self.assertEqual({i["evidence"] for i in items}, {"evidence", "strong"})
        self.assertIn("D01", {i["id"] for i in items})
        self.assertNotIn("D04", {i["id"] for i in items})

    def test_no_unbounded_span_scan(self):
        for item in hunt.plan("S3", {"spans", "browser_dt", "deployments"}, None, dict(VALUES, browserAppName="w")):
            if item["status"] == "planned" and "FROM Span" in item["nrql"]:
                self.assertNotIn("LIMIT MAX", item["nrql"], item["id"])


class RunTest(unittest.TestCase):
    def run_items(self, results, only=None, errors=()):
        items = hunt.plan("S2", {"spans"}, only, VALUES)
        return hunt.run(items, 1, "https://example.invalid", "key", fake_transport(results, dict(errors)),
                        pause=0, since="1 day ago", now=NOW)

    def test_evidence_hit_and_redaction(self):
        items = self.run_items({"D01": {"match": "resource.owner_match IS FALSE",
                                        "rows": [{"facet": ["/api/v1/orders/{id} (GET)", "order"], "count": 12,
                                                  "enduser.id": "u_3f9a2b7c11d4e5f6"}]}}, only={"D01"})
        d01 = items[0]
        self.assertEqual(d01["status"], "ok")
        self.assertEqual(d01["max_value"], 12)
        self.assertTrue(hunt.has_hit(d01))
        self.assertEqual(d01["top"][0]["enduser.id"], "u_3f9a2b…")   # masked in the summary data

    def test_timestamps_are_not_signals(self):
        old = (NOW - 10 * 86400) * 1000
        items = self.run_items({"D20": {"match": "peer.hostname",
                                        "rows": [{"facet": "api.partner.example", "count": 400, "first_seen": old}]},
                                "D21": {"match": "InvalidClassException",
                                        "rows": [{"facet": ["x", "y"], "count": 3, "first_seen": old}]}},
                               only={"D20", "D21"})
        by_id = {i["id"]: i for i in items}
        self.assertEqual(by_id["D20"]["new_count"], 0)
        self.assertFalse(hunt.has_hit(by_id["D20"]))                 # old destination: not new
        self.assertEqual(hunt.correlations(items), [])                # so no false RCE correlation

    def test_new_destination_with_rce_attempt_is_correlated(self):
        recent = (NOW - 3600) * 1000
        items = self.run_items({"D20": {"match": "peer.hostname",
                                        "rows": [{"facet": "abc.oast.fun", "count": 2, "first_seen": recent}]},
                                "D21": {"match": "InvalidClassException",
                                        "rows": [{"facet": ["x", "y"], "count": 3, "first_seen": recent}]}},
                               only={"D20", "D21"})
        self.assertEqual(hunt.correlations(items), ["D20+D21"])
        self.assertIn("RCE", hunt.summary(items, "shop-api", "en"))

    def test_errors_are_reported_not_raised(self):
        items = self.run_items({"D13": {"match": "stddev", "rows": []}}, only={"D13"}, errors={"D13": "stddev"})
        self.assertEqual(items[0]["status"], "error")
        self.assertIn("Syntax", items[0]["error"])

    def test_summary_groups_by_evidence_level(self):
        items = self.run_items({"D01": {"match": "resource.owner_match IS FALSE", "rows": [{"count": 1}]},
                                "D04": {"match": "403, 404", "rows": [{"deny_or_notfound": 2.5}]}},
                               only={"D01", "D04"})
        ja = hunt.summary(items, "shop-api", "ja")
        self.assertLess(ja.index("## 証拠"), ja.index("## 異常"))
        self.assertIn("攻撃とは呼ばない", ja)
        en = hunt.summary(items, "shop-api", "en")
        self.assertIn("## Evidence", en)
        self.assertIn("never called attacks", en)

    def test_summary_is_small(self):
        rows = [{"facet": f"/api/v1/x{i}", "count": i, "request.uri": f"/api/v1/orders/{i}" * 5} for i in range(500)]
        items = self.run_items({"D03": {"match": "uniqueCount(request.uri)", "rows": rows}}, only={"D03"})
        text = hunt.summary(items, "shop-api", "en")
        self.assertLess(len(text), 2000)   # 500 rows in, a short table out


if __name__ == "__main__":
    unittest.main()
