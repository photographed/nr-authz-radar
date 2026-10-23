import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import gen_alerts  # noqa: E402

CATALOG = json.loads((ROOT / "shared" / "alerts.json").read_text())
DETECTIONS = set(re.findall(r"^### (D\d{2}) ",
                            (ROOT / "skills/nr-appsec-guard/references/detections.nrql.md").read_text(), re.M))


class CatalogTest(unittest.TestCase):
    def test_every_detection_is_an_alert_or_hunt_only(self):
        alerts = {a["id"] for a in CATALOG["alerts"]}
        hunt = set(CATALOG["hunt_only"])
        self.assertFalse(alerts & hunt)
        self.assertEqual(alerts | hunt, DETECTIONS)

    def test_alert_nrql_uses_no_clauses_alerts_cannot_take(self):
        for a in CATALOG["alerts"]:
            for clause in ("SINCE", "UNTIL", "LIMIT", "COMPARE WITH", "TIMESERIES"):
                self.assertNotIn(clause, a["nrql"].upper(), f"{a['id']} uses {clause}")

    def test_stage_matches_detection_catalog(self):
        text = (ROOT / "skills/nr-appsec-guard/references/detections.nrql.md").read_text()
        for a in CATALOG["alerts"]:
            header = re.search(rf"^### {a['id']} .*$", text, re.M).group(0)
            self.assertIn(f"段階 {a['stage']}", header, a["id"])

    def test_runbooks_exist(self):
        for a in CATALOG["alerts"]:
            self.assertTrue((ROOT / "templates/knowledge-runbooks" / a["runbook"]).exists(), a["runbook"])


class GeneratorTest(unittest.TestCase):
    def run_gen(self, stage, sources):
        out = Path(tempfile.mkdtemp())
        chosen, skipped = gen_alerts.generate(stage, set(sources), out)
        return out, {a["id"] for a in chosen}, {a["id"] for a, _ in skipped}

    def test_s0_without_sources_has_only_agent_level_alerts(self):
        _, chosen, skipped = self.run_gen("S0", [])
        self.assertEqual(chosen, {"D04", "D06", "D10", "D21"})
        self.assertIn("D01", skipped)
        self.assertIn("D07", skipped)  # needs spans

    def test_s2_adds_idor_evidence(self):
        _, chosen, _ = self.run_gen("S2", ["spans"])
        self.assertTrue({"D01", "D02", "D03", "D07"} <= chosen)
        self.assertNotIn("D11", chosen)

    def test_skipped_report_says_what_would_enable_it(self):
        out, _, _ = self.run_gen("S0", [])
        report = (out / "SKIPPED.md").read_text()
        self.assertIn("## 推奨", report)
        self.assertIn("段階 S2 が必要", report)
        self.assertIn("Browser + 分散トレーシング", report)

    def test_hcl_template_sequences_are_escaped(self):
        out, _, _ = self.run_gen("S1", [])
        tf = (out / "alerts.tf").read_text()
        self.assertIn("LIKE '%%{%}%'", tf)          # %{ would start an HCL template directive
        self.assertIn("appName = '${var.app_name}'", tf)
        for query in re.findall(r'query = "(.*)"', tf):
            self.assertNotRegex(query.replace("${var.", ""), r"(?<![$%])[$%]\{", query)

    def test_static_terraform_is_copied(self):
        out, _, _ = self.run_gen("S0", [])
        for name in ("versions.tf", "variables.tf", "main.tf", "workflows.tf", "alerts.tf"):
            self.assertTrue((out / name).exists(), name)


if __name__ == "__main__":
    unittest.main()
