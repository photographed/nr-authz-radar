import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
ROOT = REPO / "plugin"
sys.path.insert(0, str(ROOT / "scripts"))
import attack_layer  # noqa: E402
import gen_alerts  # noqa: E402
import risk_score  # noqa: E402


class AttackLayerTest(unittest.TestCase):
    def test_layer_shape(self):
        layer = attack_layer.layer("S2", {"spans"})
        self.assertEqual(layer["domain"], "enterprise-attack")
        self.assertEqual(layer["versions"]["attack"], "20")
        for t in layer["techniques"]:
            self.assertRegex(t["techniqueID"], r"^T\d{4}(\.\d{3})?$")
            self.assertIn(t["score"], (1, 2, 3))
        json.dumps(layer)

    def test_evidence_scores_highest(self):
        by_id = {t["techniqueID"]: t for t in attack_layer.layer("S2", {"spans"})["techniques"]}
        self.assertEqual(by_id["T1190"]["score"], 3)            # D01 / D07 are evidence
        self.assertIn("D01 (evidence)", by_id["T1190"]["comment"])

    def test_stage_limits_coverage(self):
        s0 = {t["techniqueID"] for t in attack_layer.layer("S0", set())["techniques"]}
        s3 = {t["techniqueID"] for t in attack_layer.layer("S3", {"spans", "browser_dt", "browser_user", "deployments"})["techniques"]}
        self.assertLess(len(s0), len(s3))
        self.assertNotIn("T1550.001", s0)                        # D14 needs stage S3

    def test_findings_add_code_coverage(self):
        without = {t["techniqueID"] for t in attack_layer.layer("S0", set())["techniques"]}
        with_f = {t["techniqueID"] for t in attack_layer.layer("S0", set(), findings=True)["techniques"]}
        self.assertIn("T1499.003", with_f - without)             # F11 GraphQL hardening


class AttackLabelsTest(unittest.TestCase):
    def test_ranking_shows_attack(self):
        self.assertIn("ATT&CK T1190", risk_score.standards_label("F4"))

    def test_alert_descriptions_carry_attack(self):
        out = Path(tempfile.mkdtemp())
        gen_alerts.generate("S2", {"spans"}, out)
        self.assertIn("ATT&CK T1190", (out / "alerts.tf").read_text())


if __name__ == "__main__":
    unittest.main()
