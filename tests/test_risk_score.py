import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "plugin" / "scripts"))
from risk_score import rank  # noqa: E402


def finding(fid, ftype="F4", traffic=10.0, attack="none", **features):
    base = {"data_sensitivity": "personal", "privilege": "user", "auth_required": True,
            "id_type": "sequential", "exposure": "external"}
    base.update(features)
    return {"id": fid, "endpoint": f"GET /api/{fid}/{{id}}", "finding_type": ftype,
            "confidence": "likely", "features": base,
            "runtime": {"traffic_rpm": traffic, "attack_signal": attack}}


class RiskScoreTest(unittest.TestCase):
    def test_unused_critical_api_is_not_demoted(self):
        rows = rank([
            finding("busy_medium", ftype="F8", traffic=500, data_sensitivity="internal"),
            finding("dormant_critical", traffic=0, data_sensitivity="sensitive_personal"),
        ])
        self.assertEqual(rows[0]["id"], "dormant_critical")
        self.assertIn("dormant_critical", rows[0]["flags"])
        self.assertEqual(rows[0]["first_action"], "disable_or_remove")

    def test_attack_signal_promotes_to_p0(self):
        rows = rank([
            finding("critical_quiet", data_sensitivity="sensitive_personal"),
            finding("high_attacked", attack="strong", id_type="uuid"),
        ])
        self.assertEqual(rows[0]["id"], "high_attacked")
        self.assertEqual(rows[0]["priority"], "P0")

    def test_not_observed_is_flagged_not_dormant(self):
        rows = rank([finding("x", traffic=None, data_sensitivity="sensitive_personal")])
        self.assertIn("not_observed", rows[0]["flags"])
        self.assertNotIn("dormant_critical", rows[0]["flags"])

    def test_sqli_floor_on_low_data_endpoint(self):
        rows = rank([finding("sqli", ftype="F7", data_sensitivity="none")])
        self.assertEqual(rows[0]["impact"], 4)
        self.assertEqual(rows[0]["tier"], "Critical")

    def test_gateway_override_lowers_exploitability(self):
        f = finding("scope", ftype="F2")
        f["endpoint"] = "GET /internal/batch/run"
        without = rank([f])[0]
        with_ov = rank([f], [{"path": "/internal/**", "gateway_enforced": True,
                              "exposure": "internal_only"}])[0]
        self.assertLess(with_ov["exploitability"], without["exploitability"])

    def test_exploitability_never_zero(self):
        f = finding("internal", ftype="F2", exposure="internal_only", gateway_enforced=True)
        self.assertEqual(rank([f])[0]["exploitability"], 1)

    def test_rce_floor_is_max_impact(self):
        for ftype in ("F9", "F10"):
            row = rank([finding("rce", ftype=ftype, data_sensitivity="none", privilege="none")])[0]
            self.assertEqual(row["impact"], 5)
            self.assertEqual(row["tier"], "Critical")

    def test_deterministic_order(self):
        items = [finding(f"f{i}", traffic=i) for i in range(5)]
        a = [r["id"] for r in rank(items)]
        b = [r["id"] for r in rank(list(reversed(items)))]
        self.assertEqual(a, b)


if __name__ == "__main__":
    unittest.main()
