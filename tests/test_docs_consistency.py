import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REFS = ROOT / "skills" / "nr-appsec-guard" / "references"


class DocsConsistencyTest(unittest.TestCase):
    def test_referenced_detections_exist(self):
        defined = set(re.findall(r"^### (D\d{2}) ", (REFS / "detections.nrql.md").read_text(), re.M))
        self.assertEqual(len(defined), 18)
        for path in [REFS / "readiness-checks.md", REFS / "detections.nrql.md"]:
            for ref in set(re.findall(r"\bD\d{2}\b", path.read_text())):
                self.assertIn(ref, defined, f"{path.name} references undefined {ref}")

    def test_spec_attributes_used_in_queries_are_defined(self):
        spec = (ROOT / "shared" / "attribute-spec.md").read_text()
        queries = (REFS / "detections.nrql.md").read_text()
        for attr in set(re.findall(r"\b((?:authz|resource|client|api|auth|edge)\.[a-z_]+)\b", queries)):
            self.assertIn(f"`{attr}`", spec, f"{attr} used in NRQL but not in attribute-spec.md")


class StandardsMappingTest(unittest.TestCase):
    def setUp(self):
        import json
        self.std = json.loads((ROOT / "shared" / "standards.json").read_text())

    def test_every_finding_type_is_mapped(self):
        import sys
        sys.path.insert(0, str(ROOT / "scripts"))
        from risk_score import BASE_EXPLOIT
        self.assertEqual(set(self.std["findings"]), set(BASE_EXPLOIT))

    def test_every_detection_is_mapped(self):
        defined = set(re.findall(r"^### (D\d{2}) ", (REFS / "detections.nrql.md").read_text(), re.M))
        self.assertEqual(set(self.std["detections"]), defined)

    def test_label_formats(self):
        pats = {"cwe": r"CWE-\d+", "asvs": r"V\d{1,2}", "owasp_top10": r"A\d{2}",
                "owasp_api": r"API\d{1,2}", "oat": r"OAT-\d{3}", "ipa": r"\d+\.\d+"}
        for group in ("findings", "detections"):
            for key, entry in self.std[group].items():
                for field, pat in pats.items():
                    for v in entry[field]:
                        self.assertRegex(v, f"^{pat}$", f"{group}.{key}.{field}={v}")

    def test_readme_lists_finding_cwes(self):
        readme = (ROOT / "README.md").read_text()
        for key, entry in self.std["findings"].items():
            for cwe in entry["cwe"]:
                self.assertIn(cwe, readme, f"README is missing {cwe} ({key})")


if __name__ == "__main__":
    unittest.main()
