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


if __name__ == "__main__":
    unittest.main()
