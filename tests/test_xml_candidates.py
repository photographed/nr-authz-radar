import sys
import unittest
import xml.dom.minidom
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import gen_xml_candidates as gen  # noqa: E402

SRC = ROOT / "tests" / "fixtures" / "java-authz" / "src" / "main" / "java"


class XmlCandidatesTest(unittest.TestCase):
    def setUp(self):
        self.found = {(c.class_name.rsplit(".", 1)[1], c.method): c for c in gen.find_candidates(SRC)}

    def test_high_confidence_sources(self):
        self.assertEqual(self.found[("OrderPermissionEvaluator", "hasPermission")].confidence, "high")
        guard = self.found[("AccessGuard", "canReadOrder")]
        self.assertEqual(guard.confidence, "high")          # named bean called from @PreAuthorize
        self.assertIn("@PreAuthorize", guard.reason)

    def test_name_heuristics_in_authz_like_classes(self):
        self.assertEqual(self.found[("AccessGuard", "checkTenant")].confidence, "medium")
        self.assertIn(("OwnershipService", "verifyOwner"), self.found)

    def test_exclusions(self):
        self.assertNotIn(("AccessGuard", "describe"), self.found)                    # not a check
        self.assertNotIn(("OwnershipService", "isOwnerInternal"), self.found)        # private
        self.assertNotIn(("OwnershipService", "checkAlreadyInstrumented"), self.found)  # @CheckOwnership
        self.assertNotIn(("OrderController", "checkSomething"), self.found)          # class is not authz-like

    def test_xml_is_well_formed_and_never_captures_arguments(self):
        text = gen.to_xml(gen.find_candidates(SRC))
        doc = xml.dom.minidom.parseString(text)
        self.assertEqual(doc.documentElement.tagName, "extension")
        self.assertNotIn("attributeName", text)
        names = {n.firstChild.data for n in doc.getElementsByTagName("className")}
        self.assertIn("com.example.security.AccessGuard", names)

    def test_report_explains_limits(self):
        report = gen.to_report(gen.find_candidates(SRC))
        self.assertIn("引数は記録しない", report)
        self.assertIn("`resource.owner_match` は作れない", report)


if __name__ == "__main__":
    unittest.main()
