"""catalog.py and inventory_java.py: the tools that keep Claude from reading whole files."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import catalog  # noqa: E402
import inventory_java as inv  # noqa: E402

SAMPLE = ROOT / "examples" / "sample-app" / "src" / "main" / "java"
FIXTURE = ROOT / "tests" / "fixtures" / "java-authz" / "src" / "main" / "java"


class CatalogTest(unittest.TestCase):
    def test_index_lists_every_item_compactly(self):
        text = catalog.index()
        for prefix, count in (("D", 21), ("U", 6), ("I", 7), ("R", 15)):
            self.assertEqual(sum(line.startswith(prefix) for line in text.splitlines()), count, prefix)
        refs = sum(len((catalog.REFS / f).read_text()) for f in catalog.FILES.values())
        self.assertLess(len(text), refs / 8)   # the point: an index is far smaller than the files

    def test_index_by_stage_hides_what_cannot_run(self):
        text = catalog.index("S0")
        self.assertNotIn("D01 ", text)
        self.assertIn("D04 ", text)

    def test_show_returns_only_requested_sections(self):
        text = catalog.show(["D01", "I05"])
        self.assertIn("### D01", text)
        self.assertIn("### I05", text)
        self.assertNotIn("### D02", text)

    def test_english_index(self):
        self.assertIn("[evidence] Evidence of a successful IDOR", catalog.index(lang="en"))


class InventoryTest(unittest.TestCase):
    def setUp(self):
        self.inv = inv.inventory(SAMPLE)
        self.by_ep = {e["endpoint"]: e for e in self.inv["endpoints"]}

    def test_finds_rest_and_graphql_endpoints_with_path_variables(self):
        for ep in ("GET /api/v1/orders/{id}", "GET /api/v1/orders/{id}/receipt", "POST /api/v1/orders/{id}/cancel",
                   "GET /api/v0/members/{id}/profile", "PUT /api/admin/users/{id}/role",
                   "GET /api/v1/products/search", "GRAPHQL Query.order"):
            self.assertIn(ep, self.by_ep)

    def test_flags_match_the_manual_review(self):
        f = lambda ep: set(self.by_ep[ep]["flags"])  # noqa: E731
        self.assertIn("find_by_id_without_owner", f("GET /api/v1/orders/{id}"))
        self.assertIn("find_by_id_without_owner", f("GRAPHQL Query.order"))
        self.assertEqual(f("GET /api/v1/orders/{id}/receipt"), set())          # uses findByIdAndOwnerId
        self.assertIn("write_with_read_scope", f("POST /api/v1/orders/{id}/cancel"))
        self.assertIn("sql_concat", f("GET /api/v1/products/search"))
        self.assertIn("permit_all", f("GET /api/v0/members/{id}/profile"))
        self.assertIsNone(self.by_ep["PUT /api/admin/users/{id}/role"]["authz"])
        self.assertIn("any_origin_websocket", {c["flag"] for c in self.inv["config"]})

    def test_only_mode_limits_endpoints_but_keeps_config(self):
        target = (SAMPLE / "com/example/shop/search/SearchController.java").resolve()
        small = inv.inventory(SAMPLE, {target})
        self.assertEqual([e["endpoint"] for e in small["endpoints"]], ["GET /api/v1/products/search"])
        self.assertTrue(small["config"])

    def test_read_list_is_smaller_than_the_source(self):
        md = inv.to_markdown(self.inv)
        source = sum(len(p.read_text()) for p in SAMPLE.rglob("*.java"))
        self.assertLess(len(md), source)
        self.assertLess(self.inv["summary"]["to_read"], self.inv["summary"]["endpoints"])

    def test_comments_do_not_create_endpoints(self):
        self.assertTrue(all("checkSomething" not in e["handler"] for e in inv.inventory(FIXTURE)["endpoints"]
                            if e["protocol"] != "rest"))


if __name__ == "__main__":
    unittest.main()


class SkillBudgetTest(unittest.TestCase):
    """SKILL.md is loaded every time a skill runs: keep it a short router."""
    BUDGET = 6000  # bytes

    def test_skill_files_stay_small(self):
        for skill in (ROOT / "skills").glob("*/SKILL.md"):
            self.assertLessEqual(len(skill.read_bytes()), self.BUDGET, f"{skill.parent.name}/SKILL.md grew too large")

    def test_files_referenced_from_skills_exist(self):
        import re
        for skill in (ROOT / "skills").glob("*/SKILL.md"):
            text = skill.read_text()
            for ref in set(re.findall(r"`((?:\.\./[\w-]+/)?(?:references|shared|scripts|templates)/[\w./-]+?\.(?:md|json|py|yaml))`", text)):
                base = skill.parent if not ref.startswith(("shared/", "scripts/", "templates/")) else ROOT
                self.assertTrue((base / ref).resolve().exists(), f"{skill.parent.name}: {ref}")
