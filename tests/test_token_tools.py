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
        for prefix, count in (("D", 22), ("U", 7), ("I", 7), ("R", 16), ("L", 4)):
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


import inventory_php as invphp  # noqa: E402

PHP_SITE = ROOT / "examples" / "php-vuln-site"


class PhpInventoryTest(unittest.TestCase):
    def setUp(self):
        self.inv = invphp.inventory(PHP_SITE)
        self.by_ep = {e["endpoint"]: e for e in self.inv["endpoints"]}

    def test_finds_laravel_routes_with_path_variables(self):
        for ep in ("GET /orders/{id}", "PATCH /orders/{id}/ship", "GET /raw/orders/{id}", "GET /raw/orders"):
            self.assertIn(ep, self.by_ep)

    def test_flags_match_the_deliberate_bugs(self):
        f = lambda ep: set(self.by_ep[ep]["flags"])  # noqa: E731
        self.assertEqual(f("GET /orders/{id}"), set())                 # ensureOwns() is present
        self.assertIn("find_by_id", f("GET /raw/orders/{id}"))         # IDOR, no owner check
        self.assertIn("sql_concat", f("GET /raw/orders"))              # SQL injection
        self.assertTrue(self.inv["raw_sql"])                           # same spot in the raw-SQL list

    def test_only_mode_limits_endpoints(self):
        target = (PHP_SITE / "routes" / "api.php").resolve()
        # routes live in api.php; limiting to it still yields the routes (controllers are read for flags)
        small = invphp.inventory(PHP_SITE, {target})
        self.assertEqual({e["endpoint"] for e in small["endpoints"]}, set(self.by_ep))

    def test_skips_vendor(self):
        self.assertFalse(any("vendor/" in e["file"].replace("\\", "/") for e in self.inv["endpoints"]))


import inventory_python as invpy  # noqa: E402

PY_FIXTURE = ROOT / "tests" / "fixtures" / "python-authz"


class PythonInventoryTest(unittest.TestCase):
    def setUp(self):
        self.inv = invpy.inventory(PY_FIXTURE)
        self.by = {e["endpoint"]: e for e in self.inv["endpoints"]}

    def test_finds_flask_fastapi_and_drf(self):
        self.assertIn("GET /api/orders/<int:order_id>", self.by)     # Flask @bp.route
        self.assertIn("GET /api/v2/orders/{order_id}", self.by)      # FastAPI @router.get
        self.assertTrue(any(e["handler"] == "OrderView.get" for e in self.inv["endpoints"]))  # DRF class view

    def test_flags_and_authz(self):
        f = lambda ep: set(self.by[ep]["flags"])  # noqa: E731
        self.assertIn("get_by_id", f("GET /api/orders/<int:order_id>"))       # IDOR
        self.assertEqual(f("GET /api/orders/<int:order_id>/receipt"), set())  # owner filter present
        self.assertIn("sql_concat", f("GET /api/search"))                      # SQLi
        self.assertFalse(self.by["GET /api/search"]["authz"])                  # no auth decorator
        self.assertFalse(self.by["POST /api/v2/admin/orders/{order_id}/ship"]["authz"])  # BFLA: no Depends
        self.assertIn("command_exec", f("POST /api/v2/admin/orders/{order_id}/ship"))

    def test_drf_permission_classes_count_as_authz(self):
        order_view = next(e for e in self.inv["endpoints"] if e["handler"] == "OrderView.get")
        self.assertTrue(order_view["authz"])              # permission_classes = [IsAuthenticated]
        self.assertIn("get_by_id", order_view["flags"])   # but still IDOR (no owner filter)

    def test_unsafe_deserialization_flagged(self):
        imp = next(e for e in self.inv["endpoints"] if e["handler"] == "ImportView.post")
        self.assertIn("unsafe_deserialization", imp["flags"])

    def test_only_mode(self):
        target = (PY_FIXTURE / "app" / "flask_views.py").resolve()
        small = invpy.inventory(PY_FIXTURE, {target})
        self.assertTrue(all("flask_views.py" in e["file"] for e in small["endpoints"]))


import inventory_node as invnode  # noqa: E402

NODE_FIXTURE = ROOT / "tests" / "fixtures" / "node-authz"


class NodeInventoryTest(unittest.TestCase):
    def setUp(self):
        self.inv = invnode.inventory(NODE_FIXTURE)
        self.by = {e["endpoint"]: e for e in self.inv["endpoints"]}

    def test_finds_express_and_nextjs_routes(self):
        self.assertIn("GET /api/orders/:id", self.by)          # Express router.get
        self.assertIn("GET /api/orders/[id]", self.by)         # Next.js app/**/route.js export GET

    def test_express_flags_and_authz(self):
        f = lambda ep: set(self.by[ep]["flags"])  # noqa: E731
        self.assertIn("find_by_id", f("GET /api/orders/:id"))              # IDOR (findByPk)
        self.assertEqual(f("GET /api/orders/:id/receipt"), set())          # scoped by userId
        self.assertIn("sql_concat", f("GET /api/search"))                  # SQLi template literal
        self.assertFalse(self.by["GET /api/search"]["authz"])              # no auth middleware
        self.assertTrue(self.by["GET /api/orders/:id"]["authz"])           # requireAuth present

    def test_nextjs_route_with_ownership_is_not_flagged(self):
        nextjs = self.by["GET /api/orders/[id]"]
        self.assertTrue(nextjs["authz"])             # withAuthzRadar recognised
        self.assertEqual(set(nextjs["flags"]), set())  # ownership() call = owner hint

    def test_skips_node_modules_and_tests(self):
        self.assertFalse(any("node_modules" in e["file"] for e in self.inv["endpoints"]))


import inventory_ruby as invrb  # noqa: E402
import inventory_go as invgo    # noqa: E402

RB_FIXTURE = ROOT / "tests" / "fixtures" / "ruby-authz"
GO_FIXTURE = ROOT / "tests" / "fixtures" / "go-authz"


class RubyInventoryTest(unittest.TestCase):
    def setUp(self):
        self.inv = invrb.inventory(RB_FIXTURE)
        self.by = {e["endpoint"]: e for e in self.inv["endpoints"]}

    def test_finds_actions_and_routes(self):
        self.assertIn("orders#show", self.by)
        self.assertTrue(self.inv["routes"])   # resources :orders from routes.rb

    def test_flags(self):
        f = lambda ep: set(self.by[ep]["flags"])  # noqa: E731
        self.assertIn("find_by_id", f("orders#show"))      # Order.find(params[:id]) IDOR
        self.assertEqual(f("orders#receipt"), set())       # current_user.orders.find
        self.assertIn("sql_concat", f("orders#search"))    # where("... #{params} ...")

    def test_before_action_scoping_does_not_bleed(self):
        # authenticate_user! is authn; it shows as a filter but the reviewer still reads the action
        self.assertIn("authenticate_user", self.by["orders#show"]["filters"])


class GoInventoryTest(unittest.TestCase):
    def setUp(self):
        self.inv = invgo.inventory(GO_FIXTURE)
        self.by = {e["endpoint"]: e for e in self.inv["endpoints"]}

    def test_finds_routes(self):
        for ep in ("GET /api/orders/{id}", "GET /api/search", "POST /api/admin/orders/{id}/ship"):
            self.assertIn(ep, self.by)

    def test_flags(self):
        self.assertIn("query_by_id", self.by["GET /api/orders/{id}"]["flags"])   # IDOR
        self.assertIn("sql_concat", self.by["GET /api/search"]["flags"])         # fmt.Sprintf
        self.assertIn("command_exec", self.by["POST /api/admin/orders/{id}/ship"]["flags"])
        self.assertTrue(all(not e["authz"] for e in self.inv["endpoints"]))       # fixture has no auth mw
