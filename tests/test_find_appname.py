"""find_appname.py: bind a repository to its New Relic appName(s)."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import find_appname as fa  # noqa: E402

FIXTURE = ROOT / "tests" / "fixtures" / "appname"


class FindAppNameTest(unittest.TestCase):
    def setUp(self):
        self.res = fa.find(FIXTURE)
        self.names = {c["app_name"]: c for c in self.res["candidates"]}

    def test_reads_each_agent_config(self):
        self.assertEqual(self.names["Shop Orders API"]["agent"], "java/ruby")        # newrelic.yml scalar
        self.assertEqual(self.names["checkout-web"]["agent"], "node")                # newrelic.cjs list
        self.assertEqual(self.names["inventory-service"]["agent"], "python/php")     # newrelic.ini
        for n in ("Shop Orders API", "checkout-web", "inventory-service"):
            self.assertEqual(self.names[n]["confidence"], "high")

    def test_node_list_keeps_every_app(self):
        self.assertIn("checkout-web", self.names)
        self.assertIn("checkout-web-canary", self.names)

    def test_env_var_literal_is_medium(self):
        self.assertEqual(self.names["Payments API"]["confidence"], "medium")
        self.assertIn("NEW_RELIC_APP_NAME", self.names["Payments API"]["note"])
        self.assertEqual(self.names["Batch Runner"]["agent"], "env")                 # Dockerfile ENV

    def test_interpolated_value_is_low_and_not_a_real_name(self):
        low = [c for c in self.res["candidates"] if c["confidence"] == "low"]
        self.assertTrue(low)
        self.assertTrue(all(c["app_name"].startswith("(") for c in low))             # not a usable name
        self.assertNotIn("${WORKER_APP_NAME}", self.names)

    def test_summary_flags_ambiguity(self):
        self.assertTrue(self.res["summary"]["needs_confirmation"])                   # many names here
        self.assertNotIn("(set via NEW_RELIC_APP_NAME)", self.res["summary"]["distinct_app_names"])

    def test_single_app_repo_does_not_need_confirmation(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "newrelic.ini").write_text("[newrelic]\napp_name = only-one\n")
            res = fa.find(Path(d))
            self.assertEqual(res["summary"]["distinct_app_names"], ["only-one"])
            self.assertFalse(res["summary"]["needs_confirmation"])

    def test_semicolon_multi_app_is_split(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "newrelic.yml").write_text("common: &x\n  app_name: A;B;C\n")
            res = fa.find(Path(d))
            self.assertEqual(set(res["summary"]["distinct_app_names"]), {"A", "B", "C"})

    def test_skips_vendored_configs(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            v = Path(d) / "node_modules" / "pkg"
            v.mkdir(parents=True)
            (v / "newrelic.js").write_text("exports.config={app_name:['vendored']}")
            res = fa.find(Path(d))
            self.assertNotIn("vendored", res["summary"]["distinct_app_names"])
