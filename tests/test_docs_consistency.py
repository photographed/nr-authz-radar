import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REFS = ROOT / "skills" / "nr-appsec-guard" / "references"


class DocsConsistencyTest(unittest.TestCase):
    def test_referenced_detections_exist(self):
        defined = set(re.findall(r"^### (D\d{2}) ", (REFS / "detections.nrql.md").read_text(), re.M))
        self.assertEqual(len(defined), 23)
        for path in [REFS / "readiness-checks.md", REFS / "detections.nrql.md"]:
            for ref in set(re.findall(r"\bD\d{2}\b", path.read_text())):
                self.assertIn(ref, defined, f"{path.name} references undefined {ref}")

    def test_spec_attributes_used_in_queries_are_defined(self):
        spec = (ROOT / "shared" / "attribute-spec.md").read_text()
        queries = (REFS / "detections.nrql.md").read_text()
        for attr in set(re.findall(r"\b((?:authz|resource|client|api|auth|edge)\.[a-z_]+)\b", queries)):
            self.assertIn(f"`{attr}`", spec, f"{attr} used in NRQL but not in attribute-spec.md")


def _defined(prefix, filename):
    return set(re.findall(rf"^### ({prefix}\d{{2}}) ", (REFS / filename).read_text(), re.M))


class GoalStructureTest(unittest.TestCase):
    FILES = {"D": "detections.nrql.md", "U": "usage.nrql.md", "I": "investigation.nrql.md", "R": "readiness-checks.md",
             "L": "logs.nrql.md"}

    def test_every_reference_is_defined(self):
        defined = {p: _defined(p, f) for p, f in self.FILES.items()}
        docs = list((ROOT / "shared").glob("*.md")) + list((ROOT / "skills").rglob("*.md")) + [ROOT / "README.md"]
        for path in docs:
            text = path.read_text()
            for prefix in self.FILES:
                for ref in set(re.findall(rf"\b({prefix}\d{{2}})\b", text)):
                    if path.name == "README.md" and ref in ("D16", "D19"):
                        continue  # roadmap history mentions the old IDs
                    self.assertIn(ref, defined[prefix], f"{path.relative_to(ROOT)} references undefined {ref}")

    def test_detections_and_usage_declare_stage(self):
        for filename in ("detections.nrql.md", "usage.nrql.md"):
            for line in (REFS / filename).read_text().splitlines():
                if re.match(r"^### [DU]\d{2} ", line):
                    self.assertRegex(line, r"段階 S[0-3]", f"{filename}: {line}")

    def test_log_queries_are_scoped_never_scans(self):
        text = (REFS / "logs.nrql.md").read_text()
        blocks = re.findall(r"```sql\n(.*?)```", text, re.S)
        self.assertGreaterEqual(len(blocks), 4)
        for sql in blocks:
            if "FROM Log" not in sql:
                continue
            self.assertNotIn("SELECT *", sql)
            self.assertRegex(sql, r"LIMIT (\d+)")
            self.assertLessEqual(int(re.search(r"LIMIT (\d+)", sql).group(1)), 200, sql)
            self.assertRegex(sql, r"SINCE \{(since|from)\}", sql)               # a bounded window
            self.assertTrue(any(k in sql for k in ("trace.id IN", "'authz-radar ", "{pathPrefix}", "{edgeLogFilter}")),
                            "log query must be scoped by an APM key or an explicit filter: " + sql)

    def test_hunt_never_reads_logs(self):
        import sys
        sys.path.insert(0, str(ROOT / "scripts"))
        import hunt
        for blocks in hunt.parse_all(hunt.CATALOG_MD.read_text()).values():
            for sql in blocks:
                self.assertNotIn("FROM Log", sql)

    def test_usage_and_investigation_counts(self):
        self.assertEqual(len(_defined("U", "usage.nrql.md")), 7)
        self.assertEqual(len(_defined("I", "investigation.nrql.md")), 7)

    def test_reports_separate_now_from_recommendations(self):
        goals = (ROOT / "shared" / "goals.md").read_text()
        self.assertIn("## 今のデータでわかること・できること", goals)
        self.assertIn("## 推奨（段階的に）", goals)
        for skill in ("nr-appsec-guard", "api-authz-review"):
            text = (ROOT / "skills" / skill / "SKILL.md").read_text()
            self.assertIn("shared/goals.md", text, f"{skill} must follow the report rules")


class JavaContractTest(unittest.TestCase):
    def test_java_attribute_names_match_spec(self):
        java = (ROOT / "instrumentation/java/src/main/java/io/github/photographed/authzradar/AuthzAttributes.java").read_text()
        spec = (ROOT / "shared" / "attribute-spec.md").read_text()
        names = re.findall(r'String [A-Z_]+ = "((?:authz|resource|client|api|auth)\.[a-z_]+)"', java)
        self.assertGreaterEqual(len(names), 9)
        for name in names:
            self.assertIn(f"`{name}`", spec, f"Java uses {name}, which is not in attribute-spec.md")

    def test_java_deny_reasons_match_spec(self):
        java = (ROOT / "instrumentation/java/src/main/java/io/github/photographed/authzradar/AuthzAttributes.java").read_text()
        spec = (ROOT / "shared" / "attribute-spec.md").read_text()
        for reason in re.findall(r'REASON_[A-Z_]+ = "([a-z_]+)"', java):
            self.assertIn(f"`{reason}`", spec, f"deny reason {reason} is not in attribute-spec.md")


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
                "owasp_api": r"API\d{1,2}", "oat": r"OAT-\d{3}", "ipa": r"\d+\.\d+", "attack": r"T\d{4}(\.\d{3})?"}
        for group in ("findings", "detections", "usage"):
            for key, entry in self.std[group].items():
                for field, pat in pats.items():
                    for v in entry.get(field, []):
                        self.assertRegex(v, f"^{pat}$", f"{group}.{key}.{field}={v}")

    def test_attack_techniques_are_known_and_named(self):
        techniques = self.std["attack_techniques"]
        self.assertEqual(self.std["attack_version"], "20.0")
        for group in ("findings", "detections"):
            for key, entry in self.std[group].items():
                self.assertIn("attack", entry, f"{group}.{key} has no ATT&CK mapping (use [] if none)")
                for t in entry["attack"]:
                    self.assertIn(t, techniques, f"{group}.{key}: {t} is not in attack_techniques")
        for t, meta in techniques.items():
            self.assertTrue(meta["name"] and meta["tactics"], t)
        used = {t for g in ("findings", "detections") for e in self.std[g].values() for t in e["attack"]}
        self.assertEqual(used, set(techniques), "attack_techniques should list exactly the techniques in use")

    def test_usage_mapping_ids_exist(self):
        self.assertLessEqual(set(self.std["usage"]), _defined("U", "usage.nrql.md"))

    def test_readme_lists_finding_cwes(self):
        readme = (ROOT / "README.md").read_text()
        for key, entry in self.std["findings"].items():
            for cwe in entry["cwe"]:
                self.assertIn(cwe, readme, f"README is missing {cwe} ({key})")


class VersioningTest(unittest.TestCase):
    def test_changelog_matches_plugin_version(self):
        import json
        version = json.loads((ROOT / ".claude-plugin" / "plugin.json").read_text())["version"]
        self.assertRegex(version, r"^\d+\.\d+\.\d+$")
        self.assertIn(f"## [{version}]", (ROOT / "CHANGELOG.md").read_text())

    def test_no_stray_doc_versions(self):
        for path in list((ROOT / "shared").glob("*.md")) + list((ROOT / "skills").rglob("*.md")):
            first = path.read_text().splitlines()[0]
            self.assertNotRegex(first, r"\(v\d", f"{path.name}: version belongs in plugin.json / CHANGELOG.md")

    def test_mcp_urls_are_literal(self):
        import json
        servers = json.loads((ROOT / ".mcp.json").read_text())["mcpServers"]
        for name, cfg in servers.items():
            self.assertTrue(cfg["url"].startswith("https://"), f"{name}: URL must not depend on unset env vars")


if __name__ == "__main__":
    unittest.main()
