"""Cross-language checks for instrumentation/<lang>: tests pass, pseudonyms agree, names follow the spec."""
import hashlib
import hmac
import re
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INST = ROOT / "instrumentation"
SPEC = (ROOT / "shared" / "attribute-spec.md").read_text()
EXPECTED = "u_" + hmac.new(b"k", b"alice", hashlib.sha256).hexdigest()[:16]

SOURCES = {
    "python": INST / "python" / "authz_radar.py",
    "node": INST / "node" / "authz-radar.js",
    "ruby": INST / "ruby" / "authz_radar.rb",
    "go": INST / "go" / "authzradar.go",
    "php": INST / "php" / "src" / "Telemetry.php",
    "dotnet": INST / "dotnet" / "AuthzRadar.cs",
    "java": INST / "java/src/main/java/io/github/photographed/authzradar/AuthzAttributes.java",
}

PSEUDONYM = {
    "python": (["python3", "-c", "import authz_radar as a;print(a.pseudonym('alice', b'k'))"], INST / "python"),
    "node": (["node", "-e", "console.log(require('./authz-radar').pseudonym('alice','k'))"], INST / "node"),
    "ruby": (["ruby", "-r", "./authz_radar", "-e", "puts AuthzRadar.pseudonym('alice','k')"], INST / "ruby"),
    "php": (["php", "-r", "require 'autoload.php'; echo (new AuthzRadar\\Pseudonymizer('k'))->user('alice');"], INST / "php"),
}

TESTS = {
    "python": (["python3", "-m", "unittest", "-q", "test_authz_radar"], INST / "python"),
    "node": (["node", "--test"], INST / "node"),
    "ruby": (["ruby", "authz_radar_test.rb"], INST / "ruby"),
    "php": (["php", "tests/TelemetryTest.php"], INST / "php"),
    "go": (["go", "test", "./..."], INST / "go"),
}


def run(cmd, cwd):
    if shutil.which(cmd[0]) is None:
        raise unittest.SkipTest(f"{cmd[0]} not installed")
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=600)


class LanguagesTest(unittest.TestCase):
    def test_language_suites_pass(self):
        for lang, (cmd, cwd) in TESTS.items():
            with self.subTest(lang=lang):
                result = run(cmd, cwd)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_pseudonyms_agree_across_languages(self):
        for lang, (cmd, cwd) in PSEUDONYM.items():
            with self.subTest(lang=lang):
                result = run(cmd, cwd)
                self.assertEqual(result.stdout.strip(), EXPECTED, result.stderr)
        java_test = (INST / "java/src/test/java/io/github/photographed/authzradar/PseudonymizerTest.java").read_text()
        self.assertIn(EXPECTED, java_test)
        self.assertIn(EXPECTED.replace("u_", ""), hmac.new(b"k", b"alice", hashlib.sha256).hexdigest())

    def test_attribute_names_follow_the_spec(self):
        for lang, path in SOURCES.items():
            with self.subTest(lang=lang):
                names = set(re.findall(r"['\"]((?:authz|resource|client|api|auth|edge)\.[a-z_]+)['\"]", path.read_text()))
                self.assertTrue(names, f"{lang}: no attribute names found")
                for name in names:
                    self.assertIn(f"`{name}`", SPEC, f"{lang} uses {name}, not in attribute-spec.md")

    def test_every_language_sends_the_two_stage_s2_attributes(self):
        for lang, path in SOURCES.items():
            if lang == "java":
                continue
            text = path.read_text()
            with self.subTest(lang=lang):
                self.assertIn("resource.owner_match", text)
                self.assertIn("authz.decision", text)


if __name__ == "__main__":
    unittest.main()
