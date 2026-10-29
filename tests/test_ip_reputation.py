"""ip_reputation.py: local, opt-in IP reputation enrichment (never sends to New Relic)."""
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
ROOT = REPO / "plugin"
sys.path.insert(0, str(ROOT / "scripts"))
import ip_reputation as ipr  # noqa: E402


class ExtractTest(unittest.TestCase):
    def test_extracts_ipv4_from_log_like_text(self):
        text = 'GET /?search=x 203.0.113.4 - - "UA" 198.51.100.9 and 203.0.113.4 again'
        self.assertEqual(ipr.extract_ips(text), ["203.0.113.4", "198.51.100.9"])  # deduped, order kept

    def test_extracts_ipv6_and_ignores_junk(self):
        ips = ipr.extract_ips("client 2001:db8::1 ver 1.2.3.4 notanip 999.999.999.999")
        self.assertIn("2001:db8::1", ips)
        self.assertIn("1.2.3.4", ips)
        self.assertNotIn("999.999.999.999", ips)

    def test_public_vs_private(self):
        self.assertTrue(ipr.is_public("8.8.8.8"))
        self.assertFalse(ipr.is_public("10.0.0.1"))
        self.assertFalse(ipr.is_public("127.0.0.1"))
        self.assertFalse(ipr.is_public("203.0.113.4"))   # TEST-NET-3 doc range is reserved


class FakeHTTP:
    def __init__(self, by_ip):
        self.by_ip, self.calls = by_ip, []

    def __call__(self, url, headers):
        self.calls.append((url, headers))
        import urllib.parse as up
        ip = up.parse_qs(up.urlparse(url).query)["ipAddress"][0]
        return {"data": self.by_ip.get(ip, {"abuseConfidenceScore": 0, "totalReports": 0})}


class ClientTest(unittest.TestCase):
    def test_check_maps_fields_and_sends_key_header(self):
        http = FakeHTTP({"1.2.3.4": {"abuseConfidenceScore": 87, "totalReports": 42,
                                         "lastReportedAt": "2026-10-01T00:00:00+00:00", "countryCode": "XX", "isp": "Evil"}})
        c = ipr.AbuseIPDBClient("secret", http=http)
        r = c.check("1.2.3.4")
        self.assertEqual(r["score"], 87)
        self.assertEqual(r["reports"], 42)
        self.assertEqual(http.calls[0][1]["Key"], "secret")   # api key in header, not URL
        self.assertNotIn("secret", http.calls[0][0])

    def test_lookup_skips_private_without_calling(self):
        http = FakeHTTP({})
        rows = ipr.lookup(["10.0.0.1", "1.2.3.4"], ipr.AbuseIPDBClient("k", http=http))
        self.assertEqual(http.calls and len(http.calls), 1)   # only the public one was queried
        priv = next(r for r in rows if r["ip"] == "10.0.0.1")
        self.assertIn("private", priv["note"])

    def test_lookup_keeps_going_on_error(self):
        def boom(url, headers):
            raise RuntimeError("network down")
        rows = ipr.lookup(["1.2.3.4"], ipr.AbuseIPDBClient("k", http=boom))
        self.assertIsNone(rows[0]["score"])
        self.assertIn("RuntimeError", rows[0]["note"])

    def test_markdown_flags_high_scores(self):
        md = ipr.to_markdown([{"ip": "203.0.113.4", "score": 90, "reports": 5},
                              {"ip": "198.51.100.9", "score": 1, "reports": 0}], min_score=25)
        self.assertIn("⚠️", md)
        self.assertIn("1 of 2", md)


if __name__ == "__main__":
    unittest.main()
