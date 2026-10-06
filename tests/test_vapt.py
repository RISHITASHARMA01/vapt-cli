"""Unit tests for vapt_cli helpers. Run from the project folder with:
    python3 -m unittest discover -s tests -v
(standard library only; pytest also works if you have it installed)
"""
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import vapt_cli as v  # noqa: E402


class TestOwaspMapping(unittest.TestCase):
    def test_cwe_is_used_first(self):
        # name says nothing useful, but CWE-79 is XSS -> Injection
        self.assertTrue(v.map_to_owasp("Some alert", "79").startswith("A03"))

    def test_csrf_maps_to_a01(self):
        self.assertTrue(v.map_to_owasp("Absence of Anti-CSRF Tokens", "352").startswith("A01"))

    def test_keyword_fallback_on_name(self):
        self.assertTrue(v.map_to_owasp("Content Security Policy (CSP) Header Not Set", "693").startswith("A05"))

    def test_real_juice_shop_alerts(self):
        self.assertTrue(v.map_to_owasp("Cross-Domain Misconfiguration", "264").startswith("A05"))
        self.assertTrue(v.map_to_owasp("Deprecated Feature Policy Header Set", "16").startswith("A05"))
        self.assertTrue(v.map_to_owasp("Storable and Cacheable Content", "524").startswith("A05"))

    def test_unknown_alert_is_unmapped(self):
        self.assertEqual(v.map_to_owasp("Modern Web Application", "-1"), v.UNCATEGORIZED)

    def test_empty_inputs_do_not_crash(self):
        self.assertEqual(v.map_to_owasp("", ""), v.UNCATEGORIZED)


class TestValidation(unittest.TestCase):
    def test_valid_hosts(self):
        for h in ("localhost", "192.168.1.10", "example.com", "my-host.local", "::1"):
            self.assertTrue(v.valid_host(h), h)

    def test_invalid_hosts(self):
        for h in ("", "-iL", "--script=evil", "a b", "host;ls", "bad_host!", "$(id)"):
            self.assertFalse(v.valid_host(h), h)

    def test_valid_ports(self):
        for p in ("80", "22,80,443", "1-1024", "1-100,443"):
            self.assertTrue(v.valid_ports(p), p)

    def test_invalid_ports(self):
        for p in ("", "80; ls", "abc", "1--5", "-p", "80,"):
            self.assertFalse(v.valid_ports(p), p)

    def test_md_escape(self):
        self.assertEqual(v.md_escape("a|b"), "a\\|b")


class TestCleanText(unittest.TestCase):
    def test_strips_html_and_unescapes(self):
        self.assertEqual(v.clean_text("<p>Hello &amp; <b>world</b></p>"), "Hello & world")

    def test_collapses_whitespace(self):
        self.assertEqual(v.clean_text("a\n\n   b"), "a b")

    def test_none_safe(self):
        self.assertEqual(v.clean_text(None), "")


NMAP_XML = """<?xml version="1.0"?>
<nmaprun><host><ports>
  <port protocol="tcp" portid="3002"><state state="open"/>
    <service name="http" product="Node.js Express" version="4"/></port>
  <port protocol="tcp" portid="22"><state state="closed"/>
    <service name="ssh"/></port>
</ports></host></nmaprun>
"""


class TestNmapParsing(unittest.TestCase):
    def test_only_open_ports_are_returned(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "scan.xml"
            p.write_text(NMAP_XML)
            ports = v.parse_nmap_xml(p)
        self.assertEqual(len(ports), 1)
        self.assertEqual(ports[0]["port"], "3002")
        self.assertEqual(ports[0]["service"], "http")
        self.assertEqual(ports[0]["version"], "Node.js Express 4")

    def test_bad_xml_returns_empty_list(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "bad.xml"
            p.write_text("not xml")
            self.assertEqual(v.parse_nmap_xml(p), [])

    def test_missing_file_returns_empty_list(self):
        self.assertEqual(v.parse_nmap_xml(Path("/nonexistent/file.xml")), [])


def _fake_alert(**kw):
    base = {"name": "Cross Site Scripting | test", "risk": "High", "description": "desc",
            "solution": "fix it", "cwe": "79", "count": 2, "uris": ["http://x/a"]}
    base.update(kw)
    return base


class TestReport(unittest.TestCase):
    def _build(self, nmap, zap):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            path = v.build_report("http://localhost:3002", "localhost", nmap, zap, d)
            return path.read_text(encoding="utf-8")

    def test_full_report_contains_expected_sections(self):
        nmap = {"raw_output": "PORT STATE", "open_ports": [
            {"port": "3002", "proto": "tcp", "service": "http", "version": "Node"}]}
        zap = {"alerts": [_fake_alert()], "html_path": Path("zap_report.html"), "mode": "baseline"}
        text = self._build(nmap, zap)
        self.assertIn("## Summary", text)
        self.assertIn("| 3002 | tcp | http | Node |", text)
        self.assertIn("A03:2021 - Injection", text)
        self.assertIn("`http://x/a`", text)
        self.assertIn("Cross Site Scripting \\| test", text)   # pipe escaped in table
        self.assertIn("Baseline (passive)", text)

    def test_skipped_stages_are_not_reported_as_failures(self):
        text = self._build({"skipped": True}, {"skipped": True})
        self.assertIn("Skipped by user", text)
        self.assertNotIn("failed", text)

    def test_errors_are_reported(self):
        text = self._build({"error": "nmap missing"}, {"error": "docker missing"})
        self.assertIn("Nmap scan failed: nmap missing", text)
        self.assertIn("ZAP scan failed: docker missing", text)

    def test_full_scan_mode_is_labelled(self):
        zap = {"alerts": [_fake_alert()], "mode": "full"}
        text = self._build({"skipped": True}, zap)
        self.assertIn("Full (active scan)", text)
        self.assertIn("active scanner", text)


class TestRunStreaming(unittest.TestCase):
    def test_collects_output_and_exit_code(self):
        rc, tail, timed_out = v.run_streaming(["bash", "-c", "echo one; echo two"], 10)
        self.assertEqual(rc, 0)
        self.assertFalse(timed_out)
        self.assertIn("two", tail)

    def test_hung_process_is_killed_on_timeout(self):
        start = time.time()
        rc, tail, timed_out = v.run_streaming(["bash", "-c", "echo start; sleep 30"], 2)
        self.assertTrue(timed_out)
        self.assertLess(time.time() - start, 10)


if __name__ == "__main__":
    unittest.main()
