"""Offline fixtures; no targets are scanned."""
import json
from pathlib import Path
import tempfile
import unittest

from assessment import parse_nessus, parse_zap, parse_nmap, parse_cvss, risk_from_cvss, report, parse_evidence

ROOT = Path(__file__).resolve().parents[1]

class AssessmentTests(unittest.TestCase):
    def test_cvss_boundaries(self):
        self.assertEqual([risk_from_cvss(parse_cvss(x)) for x in (0, 3.9, 4, 6.9, 7, 8.9, 9, 10)],
                         ["Informational", "Low", "Medium", "Medium", "High", "High", "Critical", "Critical"])
        self.assertIsNone(parse_cvss("not available"))
        self.assertIsNone(parse_cvss(12))
        self.assertIsNone(parse_cvss("NaN"))

    def test_nessus(self):
        findings = parse_nessus(ROOT / "examples" / "synthetic_lab.nessus")
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0]["severity"], "Critical")
        self.assertEqual(findings[0]["cvss"], 9.8)
        self.assertEqual(findings[1]["severity"], "Low")
        self.assertIsNone(findings[1]["cvss"])

    def test_zap_and_nmap(self):
        self.assertEqual(parse_zap(ROOT / "examples" / "synthetic_zap.json")[0]["severity"], "Medium")
        f = parse_nmap(ROOT / "examples" / "synthetic_nmap.xml")
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["severity"], "Informational")

    def test_reject_doctype(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.nessus"
            path.write_text("<!DOCTYPE a [<!ENTITY x 'bad'>]><NessusClientData_v2/>")
            with self.assertRaises(ValueError):
                parse_nessus(path)

    def test_consolidation(self):
        nessus = ROOT / "examples" / "synthetic_lab.nessus"
        nmap = ROOT / "examples" / "synthetic_nmap.xml"
        findings = parse_nessus(nessus) + parse_nmap(nmap)
        evidence = parse_evidence(ROOT / "examples" / "lab_evidence.json")
        result = report(findings, [("Nessus", nessus), ("Nmap", nmap)], evidence)
        self.assertIn("SHA-256", result)
        self.assertIn("Authorized lab evidence", result)
        self.assertIn("Critical", result)
        self.assertIn("Remediation and verification", result)
        self.assertIn("synthetic fixture", result)

if __name__ == "__main__":
    unittest.main()
