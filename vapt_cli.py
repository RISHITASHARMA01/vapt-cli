#!/usr/bin/env python3
"""
VAPT Automation CLI
--------------------
Automates a basic Vulnerability Assessment & Penetration Testing workflow:
  1. Network scan of the target host with Nmap.
  2. Automated web vulnerability scan of the target URL with OWASP ZAP
     (baseline scan, run via Docker).
  3. Compiles both results into a single Markdown report, with ZAP
     findings mapped to OWASP Top 10 (2021) categories.

Only run this against systems you own or have explicit written
authorization to test.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# OWASP Top 10 (2021) keyword mapping
# ---------------------------------------------------------------------------
# Best-effort classifier: matches ZAP alert names/descriptions against
# keywords associated with each OWASP Top 10 category. Not authoritative --
# use as a starting point and verify manually.
OWASP_TOP_10_KEYWORDS = {
    "A01:2021 - Broken Access Control": [
        "access control", "path traversal", "directory browsing",
        "forced browsing", "cors", "cross-domain", ".git", ".env",
        "backup file", "source code disclosure",
    ],
    "A02:2021 - Cryptographic Failures": [
        "tls", "ssl", "certificate", "weak cipher", "cleartext",
        "insecure encryption", "hsts", "http (not https)",
        "sensitive data", "hash", "encryption",
    ],
    "A03:2021 - Injection": [
        "sql injection", "xss", "cross site scripting", "cross-site scripting",
        "command injection", "code injection", "ldap injection",
        "xpath injection", "template injection", "crlf injection",
    ],
    "A04:2021 - Insecure Design": [
        "insecure design", "business logic", "rate limit",
        "brute force", "anti-csrf tokens scanner",
    ],
    "A05:2021 - Security Misconfiguration": [
        "misconfiguration", "server leaks", "debug", "stack trace",
        "default credentials", "directory listing", "x-content-type-options",
        "x-frame-options", "content security policy", "csp",
        "server header", "banner", "verb tampering", "missing header",
        "cache", "cookie", "trace.axd", "wsdl",
    ],
    "A06:2021 - Vulnerable and Outdated Components": [
        "outdated", "known vulnerable", "vulnerable js library",
        "deprecated", "end of life", "unsupported version",
    ],
    "A07:2021 - Identification and Authentication Failures": [
        "authentication", "session", "credential", "password",
        "login", "csrf", "cross-site request forgery",
    ],
    "A08:2021 - Software and Data Integrity Failures": [
        "integrity", "deserialization", "subresource integrity",
        "sri", "unsigned",
    ],
    "A09:2021 - Security Logging and Monitoring Failures": [
        "logging", "monitoring",
    ],
    "A10:2021 - Server-Side Request Forgery": [
        "ssrf", "server side request forgery", "server-side request forgery",
    ],
}

UNCATEGORIZED = "Unmapped / Manual Review Needed"

RISK_ORDER = {"High": 0, "Medium": 1, "Low": 2, "Informational": 3}


def map_to_owasp(alert_name: str, description: str = "") -> str:
    haystack = f"{alert_name} {description}".lower()
    for category, keywords in OWASP_TOP_10_KEYWORDS.items():
        for kw in keywords:
            if kw in haystack:
                return category
    return UNCATEGORIZED


# ---------------------------------------------------------------------------
# Nmap
# ---------------------------------------------------------------------------
def run_nmap(host: str, output_dir: Path) -> dict:
    """Run an Nmap service/version scan against host, save raw + XML output."""
    if not shutil.which("nmap"):
        return {"error": "nmap not found on PATH. Install with: sudo apt install nmap"}

    xml_path = output_dir / "nmap_scan.xml"
    txt_path = output_dir / "nmap_scan.txt"

    cmd = ["nmap", "-sV", "-T4", "-oX", str(xml_path), "-oN", str(txt_path), host]
    print(f"[*] Running Nmap scan against {host} ...")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except subprocess.TimeoutExpired:
        return {"error": "nmap scan timed out after 600s"}

    if result.returncode != 0:
        return {"error": f"nmap exited with code {result.returncode}: {result.stderr.strip()}"}

    return {"txt_path": txt_path, "xml_path": xml_path, "raw_output": txt_path.read_text()}


# ---------------------------------------------------------------------------
# OWASP ZAP (baseline scan via Docker)
# ---------------------------------------------------------------------------
def run_zap_baseline(target_url: str, output_dir: Path) -> dict:
    """
    Run the ZAP baseline scan against target_url using the zaproxy/zap-stable
    Docker image, producing a JSON report (for parsing) and an HTML report
    (for human review).
    """
    if not shutil.which("docker"):
        return {"error": "docker not found on PATH. Install Docker or use a native ZAP install."}

    output_dir.mkdir(parents=True, exist_ok=True)
    json_report = "zap_report.json"
    html_report = "zap_report.html"

    cmd = [
        "docker", "run", "--rm",
        "--network", "host",  # so "localhost"/local IPs in target_url resolve to the host, not the ZAP container
        "-v", f"{output_dir.resolve()}:/zap/wrk/:rw",
        "--user", f"{os.getuid()}:{os.getgid()}",
        "zaproxy/zap-stable",
        "zap-baseline.py",
        "-t", target_url,
        "-J", json_report,
        "-r", html_report,
        "-I",  # don't fail the run on warnings/alerts found
    ]

    print(f"[*] Running OWASP ZAP baseline scan against {target_url} (this can take a few minutes) ...")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
    except subprocess.TimeoutExpired:
        return {"error": "ZAP baseline scan timed out after 1800s"}

    json_path = output_dir / json_report
    html_path = output_dir / html_report

    if not json_path.exists():
        return {
            "error": (
                "ZAP did not produce a JSON report. "
                f"stdout: {result.stdout[-1000:]} stderr: {result.stderr[-1000:]}"
            )
        }

    alerts = []
    try:
        data = json.loads(json_path.read_text())
        for site in data.get("site", []):
            for alert in site.get("alerts", []):
                alerts.append({
                    "name": alert.get("name", "Unknown"),
                    "risk": alert.get("riskdesc", "").split(" ")[0] or "Informational",
                    "description": alert.get("desc", ""),
                    "solution": alert.get("solution", ""),
                    "count": len(alert.get("instances", [])),
                })
    except json.JSONDecodeError as e:
        return {"error": f"Failed to parse ZAP JSON report: {e}"}

    return {"alerts": alerts, "html_path": html_path, "json_path": json_path}


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------
def build_report(target_url: str, host: str, nmap_result: dict, zap_result: dict, output_dir: Path) -> Path:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = []

    lines.append("# VAPT Report")
    lines.append("")
    lines.append(f"**Target URL:** {target_url}  ")
    lines.append(f"**Target Host:** {host}  ")
    lines.append(f"**Scan Date:** {ts}  ")
    lines.append("")
    lines.append(
        "> Generated automatically by `vapt_cli.py`. Findings are a starting "
        "point for manual verification, not a final security assessment."
    )
    lines.append("")

    # --- Nmap section ---
    lines.append("## 1. Network Scan (Nmap)")
    lines.append("")
    if "error" in nmap_result:
        lines.append(f"⚠️ Nmap scan failed: {nmap_result['error']}")
    else:
        lines.append("```")
        lines.append(nmap_result["raw_output"].strip())
        lines.append("```")
    lines.append("")

    # --- ZAP section ---
    lines.append("## 2. Web Vulnerability Scan (OWASP ZAP)")
    lines.append("")
    if "error" in zap_result:
        lines.append(f"⚠️ ZAP scan failed: {zap_result['error']}")
        lines.append("")
    else:
        alerts = zap_result["alerts"]
        if not alerts:
            lines.append("No alerts reported by ZAP baseline scan.")
        else:
            alerts_sorted = sorted(alerts, key=lambda a: RISK_ORDER.get(a["risk"], 4))
            lines.append(f"ZAP reported **{len(alerts)}** distinct alert type(s).")
            lines.append("")
            lines.append("| Risk | Alert | Instances | OWASP Top 10 Mapping |")
            lines.append("|------|-------|-----------|------------------------|")
            for a in alerts_sorted:
                category = map_to_owasp(a["name"], a["description"])
                lines.append(f"| {a['risk']} | {a['name']} | {a['count']} | {category} |")
            lines.append("")

            lines.append("### 2.1 Findings by OWASP Top 10 Category")
            lines.append("")
            by_category: dict[str, list] = {}
            for a in alerts_sorted:
                category = map_to_owasp(a["name"], a["description"])
                by_category.setdefault(category, []).append(a)

            for category, cat_alerts in by_category.items():
                lines.append(f"#### {category}")
                lines.append("")
                for a in cat_alerts:
                    lines.append(f"- **[{a['risk']}] {a['name']}** ({a['count']} instance(s))")
                    if a["description"]:
                        desc = a["description"].strip().replace("\n", " ")
                        lines.append(f"  - *Description:* {desc[:400]}{'...' if len(desc) > 400 else ''}")
                    if a["solution"]:
                        sol = a["solution"].strip().replace("\n", " ")
                        lines.append(f"  - *Recommendation:* {sol[:400]}{'...' if len(sol) > 400 else ''}")
                lines.append("")

        if zap_result.get("html_path"):
            lines.append(f"Full ZAP HTML report: `{zap_result['html_path'].name}`")
            lines.append("")

    # --- Recommendations ---
    lines.append("## 3. General Recommendations")
    lines.append("")
    lines.append("- Patch and update all identified outdated/vulnerable components.")
    lines.append("- Enforce HTTPS/TLS everywhere and set secure response headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options).")
    lines.append("- Apply input validation and parameterized queries to prevent injection.")
    lines.append("- Review access control logic for IDOR and privilege escalation issues (not detectable by automated scanners — verify manually).")
    lines.append("- Complement this automated scan with manual testing (e.g., Burp Suite) for business-logic flaws.")
    lines.append("")

    lines.append("## 4. Scope & Limitations")
    lines.append("")
    lines.append(
        "- OWASP Top 10 mapping is keyword-based and approximate; verify "
        "classifications manually before including in a formal report."
    )
    lines.append("- ZAP baseline scan is passive + light active only; it does not attempt exploitation.")
    lines.append("- This report does not include manual testing results unless added separately.")
    lines.append("")

    report_path = output_dir / "vapt_report.md"
    report_path.write_text("\n".join(lines))
    return report_path


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="VAPT Automation CLI: Nmap + OWASP ZAP scan compiled into an OWASP Top 10 mapped Markdown report."
    )
    parser.add_argument("--target", required=True, help="Target URL for the ZAP web scan, e.g. http://localhost:3000")
    parser.add_argument("--host", required=True, help="Target host/IP for the Nmap scan, e.g. localhost or 192.168.1.10")
    parser.add_argument("--output", default="./vapt_output", help="Output directory for scan results and report (default: ./vapt_output)")
    parser.add_argument("--skip-nmap", action="store_true", help="Skip the Nmap scan")
    parser.add_argument("--skip-zap", action="store_true", help="Skip the ZAP scan")
    args = parser.parse_args()

    parsed = urlparse(args.target)
    if parsed.scheme not in ("http", "https"):
        print("Error: --target must be a full URL, e.g. http://localhost:3000", file=sys.stderr)
        sys.exit(1)

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 60)
    print(" VAPT Automation CLI")
    print(" Only run against systems you own or are authorized to test.")
    print("=" * 60)

    nmap_result = {"error": "skipped (--skip-nmap)"} if args.skip_nmap else run_nmap(args.host, output_dir)
    zap_result = {"error": "skipped (--skip-zap)"} if args.skip_zap else run_zap_baseline(args.target, output_dir)

    report_path = build_report(args.target, args.host, nmap_result, zap_result, output_dir)

    print()
    print(f"[+] Report written to: {report_path}")
    if zap_result.get("html_path") and Path(zap_result["html_path"]).exists():
        print(f"[+] Full ZAP HTML report: {zap_result['html_path']}")


if __name__ == "__main__":
    main()
