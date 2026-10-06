#!/usr/bin/env python3
"""
VAPT Automation CLI
--------------------
Automates a basic Vulnerability Assessment & Penetration Testing workflow:
  1. Network scan of the target host with Nmap.
  2. Automated web vulnerability scan of the target URL with OWASP ZAP
     (baseline scan by default, optional full active scan), run via Docker.
  3. Compiles both results into a single Markdown report, with ZAP
     findings mapped to OWASP Top 10 (2021) categories.

Only run this against systems you own or have explicit written
authorization to test.
"""

import argparse
import html
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# OWASP Top 10 (2021) mapping
# ---------------------------------------------------------------------------
# 1) CWE-based lookup (preferred: ZAP reports a CWE id per alert).
#    Best-effort table of common CWEs -- verify against owasp.org before
#    quoting it in a formal report.
CWE_TO_OWASP = {
    # A01 Broken Access Control
    "22": "A01:2021 - Broken Access Control",
    "200": "A01:2021 - Broken Access Control",
    "284": "A01:2021 - Broken Access Control",
    "352": "A01:2021 - Broken Access Control",      # CSRF
    "548": "A01:2021 - Broken Access Control",
    "639": "A01:2021 - Broken Access Control",
    # A02 Cryptographic Failures
    "311": "A02:2021 - Cryptographic Failures",
    "319": "A02:2021 - Cryptographic Failures",
    "326": "A02:2021 - Cryptographic Failures",
    "327": "A02:2021 - Cryptographic Failures",
    # A03 Injection
    "78": "A03:2021 - Injection",
    "79": "A03:2021 - Injection",                    # XSS
    "89": "A03:2021 - Injection",                    # SQL injection
    "94": "A03:2021 - Injection",
    # A04 Insecure Design
    "1021": "A04:2021 - Insecure Design",           # clickjacking / framing
    # A05 Security Misconfiguration
    "16": "A05:2021 - Security Misconfiguration",
    "614": "A05:2021 - Security Misconfiguration",  # cookie without Secure
    "942": "A05:2021 - Security Misconfiguration",  # permissive CORS
    "1004": "A05:2021 - Security Misconfiguration", # cookie without HttpOnly
    # A06 Vulnerable and Outdated Components
    "937": "A06:2021 - Vulnerable and Outdated Components",
    "1035": "A06:2021 - Vulnerable and Outdated Components",
    "1104": "A06:2021 - Vulnerable and Outdated Components",
    # A07 Identification and Authentication Failures
    "287": "A07:2021 - Identification and Authentication Failures",
    "384": "A07:2021 - Identification and Authentication Failures",
    # A08 Software and Data Integrity Failures
    "502": "A08:2021 - Software and Data Integrity Failures",
    "829": "A08:2021 - Software and Data Integrity Failures",  # missing SRI
    # A10 SSRF
    "918": "A10:2021 - Server-Side Request Forgery",
}

# 2) Keyword fallback, matched against the alert NAME only (descriptions
#    mention too many unrelated words and caused wrong matches).
OWASP_TOP_10_KEYWORDS = {
    "A01:2021 - Broken Access Control": [
        "access control", "path traversal", "directory browsing",
        "forced browsing", "csrf", "cross-site request forgery",
        ".git", ".env", "backup file", "source code disclosure",
    ],
    "A02:2021 - Cryptographic Failures": [
        "tls", "ssl", "certificate", "weak cipher", "cleartext",
        "hsts", "strict-transport-security", "http only site",
    ],
    "A03:2021 - Injection": [
        "sql injection", "xss", "cross site scripting", "cross-site scripting",
        "command injection", "code injection", "ldap injection",
        "xpath injection", "template injection", "crlf injection",
    ],
    "A04:2021 - Insecure Design": [
        "insecure design", "business logic", "rate limit", "anti-clickjacking",
    ],
    "A05:2021 - Security Misconfiguration": [
        "misconfiguration", "server leaks", "debug", "stack trace",
        "default credentials", "directory listing", "x-content-type-options",
        "x-frame-options", "content security policy", "csp",
        "server header", "banner", "missing header", "cache-control",
        "cookie", "cross-domain", "cors", "timestamp disclosure",
        "information disclosure", "application error", "cacheable", "cross-origin",
        "feature policy", "permissions policy",
    ],
    "A06:2021 - Vulnerable and Outdated Components": [
        "outdated", "known vulnerable", "vulnerable js library",
        "deprecated", "end of life", "unsupported version",
    ],
    "A07:2021 - Identification and Authentication Failures": [
        "authentication", "session", "credential", "password", "login",
    ],
    "A08:2021 - Software and Data Integrity Failures": [
        "deserialization", "subresource integrity", "unsigned",
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


def map_to_owasp(alert_name: str, cwe_id: str = "") -> str:
    """Map a ZAP alert to an OWASP Top 10 (2021) category. CWE first, then name keywords."""
    cwe = str(cwe_id).strip()
    if cwe in CWE_TO_OWASP:
        return CWE_TO_OWASP[cwe]
    name = (alert_name or "").lower()
    for category, keywords in OWASP_TOP_10_KEYWORDS.items():
        for kw in keywords:
            if kw in name:
                return category
    return UNCATEGORIZED


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def clean_text(text: str) -> str:
    """ZAP descriptions contain HTML (<p> tags etc). Strip tags and tidy whitespace."""
    text = re.sub(r"<[^>]+>", " ", text or "")
    text = html.unescape(text)
    return re.sub(r"\s+", " ", text).strip()


def valid_host(host: str) -> bool:
    """Accept an IP address or a plain hostname. Reject anything that could be read as an Nmap option."""
    if not host or host.startswith("-"):
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(re.fullmatch(r"[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", host))


def valid_ports(ports: str) -> bool:
    """Nmap port spec: digits, commas and dashes only, e.g. 22,80,443 or 1-1024."""
    return bool(re.fullmatch(r"[0-9]+([,-][0-9]+)*", ports or ""))


def md_escape(text: str) -> str:
    """Keep table cells from breaking on pipe characters."""
    return (text or "").replace("|", "\\|")


def confirm_authorization(host: str, assume_yes: bool) -> bool:
    """Require an explicit confirmation before any scan is launched."""
    if assume_yes:
        print("[!] --yes supplied: authorization assumed by the operator.")
        return True
    print()
    print("[!] AUTHORIZATION CHECK")
    print("    Scanning systems without written permission is illegal in most jurisdictions.")
    try:
        answer = input(f"    Type the target host ({host}) to confirm you are authorized to test it: ").strip()
    except EOFError:
        return False
    return answer == host


# ---------------------------------------------------------------------------
# Nmap
# ---------------------------------------------------------------------------
def parse_nmap_xml(xml_path: Path) -> list:
    """Return a list of open ports from Nmap's XML output."""
    ports = []
    try:
        root = ET.parse(xml_path).getroot()
    except (ET.ParseError, OSError):
        return ports
    for port in root.findall("host/ports/port"):
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue
        svc = port.find("service")
        ports.append({
            "port": port.get("portid", "?"),
            "proto": port.get("protocol", "?"),
            "service": svc.get("name", "") if svc is not None else "",
            "version": " ".join(
                p for p in (
                    svc.get("product", "") if svc is not None else "",
                    svc.get("version", "") if svc is not None else "",
                ) if p
            ),
        })
    return ports


def run_nmap(host: str, output_dir: Path, ports: str = "") -> dict:
    """Run an Nmap service/version scan against host, save raw + XML output."""
    if not shutil.which("nmap"):
        return {"error": "nmap not found on PATH. Install with: sudo apt install nmap"}

    xml_path = output_dir / "nmap_scan.xml"
    txt_path = output_dir / "nmap_scan.txt"
    # Remove stale output so an old scan can never be mistaken for this one
    xml_path.unlink(missing_ok=True)
    txt_path.unlink(missing_ok=True)

    cmd = ["nmap", "-sV", "-T4", "-oX", str(xml_path), "-oN", str(txt_path)]
    if ports:
        cmd += ["-p", ports]
    cmd.append(host)

    print(f"[*] Running Nmap scan against {host} ...")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except subprocess.TimeoutExpired:
        return {"error": "nmap scan timed out after 600s"}

    if result.returncode != 0:
        return {"error": f"nmap exited with code {result.returncode}: {result.stderr.strip()}"}
    if not txt_path.exists():
        return {"error": "nmap finished but produced no output file"}

    return {
        "txt_path": txt_path,
        "xml_path": xml_path,
        "raw_output": txt_path.read_text(),
        "open_ports": parse_nmap_xml(xml_path),
    }


# ---------------------------------------------------------------------------
# OWASP ZAP (via Docker)
# ---------------------------------------------------------------------------
def zap_network_args(target_url: str):
    """
    On Linux, --network host lets the container reach localhost services.
    On Docker Desktop (Windows/Mac) host networking does not reach the machine,
    so rewrite localhost/127.0.0.1 to host.docker.internal instead.
    """
    if sys.platform.startswith("linux"):
        return target_url, ["--network", "host"]
    parsed = urlparse(target_url)
    if parsed.hostname in ("localhost", "127.0.0.1"):
        netloc = "host.docker.internal" + (f":{parsed.port}" if parsed.port else "")
        return parsed._replace(netloc=netloc).geturl(), []
    return target_url, []


def run_streaming(cmd, timeout, container_name=None, prefix="    [zap] "):
    """
    Run cmd and echo its output live. Kill it (and its Docker container) after
    `timeout` seconds. Returns (returncode, last_30_lines, timed_out).
    """
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    state = {"timed_out": False}

    def _kill():
        state["timed_out"] = True
        if container_name:
            subprocess.run(["docker", "kill", container_name], capture_output=True)
        proc.kill()

    timer = threading.Timer(timeout, _kill)
    timer.start()
    tail = []
    try:
        for line in proc.stdout:
            line = line.rstrip()
            print(prefix + line)
            tail.append(line)
            del tail[:-30]
        proc.wait()
    except KeyboardInterrupt:
        if container_name:
            subprocess.run(["docker", "kill", container_name], capture_output=True)
        proc.kill()
        raise
    finally:
        timer.cancel()
    return proc.returncode, "\n".join(tail), state["timed_out"]


def run_zap(target_url: str, output_dir: Path, full_scan: bool = False, ajax: bool = False,
            spider_minutes: int = 2, max_minutes: int = 10) -> dict:
    """
    Run a ZAP scan against target_url using the zaproxy/zap-stable Docker image.
      - baseline (default): spider + passive rules only, no attack payloads.
      - full (--full-scan): adds the ACTIVE scanner (sends attack payloads).
    Produces a JSON report (for parsing) and an HTML report (for humans).
    """
    if not shutil.which("docker"):
        return {"error": "docker not found on PATH. Install Docker or use a native ZAP install."}

    output_dir.mkdir(parents=True, exist_ok=True)
    json_report = "zap_report.json"
    html_report = "zap_report.html"
    json_path = output_dir / json_report
    html_path = output_dir / html_report

    # Delete old reports first so a failed scan can never reuse stale results
    json_path.unlink(missing_ok=True)
    html_path.unlink(missing_ok=True)

    docker_target, net_args = zap_network_args(target_url)
    container_name = f"vapt-zap-{int(time.time())}"
    script = "zap-full-scan.py" if full_scan else "zap-baseline.py"
    timeout = 3600 if full_scan else 1800

    # ZAP runs as a non-root user inside the container, so the mounted folder must be writable
    try:
        os.chmod(output_dir, 0o777)
    except OSError:
        pass

    cmd = ["docker", "run", "--rm", "-t", "--name", container_name] + net_args + [
        "-v", f"{output_dir.resolve()}:/zap/wrk/:rw",
        "zaproxy/zap-stable",
        script,
        "-t", docker_target,
        "-J", json_report,
        "-r", html_report,
        "-I",  # don't fail the run just because alerts were found
        "-m", str(spider_minutes),   # max minutes for the spider
        "-T", str(max_minutes),      # max minutes for the whole scan
    ]
    if ajax:
        cmd.append("-j")  # AJAX spider: better coverage of JavaScript SPAs

    mode = "FULL (active)" if full_scan else "baseline (passive)"
    print(f"[*] Running OWASP ZAP {mode} scan against {docker_target} (this can take a few minutes) ...")
    returncode, tail, timed_out = run_streaming(cmd, timeout, container_name)
    if timed_out:
        return {"error": f"ZAP scan timed out after {timeout}s and was stopped"}

    if not json_path.exists():
        return {
            "error": (
                f"ZAP did not produce a JSON report (exit code {returncode}). "
                f"Last output: {tail[-1000:]}"
            )
        }

    alerts = []
    try:
        data = json.loads(json_path.read_text())
        for site in data.get("site", []):
            for alert in site.get("alerts", []):
                instances = alert.get("instances", [])
                uris = []
                for inst in instances:
                    uri = inst.get("uri", "")
                    if uri and uri not in uris:
                        uris.append(uri)
                alerts.append({
                    "name": alert.get("name", "Unknown"),
                    "risk": alert.get("riskdesc", "").split(" ")[0] or "Informational",
                    "description": clean_text(alert.get("desc", "")),
                    "solution": clean_text(alert.get("solution", "")),
                    "cwe": str(alert.get("cweid", "")).strip(),
                    "count": len(instances),
                    "uris": uris[:5],
                })
    except json.JSONDecodeError as e:
        return {"error": f"Failed to parse ZAP JSON report: {e}"}

    return {
        "alerts": alerts,
        "html_path": html_path,
        "json_path": json_path,
        "mode": "full" if full_scan else "baseline",
    }


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------
def _short(text: str, limit: int = 400) -> str:
    return text if len(text) <= limit else text[:limit].rstrip() + "..."


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

    # --- Summary ---
    if "alerts" in zap_result and zap_result["alerts"]:
        counts = {}
        for a in zap_result["alerts"]:
            counts[a["risk"]] = counts.get(a["risk"], 0) + 1
        lines.append("## Summary")
        lines.append("")
        lines.append("| Risk | Distinct alert types |")
        lines.append("|------|----------------------|")
        for risk in sorted(counts, key=lambda r: RISK_ORDER.get(r, 4)):
            lines.append(f"| {risk} | {counts[risk]} |")
        lines.append("")

    # --- Nmap section ---
    lines.append("## 1. Network Scan (Nmap)")
    lines.append("")
    if nmap_result.get("skipped"):
        lines.append("Skipped by user (`--skip-nmap`).")
    elif "error" in nmap_result:
        lines.append(f"⚠️ Nmap scan failed: {nmap_result['error']}")
    else:
        open_ports = nmap_result.get("open_ports", [])
        if open_ports:
            lines.append("| Port | Protocol | Service | Version |")
            lines.append("|------|----------|---------|---------|")
            for p in open_ports:
                lines.append(
                    f"| {p['port']} | {p['proto']} | {md_escape(p['service'])} | {md_escape(p['version'])} |"
                )
            lines.append("")
        else:
            lines.append("No open ports found in the scanned range.")
            lines.append("")
        lines.append("<details><summary>Raw Nmap output</summary>")
        lines.append("")
        lines.append("~~~")
        lines.append(nmap_result["raw_output"].strip())
        lines.append("~~~")
        lines.append("")
        lines.append("</details>")
    lines.append("")

    # --- ZAP section ---
    lines.append("## 2. Web Vulnerability Scan (OWASP ZAP)")
    lines.append("")
    if zap_result.get("skipped"):
        lines.append("Skipped by user (`--skip-zap`).")
        lines.append("")
    elif "error" in zap_result:
        lines.append(f"⚠️ ZAP scan failed: {zap_result['error']}")
        lines.append("")
    else:
        alerts = zap_result["alerts"]
        mode = zap_result.get("mode", "baseline")
        lines.append(f"**Scan mode:** {'Full (active scan)' if mode == 'full' else 'Baseline (passive)'}")
        lines.append("")
        if not alerts:
            lines.append("No alerts reported by ZAP.")
            lines.append("")
        else:
            alerts_sorted = sorted(alerts, key=lambda a: RISK_ORDER.get(a["risk"], 4))
            lines.append(f"ZAP reported **{len(alerts)}** distinct alert type(s).")
            lines.append("")
            lines.append("| Risk | Alert | CWE | Instances | OWASP Top 10 Mapping |")
            lines.append("|------|-------|-----|-----------|----------------------|")
            for a in alerts_sorted:
                category = map_to_owasp(a["name"], a["cwe"])
                lines.append(
                    f"| {a['risk']} | {md_escape(a['name'])} | {a['cwe'] or '-'} | {a['count']} | {category} |"
                )
            lines.append("")

            lines.append("### 2.1 Findings by OWASP Top 10 Category")
            lines.append("")
            by_category = {}
            for a in alerts_sorted:
                by_category.setdefault(map_to_owasp(a["name"], a["cwe"]), []).append(a)

            for category, cat_alerts in by_category.items():
                lines.append(f"#### {category}")
                lines.append("")
                for a in cat_alerts:
                    cwe_txt = f", CWE-{a['cwe']}" if a["cwe"] not in ("", "-1", "0") else ""
                    lines.append(f"- **[{a['risk']}] {a['name']}** ({a['count']} instance(s){cwe_txt})")
                    if a["description"]:
                        lines.append(f"  - *Description:* {_short(a['description'])}")
                    if a["solution"]:
                        lines.append(f"  - *Recommendation:* {_short(a['solution'])}")
                    if a["uris"]:
                        lines.append("  - *Affected URLs (sample):*")
                        for u in a["uris"]:
                            lines.append(f"    - `{u}`")
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

    # --- Limitations ---
    lines.append("## 4. Scope & Limitations")
    lines.append("")
    lines.append(
        "- OWASP Top 10 mapping uses the alert's CWE id first and alert-name keywords as a "
        "fallback; it is approximate. Verify classifications manually before including in a formal report."
    )
    if "alerts" in zap_result and zap_result.get("mode") == "full":
        lines.append("- ZAP ran in full mode, which includes the active scanner (attack payloads were sent).")
    else:
        lines.append(
            "- ZAP baseline mode is spider + passive rules only. It sends no attack payloads, so it "
            "cannot confirm injection flaws such as SQLi or XSS. Use `--full-scan` on authorized targets for that."
        )
    lines.append("- Only open ports in the scanned range are listed; unauthenticated areas only.")
    lines.append("- This report does not include manual testing results unless added separately.")
    lines.append("")

    report_path = output_dir / "vapt_report.md"
    report_path.write_text("\n".join(lines), encoding="utf-8")
    return report_path


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="VAPT Automation CLI: Nmap + OWASP ZAP scan compiled into an OWASP Top 10 mapped Markdown report."
    )
    parser.add_argument("--target", required=True, help="Target URL for the ZAP web scan, e.g. http://localhost:3000")
    parser.add_argument("--host", help="Target host/IP for Nmap (default: taken from --target)")
    parser.add_argument("--output", default="./vapt_output", help="Output directory (default: ./vapt_output)")
    parser.add_argument("--skip-nmap", action="store_true", help="Skip the Nmap scan")
    parser.add_argument("--skip-zap", action="store_true", help="Skip the ZAP scan")
    parser.add_argument("--nmap-ports", default="", help="Nmap port spec, e.g. 22,80,443 or 1-1024 (default: Nmap top 1000)")
    parser.add_argument("--full-scan", action="store_true", help="Run the ZAP FULL scan (active attacks). Authorized targets only.")
    parser.add_argument("--ajax", action="store_true", help="Use ZAP's AJAX spider (better for JavaScript apps like Juice Shop)")
    parser.add_argument("--spider-minutes", type=int, default=2, help="Max minutes for the ZAP spider (default: 2)")
    parser.add_argument("--max-minutes", type=int, default=10, help="Max minutes for the whole ZAP scan (default: 10)")
    parser.add_argument("--yes", action="store_true", help="Skip the interactive authorization prompt (you accept responsibility)")
    args = parser.parse_args()

    parsed = urlparse(args.target)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        print("Error: --target must be a full URL, e.g. http://localhost:3000", file=sys.stderr)
        sys.exit(1)

    host = args.host or parsed.hostname
    if not valid_host(host):
        print(f"Error: invalid host '{host}'. Use a hostname or IP address (it must not start with '-').", file=sys.stderr)
        sys.exit(1)
    if args.nmap_ports and not valid_ports(args.nmap_ports):
        print("Error: --nmap-ports must look like 22,80,443 or 1-1024.", file=sys.stderr)
        sys.exit(1)

    print("=" * 60)
    print(" VAPT Automation CLI")
    print(" Only run against systems you own or are authorized to test.")
    print("=" * 60)

    if args.full_scan and not args.skip_zap:
        print("[!] --full-scan enables ZAP's ACTIVE scanner: it sends attack payloads and may")
        print("    modify data or disrupt the target. Use only on systems you are authorized to attack.")

    if not confirm_authorization(host, args.yes):
        print("Authorization not confirmed. Exiting without scanning.", file=sys.stderr)
        sys.exit(1)

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.skip_nmap:
        nmap_result = {"skipped": True}
    else:
        nmap_result = run_nmap(host, output_dir, args.nmap_ports)

    if args.skip_zap:
        zap_result = {"skipped": True}
    else:
        zap_result = run_zap(args.target, output_dir, full_scan=args.full_scan, ajax=args.ajax,
                             spider_minutes=args.spider_minutes, max_minutes=args.max_minutes)

    report_path = build_report(args.target, host, nmap_result, zap_result, output_dir)

    print()
    print(f"[+] Report written to: {report_path}")
    if zap_result.get("html_path") and Path(zap_result["html_path"]).exists():
        print(f"[+] Full ZAP HTML report: {zap_result['html_path']}")


if __name__ == "__main__":
    main()