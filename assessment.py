#!/usr/bin/env python3
"""Offline, read-only consolidation of Nessus, ZAP and Nmap assessment exports.

Does not launch scans. Python standard library only.
"""
import argparse
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import html
import json
import re
import sys
import xml.etree.ElementTree as ET

MAX_INPUT_BYTES = 25 * 1024 * 1024
LEVELS = ("Critical", "High", "Medium", "Low", "Informational", "Unknown")
SEVERITIES = {"4": "Critical", "3": "High", "2": "Medium", "1": "Low", "0": "Informational"}
GENERIC_FIXES = {
    "Critical": "Validate the exposure, isolate affected assets where appropriate, and apply a vendor fix promptly.",
    "High": "Prioritize vendor patches and compensating controls, then verify with an authorized rescan.",
    "Medium": "Schedule remediation based on asset exposure and verify the corrective control.",
    "Low": "Address during routine hardening and review the resulting configuration.",
    "Informational": "Confirm the observation and document whether any action is necessary.",
    "Unknown": "Manually verify the finding and assign a risk rating before remediation."
}

def safe_text(value, limit=1000):
    """Strip HTML and newlines; escape Markdown table separators."""
    value = re.sub(r"<[^>]*>", " ", html.unescape(str(value or "")))
    value = re.sub(r"\s+", " ", value).strip()
    return value[:limit].replace("|", "\\|").replace("`", "'")

def read_input(path):
    path = Path(path)
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError(f"Input exceeds {MAX_INPUT_BYTES} bytes: {path}")
    return path.read_bytes()

def parse_cvss(value):
    """Use an exported base score; do not infer a CVSS score from scanner severity."""
    try:
        number = float(str(value).strip())
    except (ValueError, TypeError):
        return None
    if number != number or not 0 <= number <= 10:
        return None
    return round(number, 1)

def risk_from_cvss(score):
    if score is None:
        return "Unknown"
    if score == 0:
        return "Informational"
    if score < 4:
        return "Low"
    if score < 7:
        return "Medium"
    if score < 9:
        return "High"
    return "Critical"

def first_text(elem, *names):
    for name in names:
        node = elem.find(name)
        if node is not None and node.text and node.text.strip():
            return node.text.strip()
    return ""

def normalized(title, host, source, severity, score=None, cve="", remediation="", evidence="", plugin=""):
    score = parse_cvss(score)
    if score is not None:
        severity = risk_from_cvss(score)
    if severity not in LEVELS:
        severity = "Unknown"
    return {
        "title": safe_text(title, 200), "host": safe_text(host, 200),
        "source": source, "severity": severity, "cvss": score,
        "cve": safe_text(cve, 200), "plugin": safe_text(plugin, 100),
        "remediation": safe_text(remediation, 800),
        "evidence": safe_text(evidence, 400)
    }

def parse_nessus(path):
    """Parse .nessus v2 XML export safely (no entity expansion or network calls)."""
    data = read_input(path)
    if b"<!DOCTYPE" in data.upper() or b"<!ENTITY" in data.upper():
        raise ValueError("DTD/entity declarations are not permitted in Nessus XML")
    root = ET.fromstring(data)
    if root.tag != "NessusClientData_v2":
        raise ValueError("Expected NessusClientData_v2 XML")
    findings = []
    for report in root.findall("./Report"):
        for host in report.findall("./ReportHost"):
            hostname = host.get("name", "unknown")
            for item in host.findall("ReportItem"):
                severity = SEVERITIES.get(item.get("severity", ""), "Unknown")
                # Prefer v3 base score when present; fallback to v2.
                score = first_text(item, "cvss3_base_score", "cvss_base_score")
                cves = [node.text.strip() for node in item.findall("cve") if node.text]
                cve = ", ".join(dict.fromkeys(cves))
                location = "/".join(p for p in (hostname, item.get("protocol", ""), item.get("port", "")) if p)
                findings.append(normalized(
                    item.get("pluginName") or first_text(item, "plugin_name") or "Nessus finding",
                    location, "Nessus", severity, score=score, cve=cve,
                    remediation=first_text(item, "solution", "see_also"),
                    evidence=first_text(item, "plugin_output", "synopsis"),
                    plugin=item.get("pluginID", "")
                ))
    return findings

def parse_zap(path):
    data = json.loads(read_input(path))
    if not isinstance(data, dict):
        raise ValueError("ZAP JSON must be an object")
    findings = []
    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            risk_text = str(alert.get("riskdesc") or alert.get("risk") or "").split(" ")[0].title()
            urls = [instance.get("uri", "") for instance in alert.get("instances", []) if isinstance(instance, dict)]
            host = urls[0] if urls else site.get("@name", site.get("name", "unknown"))
            findings.append(normalized(
                alert.get("name", "ZAP alert"), host, "ZAP",
                risk_text if risk_text in LEVELS else "Unknown",
                remediation=alert.get("solution", ""),
                evidence=alert.get("desc", "")
            ))
    return findings

def parse_nmap(path):
    data = read_input(path)
    if b"<!DOCTYPE" in data.upper() or b"<!ENTITY" in data.upper():
        raise ValueError("DTD/entity declarations are not permitted in Nmap XML")
    root = ET.fromstring(data)
    if root.tag != "nmaprun":
        raise ValueError("Expected nmaprun XML")
    findings = []
    for host in root.findall("host"):
        addr = host.find("address")
        hostname = addr.get("addr", "unknown") if addr is not None else "unknown"
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            service_name = service.get("name", "unknown") if service is not None else "unknown"
            findings.append(normalized(
                f"Open {port.get('protocol', '?')}/{port.get('portid', '?')} ({service_name})",
                hostname, "Nmap", "Informational",
                remediation="Review whether this port is required and restrict access when appropriate.",
                evidence="Open port observed; not proof of a vulnerability."
            ))
    return findings

def parse_evidence(path):
    data = json.loads(read_input(path))
    if not isinstance(data, dict) or not isinstance(data.get("records"), list):
        raise ValueError("Evidence JSON must contain a records array")
    return data

def score_key(finding):
    # Unknown CVSS must not be advertised as scored; scanner severity is only a fallback.
    severity_rank = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Informational": 1, "Unknown": 0}
    return (-severity_rank[finding["severity"]], -(finding["cvss"] if finding["cvss"] is not None else -1),
            finding["source"], finding["title"], finding["host"])

def report(findings, inputs, evidence=None):
    findings = sorted(findings, key=score_key)
    counts = Counter(f["severity"] for f in findings)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# Consolidated Vulnerability Assessment", "",
        f"**Generated:** {now}", "**Method:** offline import of existing scanner exports", "",
        "> Scanner findings are unverified until manually confirmed. No scans were executed by this command.", "",
        "## Scope and provenance", "",
    ]
    for source, path in inputs:
        digest = hashlib.sha256(read_input(path)).hexdigest()
        lines.append(f"- {source}: `{safe_text(Path(path).name, 180)}` (SHA-256: `{digest}`)")
    lines += ["", "## Executive summary", "",
              f"**{len(findings)} observations** across imported sources (not de-duplicated or validated).", "",
              "| Severity | Count |", "|---|---:|"]
    lines += [f"| {level} | {counts[level]} |" for level in LEVELS]
    lines += ["", "## Prioritized findings", "",
              "| Priority | Tool | Affected host / URL | Finding | CVSS base | CVE |",
              "|---|---|---|---|---:|---|"]
    for f in findings:
        score = f"{f['cvss']:.1f}" if f["cvss"] is not None else "Not supplied"
        lines.append(f"| {f['severity']} | {f['source']} | {f['host']} | {f['title']} | {score} | {f['cve'] or '—'} |")
    lines += ["", "## Remediation and verification", ""]
    for i, f in enumerate(findings, 1):
        fix = f["remediation"] or GENERIC_FIXES[f["severity"]]
        lines += [f"### {i}. [{f['severity']}] {f['title']}", "",
                  f"- **Source / asset:** {f['source']} / {f['host']}",
                  f"- **CVE / plugin:** {f['cve'] or 'Not supplied'} / {f['plugin'] or 'Not supplied'}",
                  f"- **Recommended action:** {fix}",
                  "- **Verification:** Manually validate, document the fix, and retest only within written authorization."]
        if f["evidence"]:
            lines.append(f"- **Scanner evidence excerpt (unverified):** {f['evidence']}")
        lines.append("")
    lines += ["## Authorized lab evidence", ""]
    if evidence:
        lines.append(f"**Lab:** {safe_text(evidence.get('lab', 'Not specified'))}  ")
        lines.append(f"**Authorization:** {safe_text(evidence.get('authorization', 'Not specified'))}  ")
        for record in evidence["records"]:
            if not isinstance(record, dict):
                continue
            lines.append(f"- **{safe_text(record.get('label', 'Evidence'))}:** "
                         f"{safe_text(record.get('observation', ''))} "
                         f"(artifact: `{safe_text(record.get('artifact', 'not supplied'))}`)")
    else:
        lines.append("No lab evidence supplied. Do not interpret scanner output as proof of exploitation.")
    lines += ["", "## Limitations", "",
              "- CVSS scores are copied from Nessus exports, not calculated independently; ZAP/Nmap observations generally lack scores.",
              "- Severity falls back to scanner labels when CVSS is absent. Exposure, asset importance and exploitability require manual review.",
              "- Open Nmap ports are informational observations, not automatically vulnerabilities.",
              "- Duplicate findings from different scanners may remain; validate before tracking remediation.",
              "- Redact sensitive URLs, IPs, credentials and scanner outputs before publishing reports.",
              "- Only scan systems you own or are explicitly authorized to test.", ""]
    return "\n".join(lines)

def main(argv=None):
    p = argparse.ArgumentParser(description="Offline Nessus + ZAP + Nmap vulnerability assessment")
    p.add_argument("--nessus", type=Path, help=".nessus XML export")
    p.add_argument("--zap-json", type=Path, help="OWASP ZAP JSON export")
    p.add_argument("--nmap-xml", type=Path, help="Nmap XML output")
    p.add_argument("--evidence", type=Path, help="Optional lab evidence JSON")
    p.add_argument("--output", type=Path, default=Path("vapt_output/consolidated_report.md"))
    args = p.parse_args(argv)
    inputs = [(label, value) for label, value in
              (("Nessus", args.nessus), ("ZAP", args.zap_json), ("Nmap", args.nmap_xml)) if value]
    if not inputs:
        p.error("at least one of --nessus, --zap-json or --nmap-xml is required")
    try:
        findings = []
        for label, path in inputs:
            findings.extend({"Nessus": parse_nessus, "ZAP": parse_zap, "Nmap": parse_nmap}[label](path))
        evidence = parse_evidence(args.evidence) if args.evidence else None
        content = report(findings, inputs, evidence)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(content, encoding="utf-8")
    except (ValueError, OSError, ET.ParseError, json.JSONDecodeError) as exc:
        p.exit(2, f"Error: {exc}\n")
    print(f"Created {args.output} with {len(findings)} observations.")

if __name__ == "__main__":
    main()
