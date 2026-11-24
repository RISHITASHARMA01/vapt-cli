# VAPT CLI — offline assessment upgrade

This optional **standard-library-only** module complements the existing `vapt_cli.py` Nmap/ZAP scanning workflow. It does not need Nessus installed and **never launches a scan**.

## Features

- Imports Nessus `.nessus` XML (NessusClientData_v2), including plugin ID, CVEs, host, exported CVSS base score, solution and scanner output.
- Imports ZAP JSON exports and Nmap XML output. Prioritizes by CVSS where supplied; otherwise uses scanner severity, clearly marking missing CVSS.
- Generates one Markdown report with source hashes, executive counts, ranked observations, remediation, verification actions, and optional authorized-lab evidence.
- Provides entirely synthetic fixtures (reserved example hostnames and documentation IPs) and offline parser tests.

## Quick start

```bash
python3 assessment.py --nessus examples/synthetic_lab.nessus \
    --zap-json examples/synthetic_zap.json \
    --nmap-xml examples/synthetic_nmap.xml \
    --evidence examples/lab_evidence.json \
    --output vapt_output/consolidated_report.md
python3 -m unittest discover -s tests -p 'test_assessment.py' -v
```

To consolidate your own **authorized** outputs, replace the three example filenames with exports from Nessus, OWASP ZAP and Nmap. Inputs are optional individually, but at least one scanner export is required. Existing `vapt_cli.py` produces `vapt_output/zap_report.json` and `vapt_output/nmap_scan.xml`.

## Evidence template

Supply a local JSON file structured as:

```json
{
  "lab": "Locally hosted OWASP Juice Shop",
  "authorization": "Lab owned and operated by assessor",
  "records": [
    {
      "label": "Finding confirmation",
      "observation": "Document exactly what was observed, without secrets.",
      "artifact": "private/path/to/redacted-screenshot.png"
    }
  ]
}
```

Do **not** invent test execution or upload sensitive screenshots or vulnerability exports. Public examples in this repository are synthetic, **not** actual Nessus or Juice Shop scan evidence.

## CVSS and prioritization

The importer uses Nessus-exported CVSS v3 base score if available, falling back to v2 base score; no score means `Not supplied`. Numeric base scores map to 0 = informational, 0.1–3.9 low, 4.0–6.9 medium, 7.0–8.9 high and 9.0–10.0 critical. Scanner severity is a fallback, **not** a fabricated CVSS score. Human reviewers should refine priorities for business impact, attack exposure and exploitability.

## Limitations

- Nessus integration **imports existing reports**; it does not connect to the Nessus API.
- Findings remain observations pending validation; cross-tool deduplication and asset normalization are not implemented.
- Nmap open ports are informational, not proof of vulnerability.
- XML inputs reject DTD/entity declarations and files larger than 25 MB; do not process untrusted oversized reports.
- This report is not a penetration-test certificate. Test only systems you own or have written authorization for.
