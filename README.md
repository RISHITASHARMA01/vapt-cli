# VAPT Automation CLI

A simple command-line tool that automates a basic VAPT (Vulnerability
Assessment & Penetration Testing) workflow: network scanning (Nmap) +
automated web vulnerability scanning (OWASP ZAP), with results compiled
into a single Markdown report mapped to the OWASP Top 10.

Built as a placement/portfolio project to demonstrate:
- Vulnerability Assessment & Penetration Testing (VAPT)
- Network & Application Security Assessments
- Security Automation using Open-Source Tools
- OWASP Top 10 mapping

> ⚠️ **Only run this against systems you own or have explicit written
> authorization to test.** A safe, legal target for practice is a
> locally-hosted [OWASP Juice Shop](https://github.com/juice-shop/juice-shop)
> instance.

---

## 1. Setup

### Install the target (OWASP Juice Shop) locally via Docker
```bash
docker pull bkimminich/juice-shop
docker run -d -p 3000:3000 bkimminich/juice-shop
```
Juice Shop will now be running at `http://localhost:3000`.

### Install required tools

**Nmap:**
```bash
sudo apt install nmap
```

**OWASP ZAP:**

This project runs ZAP via Docker (no local install needed):
```bash
docker pull zaproxy/zap-stable
```

**Python 3.8+** (already required to run this script). No third-party
Python packages are required — the CLI only uses the standard library.

---

## 2. Run the scan

```bash
python3 vapt_cli.py --target http://localhost:3000 --host localhost
```

Optional: specify a custom output folder
```bash
python3 vapt_cli.py --target http://localhost:3000 --host localhost --output ./my_scan_results
```

Optional: skip a stage
```bash
python3 vapt_cli.py --target http://localhost:3000 --host localhost --skip-nmap
python3 vapt_cli.py --target http://localhost:3000 --host localhost --skip-zap
```

---

## 3. What you get

Inside the output folder (`./vapt_output` by default):
- `vapt_report.md` — auto-generated Markdown report (Nmap results, ZAP
  findings mapped to OWASP Top 10 categories, recommendations)
- `zap_report.html` — full detailed ZAP HTML report
- `zap_report.json` — raw ZAP findings (used to build the Markdown report)
- `nmap_scan.txt` / `nmap_scan.xml` — raw Nmap output

---

## 4. Suggested next steps for your placement project

1. Run this tool against your local Juice Shop instance.
2. Take the auto-generated `vapt_report.md` and manually add 3-5 findings
   you discover yourself using **Burp Suite** (manual testing always finds
   more than automated scanners, e.g. IDOR, broken auth logic).
3. Add screenshots of your Burp Suite requests/responses to the report.
4. Push the whole project (script + report + screenshots) to a public
   GitHub repo with a clean README (this file is a good starting template).
5. On your resume:
   > "Built a Python CLI tool automating Nmap + OWASP ZAP scanning against
   > OWASP Juice Shop; identified and documented vulnerabilities mapped to
   > the OWASP Top 10 with remediation recommendations."

---

## 5. Notes / limitations

- The OWASP Top 10 mapping in the script is a simple keyword-based helper,
  not a substitute for manual security analysis — use it as a starting
  point in your report, not a final classification.
- ZAP's baseline scan is passive + light active only; it will not find
  everything. Pair it with manual Burp Suite testing for a stronger project.
- This script does not perform exploitation (e.g., Metasploit) — that's
  intentionally left as a manual, well-documented step for your report
  since exploitation is harder to automate safely and responsibly.
