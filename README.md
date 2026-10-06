# VAPT Automation CLI

A command-line tool that automates a basic Vulnerability Assessment & Penetration Testing (VAPT) workflow. It runs an **Nmap** network scan and an **OWASP ZAP** web scan (via Docker), then compiles the results into a single Markdown report with findings mapped to the **OWASP Top 10 (2021)**.

Built as a capstone project to demonstrate:

- Vulnerability assessment of networks and web applications
- Security automation with open-source tools
- Mapping scanner findings to OWASP Top 10 categories (CWE-based)
- Safe-by-default design (authorization prompt, input validation, time limits)

> ⚠️ **Legal notice:** only run this tool against systems you own or have explicit written authorization to test. Unauthorized scanning is illegal in most jurisdictions. A safe practice target is a locally hosted [OWASP Juice Shop](https://github.com/juice-shop/juice-shop).

---

## How it works

1. **Nmap** scans the target host (service/version detection) and the open ports are parsed from Nmap's XML output.
2. **OWASP ZAP** scans the target URL inside a Docker container (`zaproxy/zap-stable`):
   - **Baseline mode (default):** spider + passive rules only. It sends **no attack payloads**.
   - **Full mode (`--full-scan`):** adds ZAP's **active scanner**, which sends attack payloads.
3. Each ZAP alert is mapped to an OWASP Top 10 (2021) category using its **CWE id** first, then alert-name keywords as a fallback.
4. Everything is compiled into `vapt_report.md`.

---

## Requirements

- Python 3.8+ (standard library only, no `pip install` needed)
- [Nmap](https://nmap.org/): `sudo apt install nmap`
- [Docker](https://docs.docker.com/engine/install/) (used to run ZAP: `docker pull zaproxy/zap-stable`)

The tool is developed and tested on Linux. On Docker Desktop (Windows/macOS), `localhost` targets are rewritten to `host.docker.internal`; this path has not been tested.

---

## Setup: a safe practice target

Run OWASP Juice Shop locally in Docker. Use any free port on your machine (the first number); the second number must stay `3000`:

```bash
docker run -d --name juice-shop -p 3002:3000 bkimminich/juice-shop
```

Juice Shop is then at `http://localhost:3002`. Remove it afterwards with `docker rm -f juice-shop`.

---

## Usage

```bash
python3 vapt_cli.py --target http://localhost:3002
```

Before any scan starts, you must type the target host to confirm you are authorized to test it.

### Common examples

```bash
# Baseline scan, Nmap limited to the app's port, custom output folder
python3 vapt_cli.py --target http://localhost:3002 --nmap-ports 3002 --output ./results

# Use ZAP's AJAX spider (better coverage of JavaScript apps)
python3 vapt_cli.py --target http://localhost:3002 --ajax

# Skip a stage
python3 vapt_cli.py --target http://localhost:3002 --skip-nmap
python3 vapt_cli.py --target http://localhost:3002 --skip-zap

# FULL scan with active attacks (authorized targets only; can take a long time)
python3 vapt_cli.py --target http://localhost:3002 --full-scan
```

### Options

| Option | Description |
|--------|-------------|
| `--target URL` | **Required.** Target URL for the ZAP scan, e.g. `http://localhost:3002` |
| `--host HOST` | Host/IP for Nmap. Default: taken from `--target` |
| `--output DIR` | Output folder (default: `./vapt_output`) |
| `--skip-nmap` | Skip the Nmap scan |
| `--skip-zap` | Skip the ZAP scan |
| `--nmap-ports SPEC` | Nmap port spec, e.g. `22,80,443` or `1-1024` (default: Nmap's top 1000 ports) |
| `--full-scan` | Run ZAP's **full scan with the active scanner** (sends attack payloads) |
| `--ajax` | Use ZAP's AJAX spider |
| `--spider-minutes N` | Max minutes for the ZAP spider (default: 2) |
| `--max-minutes N` | Max minutes for the ZAP scan phase (default: 10) |
| `--yes` | Skip the interactive authorization prompt (you accept full responsibility) |

The script also stops ZAP automatically after 30 minutes (baseline) or 60 minutes (full scan).

---

## Output

Inside the output folder:

| File | Contents |
|------|----------|
| `vapt_report.md` | Compiled report: summary, open ports, findings by OWASP category, recommendations, limitations |
| `zap_report.html` | Detailed ZAP report for human review |
| `zap_report.json` | Raw ZAP findings (parsed to build the report) |
| `nmap_scan.txt` / `nmap_scan.xml` | Raw Nmap output |

Each finding in the report shows its risk level, CWE id, number of instances, a sample of affected URLs, a description and a recommendation.

---

## Safety features

- **Authorization prompt:** you must type the target host before any scan runs.
- **Input validation:** the Nmap host and port arguments are validated, so they cannot be interpreted as Nmap options.
- **No stale results:** old report files are deleted before each scan, so a failed run can never reuse previous output.
- **Time limits:** ZAP's spider and scan phases are capped, and a hung scan is killed together with its Docker container.
- **Live output:** ZAP's progress is streamed to the terminal.

---

## Limitations

- **Baseline mode is passive.** It crawls the site and analyses responses; it sends no attack payloads, so it **cannot confirm vulnerabilities such as SQL injection or XSS**. Typical baseline findings are missing security headers, cookie flags and information disclosure. Use `--full-scan` (on authorized targets only) for active testing.
- **OWASP mapping is approximate.** It uses a best-effort CWE-to-category table plus name keywords. Some alerts stay "Unmapped / Manual Review Needed". Verify classifications manually before using them in a formal report.
- **Unauthenticated scanning only.** Areas behind a login are not tested.
- **No exploitation.** The tool does not exploit anything (e.g. Metasploit); manual testing (e.g. Burp Suite) is needed for business-logic flaws, IDOR and broken authorization.
- **Automated findings are a starting point,** not a final security assessment.

---

## Project structure

```
vapt-cli/
├── vapt_cli.py   # the CLI tool (scan orchestration + report generation)
├── README.md
└── .gitignore
```

---

## Roadmap

- [ ] Unit tests (pytest) for the mapping and validation helpers
- [ ] Authenticated scanning support
- [ ] HTML/PDF report export
- [ ] Wider CWE-to-OWASP mapping coverage
- [ ] Web dashboard for viewing reports

---

## Disclaimer

This tool is for educational and authorized security testing only. The author accepts no responsibility for misuse or damage caused by running it against systems without permission.