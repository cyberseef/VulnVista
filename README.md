# VulnVista

Professional Open-Source Web Vulnerability Scanner

## Features
- **Concurrent Multithreaded Crawling**: High-performance crawling with rate-limiting and domain-scope confinement.
- **Canary-Based Sensitive File Detection**: Baseline canary profiling eliminates soft-404/SPA false alarms; verifies real content signatures (`.env`, `.git/config`, `docker-compose.yml`, `phpinfo.php`).
- **Shannon Entropy & Secret Hunting**: Detects high-entropy secrets and explicit key signatures (AWS, Google, GitHub, Slack, Stripe, JWTs) while filtering out vendor CDNs and minified code variables.
- **Form Security Audits**: Detects insecure password transmission over HTTP, state-changing POST forms lacking Anti-CSRF tokens, and external action endpoints.
- **RFC 6797-Compliant Header Analysis**: Accurate HSTS auditing (restricted to HTTPS and public hosts) with server version disclosure pattern matching.
- **Cookie Security Classification**: Categorizes session/auth cookies vs. tracking cookies, with environment-aware flags and deduplication.
- **Context-Aware SQL Error Scanner**: Passive error matching with documentation/code block exclusion and HTTP 500 status correlation.
- **Global Deduplication Engine**: Automatically deduplicates findings across pages for clean, concise reporting.
- **Flexible Reporting**: Exports results to Markdown (`.md`), JSON (`.json`), and optional PDF reports.
- **Optional Visual Snapshots**: Automates page screenshots saved to `screenshots/`.
- **Modern Terminal UI**: Interactive progress and stylized output tables powered by `Rich`.

## Installation

1. Clone the repository:
```bash
git clone https://github.com/cyberseef/VulnVista.git
cd VulnVista
```

2. Install dependencies:

There are two ways to use VulnVista: installing it globally as a command-line tool, or running the Python script directly.

**Option A: Install Globally (Recommended)**
This allows you to use the `vulnvista` command from anywhere in your terminal.

*Linux/macOS:*
```bash
python3 -m pip install -e .
```

*Windows:*
```powershell
py -m pip install -e .
```
*(Note for Windows users: Ensure your Python `Scripts` directory is in your environment `PATH` variable, otherwise the `vulnvista` command will not be recognized).*

**Option B: Install Dependencies Only**
If you prefer not to install the package, just install the requirements to run the script directly.

*Linux/macOS:*
```bash
python3 -m pip install -r requirements.txt
```

*Windows:*
```powershell
py -m pip install -r requirements.txt
```

3. (Optional) For PDF reports and screenshots:

* Install `wkhtmltopdf` / `wkhtmltoimage` (Debian/Ubuntu/Bullseye example):

```bash
# download appropriate deb from https://wkhtmltopdf.org/downloads.html
sudo apt install ./wkhtmltox_0.12.6.1-2.bullseye_amd64.deb
```

## Usage

Depending on your installation method, you will use a different prefix to run the tool.

**If installed globally (Option A):**
Use the `vulnvista` command on any platform.
```bash
vulnvista -u https://127.0.0.1/DVWA/
```

**If running directly from the script (Option B):**
*Linux/macOS:*
```bash
python3 vuln_vista.py -u https://127.0.0.1/DVWA/
```

*Windows:*
```powershell
py vuln_vista.py -u https://127.0.0.1/DVWA/
```

---

### Common Examples

*The examples below use the global `vulnvista` command. If running as a script, replace `vulnvista` with your platform's python command (e.g., `python3 vuln_vista.py`).*

**Adjust Threads and Max Pages:**
```bash
vulnvista -u https://demo.owasp-juice.shop/#/ --max-pages 500 --threads 10
```

**Add Delay for Rate Limiting:**
```bash
vulnvista -u https://demo.owasp-juice.shop/#/ --delay 1.5
```

**Generate PDF and Screenshots** *(requires wkhtmltopdf/wkhtmltoimage)*:
```bash
vulnvista -u http://127.0.0.1/DVWA/ --pdf-report --take-screenshots
```

## Output

Reports are created under `output/`:

* `report_<domain>_<timestamp>.md`
* `report_<domain>_<timestamp>.json`
* optional: `report_<domain>_<timestamp>.pdf`

Screenshots (when enabled) are saved under `screenshots/`:

* `screenshot_<page>.png` (uses a small JavaScript render delay to avoid blank images)

## Architecture & Adding Plugins
VulnVista uses a modular plugin architecture. To add a new vulnerability check, simply create a new Python file in the `modules/` directory that inherits from `core.plugin.BasePlugin`. The scanner will automatically load it.

## Notes & limitations

* **Non-intrusive only** - strictly passive and non-destructive auditing; no active exploit attempts.
* **Smart Noise Reduction** - uses canary checks, content verification, and Shannon entropy to prevent false positives.
* **Scope-Aware** - external CDN scripts and out-of-domain resources are filtered from scans.
* No authenticated session crawling included (keeps scanning safe, deterministic, and lightweight).
* Screenshots require `wkhtmltoimage` installed locally; the tool waits briefly for JS rendering.
* Use only on targets you own or have explicit permission to audit.


## Ethics

Only scan environments you own or have explicit permission to test. Follow responsible disclosure.
