# VulnVista

Professional Open-Source Web Vulnerability Scanner

## Features
- Accept target URL
- Multithreaded concurrent scanning for fast results
- Modular Plugin Architecture: Easily extensible with custom vulnerability checks
- Crawl same-domain pages (discover pages/forms)
- Detect open directories & common sensitive files (`.env`, `docker-compose.yml`, etc.)
- Parse HTML/JS for sensitive tokens (API keys, etc.)
- Check for missing security headers and insecure cookies (Secure + HttpOnly)
- Enumerate GET/POST parameters, explicitly list hidden fields
- Basic SQL error signature detection in responses (passive)
- Generate `.md` and `.json` reports (optional PDF via wkhtmltopdf)
- Screenshots saved to `screenshots/` (optional)
- Beautiful Terminal UI using `Rich`

## Install
1. Clone:
```bash
git clone https://github.com/cyberseef/VulnVista.git
cd VulnVista
```

2. Install the dependencies:

**Windows:**
```powershell
py -m pip install -r requirements.txt
# OR install as a package:
py -m pip install -e .
```

**Linux/macOS:**
```bash
python3 -m pip install -r requirements.txt
python3 -m pip install -e .
```

3. (Optional) For PDF reports and screenshots:

* Install `wkhtmltopdf` / `wkhtmltoimage` (Debian/Ubuntu/Bullseye example):

```bash
# download appropriate deb from https://wkhtmltopdf.org/downloads.html
sudo apt install ./wkhtmltox_0.12.6.1-2.bullseye_amd64.deb
```

## Usage

If you installed it as a package and your Python Scripts folder is in your PATH, you can run the tool globally via the `vulnvista` command. 

If `vulnvista` or `pip` is not recognized, run the script directly using the Python launcher `py` (Windows) or `python3` (Linux/Mac):

Basic:

```powershell
py vuln_vista.py -u https://127.0.0.1/DVWA/
```

Adjust Threads and Max Pages:

```bash
vulnvista -u https://demo.owasp-juice.shop/#/ --max-pages 500 --threads 10
```

Add Delay for Rate Limiting:

```bash
vulnvista -u https://demo.owasp-juice.shop/#/ --delay 1.5
```

Generate PDF and screenshots (if wkhtmltopdf/wkhtmltoimage installed):

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

* **Non-intrusive only** - no active exploit attempts.
* No login automation included (keeps tool simple & stable).
* JS parsing is shallow (checks inline and linked JS for token-like patterns).
* Screenshots require `wkhtmltoimage`; the tool waits briefly for JS rendering.
* Use only on targets you have permission to test.

## Ethics

Only scan environments you own or have explicit permission to test. Follow responsible disclosure.
