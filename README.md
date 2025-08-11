# VulnVista

Lightweight non-intrusive web vulnerability scanner (Module 7 project).

## Features (requirements)
- Accept target URL
- Crawl same-domain pages (discover pages/forms)
- Detect open directories & common public files (robots.txt, sitemap.xml, etc.)
- Parse HTML/JS for tokens
- Check for missing security headers and insecure cookies (Secure + HttpOnly)
- Enumerate GET/POST parameters, explicitly list hidden fields
- Detect URL query parameters present on pages
- Basic SQL error signature detection in responses (passive)
- Generate `.md` report (optional PDF via wkhtmltopdf); screenshots saved to `screenshots/`

## Install
1. Clone:
```bash
git clone https://github.com/cyberseef/VulnVista.git
cd VulnVista
````

2. Python deps:

```bash
python3 -m pip install -r requirements.txt
```

3. (Optional) For PDF reports and screenshots:

* Install `wkhtmltopdf` / `wkhtmltoimage` (Debian/Ubuntu/Bullseye example):

```bash
# download appropriate deb from https://wkhtmltopdf.org/downloads.html
sudo apt install ./wkhtmltox_0.12.6.1-2.bullseye_amd64.deb
```

* Verify:

```bash
wkhtmltopdf --version
wkhtmltoimage --version
```

## Usage

Basic:

```bash
python3 vuln_vista.py -u https://127.0.0.1/DVWA/
```
```bash
python3 vuln_vista.py -u https://demo.owasp-juice.shop/#/
```

Max pages limit:

```bash
python3 vuln_vista.py -u http://127.0.0.1/DVWA/ --max-pages 200
```
```bash
python3 vuln_vista.py -u https://demo.owasp-juice.shop/#/ --max-pages 200
```

Generate PDF and screenshots (if wkhtmltopdf/wkhtmltoimage installed):

```bash
python3 vuln_vista.py -u http://127.0.0.1/DVWA/ --pdf-report --take-screenshots
```
```bash
python3 vuln_vista.py -u https://demo.owasp-juice.shop/#/ --pdf-report --take-screenshots
```

## Output

Reports are created under `output/`:

* `report_<domain>_<timestamp>.md`
* optional: `report_<domain>_<timestamp>.pdf`

Screenshots (when enabled) are saved under `screenshots/`:

* `screenshot_<page>.png` (uses a small JavaScript render delay to avoid blank images)

## Sample
**[MD Report Sample](/output/sample.md)**
[![PDF OWASP JUICE SHOP](/output/samplemd.png)](/output/sample.md)

**[PDF Report Sample](/output/sample.pdf)**
[![PDF OWASP JUICE SHOP](/output/samplepdf.png)](/output/sample.pdf)

**[Screenshot Sample](/screenshots/sample.png)**
[![Screenshot OWASP JUICE SHOP](/screenshots/sample.png)](/screenshots/sample.png)

## Notes & limitations

* **Non-intrusive only** - no active exploit attempts.
* No login automation included (keeps tool simple & stable).
* JS parsing is shallow (checks inline and linked JS for token-like patterns).
* Screenshots require `wkhtmltoimage`; the tool waits briefly for JS rendering.
* For large sites, raise `--max-pages` carefully.
* Use only on targets you have permission to test.

## Ethics

Only scan environments you own or have explicit permission to test. Follow responsible disclosure.

