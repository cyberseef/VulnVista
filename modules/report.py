# modules/report.py
import os
import urllib.parse
import markdown2
import pdfkit
import subprocess
from datetime import datetime

OUTPUT_DIR = "output"
SCREENSHOT_DIR = "screenshots"

def safe_name_for_domain(url):
    d = urllib.parse.urlparse(url).netloc
    return d.replace(":", "_").replace("/", "_")

def _ensure_dirs():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(SCREENSHOT_DIR, exist_ok=True)

def _wkhtmltoimage_available():
    try:
        subprocess.run(["wkhtmltoimage", "--version"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except Exception:
        return False

def generate(target, pages, vulns, pdf=False, timestamp=None, take_screenshots=False):
    _ensure_dirs()
    domain = safe_name_for_domain(target)
    ts = timestamp or datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    md_filename = f"report_{domain}_{ts}.md"
    pdf_filename = f"report_{domain}_{ts}.pdf"
    md_path = os.path.join(OUTPUT_DIR, md_filename)
    pdf_path = os.path.join(OUTPUT_DIR, pdf_filename)

    content = f"# Vulnerability Report\n\n"
    content += f"**Target:** {target}\n\n"
    content += f"**Generated:** {ts}\n\n"
    content += "## Pages Discovered\n"
    for p in pages:
        content += f"- {p}\n"

    content += "\n## Vulnerabilities Found\n"
    if not vulns:
        content += "No non-intrusive issues detected.\n"
    else:
        for v in vulns:
            content += f"### {v.get('type')}\n"
            content += f"- **Name:** {v.get('name')}\n"
            content += f"- **Page:** {v.get('url')}\n"
            content += f"- **Risk Level:** {v.get('risk')}\n\n"

    with open(md_path, 'w') as f:
        f.write(content)

    # Convert to PDF if requested and wkhtmltopdf available
    pdf_created = False
    if pdf:
        try:
            html = markdown2.markdown(content)
            pdfkit.from_string(html, pdf_path)
            pdf_created = True
        except Exception as e:
            print(f"[!] Failed to create PDF: {e}")

    # optional screenshots via wkhtmltoimage if requested
    screenshots = []
    if take_screenshots and _wkhtmltoimage_available():
        for i, p in enumerate(pages[:20]):  # limit to first 20 pages
            safe = p.replace("http://", "").replace("https://", "").replace("/", "_")
            outname = os.path.join(SCREENSHOT_DIR, f"screenshot_{safe}.png")
            try:
                # Use JS delay to allow dynamic pages to render; add quality and disable smart width
                subprocess.run([
                    "wkhtmltoimage",
                    "--width", "1280",
                    "--height", "900",
                    "--quality", "90",
                    "--disable-smart-width",
                    "--javascript-delay", "2000",
                    p,
                    outname
                ], check=True, timeout=45)
                screenshots.append(outname)
            except Exception:
                # don't fail the whole run on screenshot errors
                pass

    result = {
        'md': md_path,
        'pdf': pdf_path if pdf_created else None,
        'screenshots': screenshots
    }
    return result
