import os
import urllib.parse
import markdown2
import pdfkit
import subprocess
import json
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

def generate(target, pages, vulns, pdf=False, json_out=True, timestamp=None, take_screenshots=False):
    _ensure_dirs()
    domain = safe_name_for_domain(target)
    ts = timestamp or datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    
    md_filename = f"report_{domain}_{ts}.md"
    pdf_filename = f"report_{domain}_{ts}.pdf"
    json_filename = f"report_{domain}_{ts}.json"
    
    md_path = os.path.join(OUTPUT_DIR, md_filename)
    pdf_path = os.path.join(OUTPUT_DIR, pdf_filename)
    json_path = os.path.join(OUTPUT_DIR, json_filename)

    # 1. Generate Markdown
    content = f"# VulnVista Security Report\n\n"
    content += f"**Target:** `{target}`\n\n"
    content += f"**Generated:** `{ts}`\n\n"
    
    content += "## 🌐 Pages Discovered\n"
    for p in pages:
        content += f"- {p}\n"

    content += "\n## ⚠️ Vulnerabilities Found\n"
    if not vulns:
        content += "> No non-intrusive issues detected.\n"
    else:
        # Group by risk
        grouped_vulns = {'High': [], 'Medium': [], 'Low': [], 'Info': []}
        for v in vulns:
            risk = v.get('risk', 'Info')
            if risk in grouped_vulns:
                grouped_vulns[risk].append(v)
            else:
                grouped_vulns['Info'].append(v)
                
        for risk in ['High', 'Medium', 'Low', 'Info']:
            if not grouped_vulns[risk]:
                continue
            content += f"### {risk} Risk\n"
            for v in grouped_vulns[risk]:
                content += f"- **Type:** {v.get('type')}\n"
                content += f"  - **Name:** {v.get('name')}\n"
                content += f"  - **Page:** {v.get('url')}\n"
                if 'status' in v:
                    content += f"  - **Status Code:** {v.get('status')}\n"
            content += "\n"

    with open(md_path, 'w', encoding='utf-8') as f:
        f.write(content)

    # 2. Convert to PDF if requested
    pdf_created = False
    if pdf:
        try:
            html = markdown2.markdown(content)
            pdfkit.from_string(html, pdf_path)
            pdf_created = True
        except Exception as e:
            print(f"[!] Failed to create PDF: {e}")

    # 3. JSON Output
    json_created = False
    if json_out:
        report_data = {
            "target": target,
            "timestamp": ts,
            "pages_discovered": pages,
            "vulnerabilities": vulns
        }
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=4)
        json_created = True

    # 4. Screenshots
    screenshots = []
    if take_screenshots and _wkhtmltoimage_available():
        for i, p in enumerate(pages[:20]):
            safe = p.replace("http://", "").replace("https://", "").replace("/", "_")
            outname = os.path.join(SCREENSHOT_DIR, f"screenshot_{safe}.png")
            try:
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
                pass

    result = {
        'md': md_path,
        'pdf': pdf_path if pdf_created else None,
        'json': json_path if json_created else None,
        'screenshots': screenshots
    }
    return result
