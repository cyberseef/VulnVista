# modules/js_parser.py
import re
from bs4 import BeautifulSoup
import urllib.parse
import requests

TOKEN_REGEX = re.compile(r'(?i)(?:api[_-]?key|apikey|token|secret|auth[_-]?token|access[_-]?token)[:=]\s*[\'"]?([A-Za-z0-9\-_]{6,})')

def check_js_tokens(url, html_text, vulns):
    soup = BeautifulSoup(html_text, "html.parser")
    # inline scripts
    scripts = soup.find_all("script")
    for s in scripts:
        txt = s.string
        if txt:
            if TOKEN_REGEX.search(txt):
                vulns.append({
                    'type': 'Sensitive Token in JS',
                    'name': 'Hardcoded token in inline JS',
                    'url': url,
                    'risk': 'Medium'
                })
    # external scripts - check briefly (non-intrusive)
    for s in scripts:
        src = s.get('src')
        if src:
            full = urllib.parse.urljoin(url, src)
            try:
                r = requests.get(full, timeout=5, headers={"User-Agent":"VulnVistaScanner/1.0"})
                if r and TOKEN_REGEX.search(r.text):
                    vulns.append({
                        'type': 'Sensitive Token in JS',
                        'name': f'Hardcoded token in {src}',
                        'url': full,
                        'risk': 'Medium'
                    })
            except:
                pass
