import re
import math
import urllib.parse
import requests
from bs4 import BeautifulSoup
from core.plugin import BasePlugin

def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy to measure information density/randomness."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts = {}
    for char in data:
        counts[char] = counts.get(char, 0) + 1
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

# High-confidence concrete credential formats
KNOWN_SECRET_PATTERNS = [
    (re.compile(r'\b(AKIA[0-9A-Z]{16})\b'), "AWS Access Key ID", "High"),
    (re.compile(r'\b(AIza[0-9A-Za-z\-_]{35})\b'), "Google API Key", "High"),
    (re.compile(r'\b(xox[baprs]-[0-9A-Za-z]{10,48})\b'), "Slack API Token", "High"),
    (re.compile(r'\b(gh[pousr]_[A-Za-z0-9_]{36,})\b'), "GitHub Personal Access Token", "High"),
    (re.compile(r'\b((?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,})\b'), "Stripe Key", "High"),
    (re.compile(r'\b(eyJ[A-Za-z0-9_-]{12,}\.eyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,})\b'), "Hardcoded JWT Token", "Medium"),
]

# Generic assignment regex requiring explicit quote enclosures and >= 16 chars
GENERIC_SECRET_REGEX = re.compile(
    r'''(?i)(?:api[_-]?key|secret[_-]?key|auth[_-]?token|access[_-]?token|app[_-]?secret)\s*[:=]\s*['"]([A-Za-z0-9\-_+/]{16,})['"]'''
)

FALSE_POSITIVE_VALUES = {
    'undefined', 'null', 'true', 'false', 'bearer', 'application/json',
    'your_api_key', 'your_secret', 'your_token', 'placeholder', 'dummy',
    'authorization', 'content-type', 'localstorage', 'sessionstorage',
    'injectiontoken', 'default_token', 'changeme', 'sample_token'
}

CDN_DOMAINS = {
    'cdnjs.cloudflare.com', 'cdn.jsdelivr.net', 'unpkg.com', 'ajax.googleapis.com',
    'www.google-analytics.com', 'googletagmanager.com', 'code.jquery.com',
    'stackpath.bootstrapcdn.com', 'cdn.bootcdn.net', 'static.cloudflareinsights.com',
    'connect.facebook.net', 'platform.twitter.com'
}

class JsParserPlugin(BasePlugin):
    def __init__(self):
        self._scanned_scripts = set()

    @property
    def name(self) -> str:
        return "JavaScript Token Scanner"

    def _find_tokens_in_text(self, text: str, source_label: str, source_url: str) -> list:
        findings = []
        if not text:
            return findings

        # 1. Check known specific high-confidence signatures
        for pattern, pattern_name, risk in KNOWN_SECRET_PATTERNS:
            matches = pattern.findall(text)
            for m in matches:
                # Mask secret value in report
                masked = f"{m[:4]}...{m[-4:]}" if len(m) > 8 else "***"
                findings.append({
                    'type': 'Sensitive Credential in JS',
                    'name': f"{pattern_name} ({masked}) in {source_label}",
                    'url': source_url,
                    'risk': risk
                })
                break  # Record one finding per pattern per file to prevent spam

        # 2. Check generic assignments with Shannon entropy validation
        for match in GENERIC_SECRET_REGEX.finditer(text):
            token_val = match.group(1).strip()
            lower_val = token_val.lower()

            # Ignore common false positive terms
            if any(fp in lower_val for fp in FALSE_POSITIVE_VALUES):
                continue

            # Real secrets have high Shannon entropy (typically > 3.2 for 16+ chars)
            entropy = shannon_entropy(token_val)
            if entropy < 3.2:
                continue

            masked = f"{token_val[:4]}...{token_val[-4:]}"
            findings.append({
                'type': 'High-Entropy Secret in JS',
                'name': f"Hardcoded secret ({masked}, entropy: {entropy:.2f}) in {source_label}",
                'url': source_url,
                'risk': 'Medium'
            })
            break

        return findings

    def scan(self, url: str, response, soup=None) -> list:
        vulns = []
        if not soup:
            return vulns

        scripts = soup.find_all("script")
        # 1. Inline scripts
        for i, s in enumerate(scripts):
            txt = s.string
            if txt:
                vulns.extend(self._find_tokens_in_text(txt, f"inline script #{i+1}", url))

        # 2. External scripts (deduplicated & excluding third-party CDNs)
        for s in scripts:
            src = s.get('src')
            if not src:
                continue

            full = urllib.parse.urljoin(url, src)
            if full in self._scanned_scripts:
                continue
            self._scanned_scripts.add(full)

            # Skip 3rd-party vendor CDNs
            parsed_src = urllib.parse.urlparse(full)
            if parsed_src.netloc in CDN_DOMAINS:
                continue

            try:
                r = requests.get(
                    full,
                    timeout=5,
                    headers={"User-Agent": "VulnVistaScanner/2.0"},
                    allow_redirects=True
                )
                if r and r.status_code == 200:
                    vulns.extend(self._find_tokens_in_text(r.text, src, full))
            except Exception:
                pass

        return vulns

