import urllib.parse
import re
from core.plugin import BasePlugin

VERSION_DISCLOSURE_REGEX = re.compile(r'[/_ ]\d+(\.\d+)+')

class HeadersPlugin(BasePlugin):
    def __init__(self):
        self._scanned_hosts = set()

    @property
    def name(self) -> str:
        return "Security Headers Scanner"

    def scan(self, url: str, response, soup=None) -> list:
        vulns = []
        parsed = urllib.parse.urlparse(url)
        host = parsed.netloc

        # Security headers are host-level configurations; report once per host
        if host in self._scanned_hosts:
            return vulns
        self._scanned_hosts.add(host)

        headers = response.headers
        is_https = parsed.scheme == "https"
        is_localhost = parsed.hostname in ("localhost", "127.0.0.1", "::1")

        # 1. Content-Security-Policy
        if 'Content-Security-Policy' not in headers:
            vulns.append({
                'type': 'Missing Security Header',
                'name': 'Content-Security-Policy',
                'url': url,
                'risk': 'Medium'
            })

        # 2. Strict-Transport-Security (Only valid on HTTPS and public domains per RFC 6797)
        if is_https and not is_localhost:
            if 'Strict-Transport-Security' not in headers:
                vulns.append({
                    'type': 'Missing Security Header',
                    'name': 'Strict-Transport-Security',
                    'url': url,
                    'risk': 'Medium'
                })

        # 3. X-Frame-Options
        if 'X-Frame-Options' not in headers and 'Content-Security-Policy' not in headers:
            vulns.append({
                'type': 'Missing Security Header',
                'name': 'X-Frame-Options',
                'url': url,
                'risk': 'Low'
            })

        # 4. X-Content-Type-Options
        if 'X-Content-Type-Options' not in headers:
            vulns.append({
                'type': 'Missing Security Header',
                'name': 'X-Content-Type-Options',
                'url': url,
                'risk': 'Low'
            })

        # 5. Server / Technology Version Disclosure (only if specific versions are leaked)
        for banner_header in ("Server", "X-Powered-By"):
            banner = headers.get(banner_header)
            if banner and VERSION_DISCLOSURE_REGEX.search(banner):
                vulns.append({
                    'type': 'Server Version Disclosure',
                    'name': f"{banner_header}: {banner}",
                    'url': url,
                    'risk': 'Low'
                })

        return vulns

