import urllib.parse
import re
import secrets
import requests
from core.plugin import BasePlugin

class SensitiveFilesPlugin(BasePlugin):
    def __init__(self):
        self._scanned_origins = set()

    @property
    def name(self) -> str:
        return "Sensitive Files Scanner"

    def _get_canary_profile(self, origin: str) -> dict:
        """
        Probe a random, non-existent path to detect wildcard/soft-404 behavior,
        common in SPAs (Angular, React, Vue) and custom error routers.
        """
        canary_path = f"/.vulnvista_canary_{secrets.token_hex(6)}"
        target = urllib.parse.urljoin(origin, canary_path)
        try:
            r = requests.get(
                target,
                timeout=5,
                headers={"User-Agent": "VulnVistaScanner/2.0"},
                allow_redirects=False
            )
            return {
                "status_code": r.status_code,
                "content_length": len(r.content),
                "is_wildcard_200": (r.status_code == 200),
                "is_wildcard_redirect": (r.status_code in (301, 302, 307, 308)),
                "redirect_location": r.headers.get("Location", "")
            }
        except Exception:
            return {"status_code": 404, "content_length": 0, "is_wildcard_200": False, "is_wildcard_redirect": False}

    def _verify_content(self, file_path: str, response: requests.Response) -> tuple[bool, str]:
        """
        Verify that the response body actually matches the expected content of
        the requested sensitive file, rather than a generic HTML 404/SPA shell.
        Returns (is_genuine, risk_level).
        """
        content_type = response.headers.get("Content-Type", "").lower()
        body = response.text or ""

        # HTML returned for non-HTML files is almost always a soft-404 / SPA index page
        is_html = "text/html" in content_type or "<!doctype html" in body.lower() or "<html" in body.lower()

        if file_path == ".env":
            if is_html:
                return False, ""
            # Must look like environment key-value pairs
            if re.search(r'(?m)^[A-Z0-9_]{2,}\s*=\s*\S+', body):
                return True, "High"
            return False, ""

        if file_path == ".git/config":
            if is_html:
                return False, ""
            if "[core]" in body or "repositoryformatversion" in body:
                return True, "High"
            return False, ""

        if file_path == "docker-compose.yml":
            if is_html:
                return False, ""
            if re.search(r'(?m)^(version:|services:|networks:)', body):
                return True, "High"
            return False, ""

        if file_path == "phpinfo.php":
            if "phpinfo()" in body or "PHP Version" in body or "<title>phpinfo()</title>" in body:
                return True, "Medium"
            return False, ""

        if file_path in ("config.php", "wp-config.php.bak"):
            if is_html:
                return False, ""
            if any(term in body for term in ("DB_PASSWORD", "DB_NAME", "DB_USER", "<?php")):
                return True, "High"
            return False, ""

        if file_path.endswith("/"):
            # Directory exposure
            if "Index of /" in body or "<title>Index of" in body:
                return True, "Medium"
            # If 403 Forbidden on directory, it is restricted (informational)
            if response.status_code == 403:
                return True, "Info"
            return False, ""

        return False, ""

    def scan(self, url: str, response, soup=None) -> list:
        vulns = []
        parsed = urllib.parse.urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        # Sensitive files should be scanned only once per origin/host
        if origin in self._scanned_origins:
            return vulns
        self._scanned_origins.add(origin)

        # Baseline canary check to eliminate soft-404s
        canary = self._get_canary_profile(origin)

        common_files = [
            ".env",
            "docker-compose.yml",
            "phpinfo.php",
            ".git/config",
            "config.php",
            "wp-config.php.bak",
            "admin/",
            "backup/",
            "uploads/"
        ]

        for file_path in common_files:
            target = urllib.parse.urljoin(origin + "/", file_path)
            try:
                r = requests.get(
                    target,
                    timeout=5,
                    headers={"User-Agent": "VulnVistaScanner/2.0"},
                    allow_redirects=False
                )

                # Skip if wildcard 200 matches canary response closely
                if canary["is_wildcard_200"] and r.status_code == 200:
                    diff = abs(len(r.content) - canary["content_length"])
                    # If response length is within 10% or 50 bytes of canary, it's a SPA / soft-404
                    if diff < max(50, canary["content_length"] * 0.1):
                        continue

                # Skip if wildcard redirects to generic destination
                if r.status_code in (301, 302, 307, 308):
                    loc = r.headers.get("Location", "")
                    if canary["is_wildcard_redirect"] and loc == canary["redirect_location"]:
                        continue
                    # Ignore redirects to homepage or login
                    parsed_loc = urllib.parse.urlparse(loc)
                    if parsed_loc.path in ("", "/", "/login", "/index.html"):
                        continue

                # Content and signature verification
                if r.status_code == 200:
                    is_genuine, risk = self._verify_content(file_path, r)
                    if is_genuine:
                        vulns.append({
                            'type': 'Sensitive File/Directory Discovered',
                            'name': file_path,
                            'url': target,
                            'risk': risk,
                            'status': r.status_code
                        })
                elif r.status_code == 403 and file_path.endswith("/"):
                    # Restricted directory, log only as Info
                    vulns.append({
                        'type': 'Restricted Directory Detected',
                        'name': file_path,
                        'url': target,
                        'risk': 'Info',
                        'status': 403
                    })
            except Exception:
                pass

        return vulns

