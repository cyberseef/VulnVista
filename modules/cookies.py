import re
import urllib.parse
from core.plugin import BasePlugin

HTTPONLY_REGEX = re.compile(r'(?i)\bhttponly\b')
SECURE_REGEX = re.compile(r'(?i)\bsecure\b')
SAMESITE_REGEX = re.compile(r'(?i)\bsamesite=(?:lax|strict|none)\b')

SESSION_COOKIE_PATTERNS = {
    'session', 'sess', 'phpsessid', 'jsessionid', 'token', 'auth',
    'jwt', 'sid', 'connect.sid', 'asp.net_sessionid', 'remember_me',
    'authtoken', 'csrftoken', 'xsrf-token'
}

def _extract_set_cookie_headers(response):
    headers = []
    try:
        raw = getattr(response, 'raw', None)
        if raw and hasattr(raw, 'headers') and hasattr(raw.headers, 'getlist'):
            headers = raw.headers.getlist('Set-Cookie')
    except Exception:
        headers = []

    if not headers:
        sc = response.headers.get('Set-Cookie')
        if sc:
            parts = [p.strip() for p in sc.split('\n') if p.strip()]
            if not parts:
                tmp = []
                buf = ''
                for seg in sc.split(','):
                    if '=' in seg and (';' in seg.split('=')[-1] or buf == ''):
                        if buf:
                            tmp.append(buf.strip())
                        buf = seg
                    else:
                        buf += ',' + seg
                if buf:
                    tmp.append(buf.strip())
                parts = tmp
            headers = parts
    return headers

class CookiesPlugin(BasePlugin):
    def __init__(self):
        self._reported_cookies = set()

    @property
    def name(self) -> str:
        return "Insecure Cookies Scanner"

    def scan(self, url: str, response, soup=None) -> list:
        vulns = []
        parsed = urllib.parse.urlparse(url)
        is_https = parsed.scheme == "https"
        is_localhost = parsed.hostname in ("localhost", "127.0.0.1", "::1")

        set_cookie_headers = _extract_set_cookie_headers(response)
        for header in set_cookie_headers:
            try:
                name_part = header.split('=', 1)[0].strip()
            except Exception:
                name_part = 'cookie'

            lower_name = name_part.lower()
            is_session_cookie = any(p in lower_name for p in SESSION_COOKIE_PATTERNS)

            # Deduplicate per (cookie_name, domain)
            cookie_key = (name_part, parsed.netloc)
            if cookie_key in self._reported_cookies:
                continue
            self._reported_cookies.add(cookie_key)

            has_httponly = HTTPONLY_REGEX.search(header) is not None
            has_secure = SECURE_REGEX.search(header) is not None

            # 1. Missing HttpOnly
            if not has_httponly:
                vulns.append({
                    'type': 'Insecure Cookie - Missing HttpOnly',
                    'name': name_part,
                    'url': url,
                    'risk': 'Medium' if is_session_cookie else 'Low'
                })

            # 2. Missing Secure flag (Only valid to demand on HTTPS and non-localhost)
            if is_https and not is_localhost and not has_secure:
                vulns.append({
                    'type': 'Insecure Cookie - Missing Secure',
                    'name': name_part,
                    'url': url,
                    'risk': 'Medium' if is_session_cookie else 'Low'
                })

            # 3. Missing SameSite flag
            if not SAMESITE_REGEX.search(header) and is_session_cookie:
                vulns.append({
                    'type': 'Insecure Cookie - Missing SameSite',
                    'name': name_part,
                    'url': url,
                    'risk': 'Low'
                })

        return vulns

