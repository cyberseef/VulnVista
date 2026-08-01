import re
from core.plugin import BasePlugin

HTTPONLY_REGEX = re.compile(r'(?i)\bhttponly\b')
SECURE_REGEX = re.compile(r'(?i)\bsecure\b')

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
    @property
    def name(self) -> str:
        return "Insecure Cookies Scanner"

    def scan(self, url: str, response, soup=None) -> list:
        vulns = []
        cookiejar = getattr(response, 'cookies', [])
        for cookie in cookiejar:
            secure_flag = getattr(cookie, 'secure', False)
            if not secure_flag:
                vulns.append({
                    'type': 'Insecure Cookie - Missing Secure',
                    'name': getattr(cookie, 'name', 'cookie'),
                    'url': url,
                    'risk': 'Low'
                })

        set_cookie_headers = _extract_set_cookie_headers(response)
        for header in set_cookie_headers:
            try:
                name_part = header.split('=', 1)[0].strip()
            except Exception:
                name_part = 'cookie'
            has_httponly = HTTPONLY_REGEX.search(header) is not None
            if not has_httponly:
                vulns.append({
                    'type': 'Insecure Cookie - Missing HttpOnly',
                    'name': name_part or 'cookie',
                    'url': url,
                    'risk': 'Low'
                })
        return vulns
