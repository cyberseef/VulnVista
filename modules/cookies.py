# modules/cookies.py
import re

HTTPONLY_REGEX = re.compile(r'(?i)\bhttponly\b')
SECURE_REGEX = re.compile(r'(?i)\bsecure\b')

def _extract_set_cookie_headers(response):
    headers = []
    # Prefer urllib3's getlist for repeated headers
    try:
        raw = getattr(response, 'raw', None)
        if raw and hasattr(raw, 'headers') and hasattr(raw.headers, 'getlist'):
            headers = raw.headers.getlist('Set-Cookie')
    except Exception:
        headers = []

    # Fallback: single header access (may collapse multiples)
    if not headers:
        sc = response.headers.get('Set-Cookie')
        if sc:
            # Best-effort split; Set-Cookie should not be folded by servers, but in case it is
            # we split on '\n' first, then try commas that are followed by a non-space token containing '='
            parts = [p.strip() for p in sc.split('\n') if p.strip()]
            if not parts:
                # heuristic split on comma that is followed by a token ending with '=' (cookie name)
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

def check_cookies(response, url, vulns):
    # 1) Secure flag via cookie jar (simple, reliable)
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

    # 2) HttpOnly flag via Set-Cookie header parsing
    set_cookie_headers = _extract_set_cookie_headers(response)
    for header in set_cookie_headers:
        try:
            # cookie name is before first '='
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
