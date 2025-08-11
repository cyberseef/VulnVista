# modules/cookies.py
def check_cookies(cookiejar, url, vulns):
    # cookiejar is requests.cookies.RequestsCookieJar
    for c in cookiejar:
        secure = getattr(c, 'secure', False)
        # requests' Cookie object may not expose HttpOnly easily; we conservatively flag if secure False
        if not secure:
            vulns.append({
                'type': 'Insecure Cookie',
                'name': getattr(c, 'name', 'cookie'),
                'url': url,
                'risk': 'Low'
            })
