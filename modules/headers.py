# modules/headers.py
def check_headers(headers, url, vulns):
    missing = []
    if 'Content-Security-Policy' not in headers:
        missing.append('Content-Security-Policy')
    if 'Strict-Transport-Security' not in headers:
        missing.append('Strict-Transport-Security')
    if 'X-Frame-Options' not in headers:
        missing.append('X-Frame-Options')

    for head in missing:
        vulns.append({
            'type': 'Missing Security Header',
            'name': head,
            'url': url,
            'risk': 'Medium'
        })
