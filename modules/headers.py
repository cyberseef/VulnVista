from core.plugin import BasePlugin

class HeadersPlugin(BasePlugin):
    @property
    def name(self) -> str:
        return "Security Headers Scanner"

    def scan(self, url: str, response, soup=None) -> list:
        vulns = []
        headers = response.headers
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
            
        server = headers.get("Server") or headers.get("X-Powered-By")
        if server:
            vulns.append({'type': 'Server Stack Disclosure', 'name': server, 'url': url, 'risk': 'Low'})
            
        return vulns
