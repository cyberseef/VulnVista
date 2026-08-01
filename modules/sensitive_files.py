import urllib.parse
from core.plugin import BasePlugin
import requests

class SensitiveFilesPlugin(BasePlugin):
    @property
    def name(self) -> str:
        return "Sensitive Files Scanner"

    def scan(self, url: str, response, soup=None) -> list:
        vulns = []
        parsed = urllib.parse.urlparse(url)
        
        # Only check sensitive files if this URL looks like a directory
        if not parsed.path.endswith('/') and parsed.path != '':
            return vulns
            
        common_files = [
            ".env", 
            "docker-compose.yml", 
            "phpinfo.php", 
            ".git/config",
            "config.php",
            "wp-config.php.bak",
            "robots.txt",
            "sitemap.xml",
            "admin/",
            "backup/",
            "uploads/"
        ]
        
        for file in common_files:
            target = urllib.parse.urljoin(url, file)
            try:
                r = requests.head(target, timeout=5, headers={"User-Agent": "VulnVistaScanner/2.0"}, allow_redirects=False)
                if r.status_code in [200, 301, 302, 403]:
                    # Determine risk
                    risk = 'High' if file in ['.env', '.git/config'] else 'Low'
                    
                    vulns.append({
                        'type': 'Sensitive File/Directory Discovered',
                        'name': file,
                        'url': target,
                        'risk': risk,
                        'status': r.status_code
                    })
            except Exception:
                pass
                
        return vulns
