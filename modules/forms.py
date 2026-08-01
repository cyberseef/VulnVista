from bs4 import BeautifulSoup
from core.plugin import BasePlugin

class FormsPlugin(BasePlugin):
    @property
    def name(self) -> str:
        return "Forms & Input Scanner"

    def scan(self, url: str, response, soup=None) -> list:
        vulns = []
        if not soup:
            return vulns
            
        forms = soup.find_all('form')
        for form in forms:
            method = (form.get('method') or 'GET').upper()
            
            inputs = form.find_all(['input', 'textarea', 'select'])
            for field in inputs:
                input_type = (field.get('type') or '').lower()
                name = field.get('name') or field.get('id') or '(no-name)'

                if input_type == 'hidden':
                    vulns.append({
                        'type': 'Hidden Field Discovered',
                        'name': name,
                        'url': url,
                        'risk': 'Info'
                    })

                vulns.append({
                    'type': 'Input Parameter Detected',
                    'name': f"{name} ({method})",
                    'url': url,
                    'risk': 'Info'
                })

                if input_type in ('text', 'search', 'email', 'url', 'tel') or field.name == 'textarea' or input_type == '':
                    vulns.append({
                        'type': 'Possible XSS or SQLi Input',
                        'name': f"{name} ({method})",
                        'url': url,
                        'risk': 'Medium'
                    })
        return vulns
