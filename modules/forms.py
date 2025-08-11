# modules/forms.py
from bs4 import BeautifulSoup

def check_forms(url, html_text, vulns):
    soup = BeautifulSoup(html_text, "html.parser")
    forms = soup.find_all('form')
    for form in forms:
        method = (form.get('method') or 'GET').upper()
        action = form.get('action') or '(current page)'

        inputs = form.find_all(['input', 'textarea', 'select'])
        for field in inputs:
            input_type = (field.get('type') or '').lower()
            name = field.get('name') or field.get('id') or '(no-name)'

            # Flag hidden inputs explicitly
            if input_type == 'hidden':
                vulns.append({
                    'type': 'Hidden Field Discovered',
                    'name': name,
                    'url': url,
                    'risk': 'Info'
                })

            # Enumerate parameters present in forms (possible unsanitized params)
            vulns.append({
                'type': 'Input Parameter Detected',
                'name': f"{name} ({method})",
                'url': url,
                'risk': 'Info'
            })

            # Basic potential XSS/SQLi-susceptible inputs (text-like)
            if input_type in ('text', 'search', 'email', 'url', 'tel') or field.name == 'textarea' or input_type == '':
                vulns.append({
                    'type': 'Possible XSS or SQLi Input',
                    'name': f"{name} ({method})",
                    'url': url,
                    'risk': 'Medium'
                })
