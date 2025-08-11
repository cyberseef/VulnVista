# modules/forms.py
from bs4 import BeautifulSoup

def check_forms(url, html_text, vulns):
    soup = BeautifulSoup(html_text, "html.parser")
    forms = soup.find_all('form')
    for f in forms:
        inputs = f.find_all(['input','textarea','select'])
        for i in inputs:
            itype = i.get('type','').lower()
            name = i.get('name') or i.get('id') or '(no-name)'
            if itype in ('text','search','email') or i.name == 'textarea' or itype == '':
                vulns.append({
                    'type': 'Possible XSS or SQLi Input',
                    'name': name,
                    'url': url,
                    'risk': 'Medium'
                })
