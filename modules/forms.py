import urllib.parse
from core.plugin import BasePlugin

CSRF_TOKEN_NAMES = {
    'csrf', 'xsrf', 'token', 'csrf_token', 'xsrf_token', '_csrf',
    '_token', 'authenticity_token', 'anticrfs', '__requestverificationtoken'
}

class FormsPlugin(BasePlugin):
    @property
    def name(self) -> str:
        return "Forms & Input Scanner"

    def scan(self, url: str, response, soup=None) -> list:
        vulns = []
        if not soup:
            return vulns

        parsed_page = urllib.parse.urlparse(url)
        is_https = parsed_page.scheme == "https"
        is_localhost = parsed_page.hostname in ("localhost", "127.0.0.1", "::1")

        forms = soup.find_all('form')
        for form_idx, form in enumerate(forms):
            method = (form.get('method') or 'GET').upper()
            action = form.get('action') or ''
            full_action = urllib.parse.urljoin(url, action)
            parsed_action = urllib.parse.urlparse(full_action)

            inputs = form.find_all(['input', 'textarea', 'select'])
            has_password = False
            has_csrf = False
            input_names = []

            for field in inputs:
                input_type = (field.get('type') or '').lower()
                name = field.get('name') or field.get('id') or ''

                if input_type == 'password':
                    has_password = True

                # Check for anti-CSRF token in field name or id
                lower_name = name.lower()
                if any(token_pattern in lower_name for token_pattern in CSRF_TOKEN_NAMES):
                    has_csrf = True

                if name:
                    input_names.append(name)

            # 1. Insecure Password Transmission over plain HTTP
            if has_password and not is_https and not is_localhost:
                vulns.append({
                    'type': 'Insecure Password Transmission',
                    'name': f"Password form submitted over unencrypted HTTP (Form #{form_idx+1})",
                    'url': url,
                    'risk': 'High'
                })

            # 2. External Form Action
            if parsed_action.netloc and parsed_action.netloc != parsed_page.netloc:
                vulns.append({
                    'type': 'External Form Action',
                    'name': f"Form action targets external origin ({parsed_action.netloc})",
                    'url': url,
                    'risk': 'Low'
                })

            # 3. State-changing POST form without Anti-CSRF token
            if method == 'POST' and not has_csrf and len(inputs) > 0:
                vulns.append({
                    'type': 'Missing Anti-CSRF Protection',
                    'name': f"POST Form #{form_idx+1} lacks visible Anti-CSRF token",
                    'url': url,
                    'risk': 'Low'
                })

            # 4. Attack Surface Enumeration (Informational)
            if input_names:
                summary_inputs = ", ".join(input_names[:5]) + ("..." if len(input_names) > 5 else "")
                vulns.append({
                    'type': 'Attack Surface: Form Inputs',
                    'name': f"Form #{form_idx+1} [{method}] ({summary_inputs})",
                    'url': url,
                    'risk': 'Info'
                })

        return vulns

