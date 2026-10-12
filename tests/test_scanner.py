import unittest
from bs4 import BeautifulSoup
from unittest.mock import MagicMock

from core.scanner import Scanner
from modules.js_parser import JsParserPlugin, shannon_entropy
from modules.headers import HeadersPlugin
from modules.forms import FormsPlugin
from modules.sensitive_files import SensitiveFilesPlugin

class TestScanner(unittest.TestCase):
    def test_plugin_loading(self):
        scanner = Scanner("http://localhost")
        plugins = scanner.plugins
        self.assertGreater(len(plugins), 0, "No plugins were loaded")

        plugin_names = [p.name for p in plugins]
        self.assertIn("Sensitive Files Scanner", plugin_names)
        self.assertIn("Insecure Cookies Scanner", plugin_names)
        self.assertIn("Forms & Input Scanner", plugin_names)
        self.assertIn("Security Headers Scanner", plugin_names)
        self.assertIn("JavaScript Token Scanner", plugin_names)
        self.assertIn("Passive SQLi Error Scanner", plugin_names)

    def test_url_normalization(self):
        scanner = Scanner("http://example.com/test/")
        self.assertEqual(scanner.start_url, "http://example.com/test")

    def test_same_domain(self):
        scanner = Scanner("https://target.com")
        self.assertTrue(scanner._same_domain("https://target.com/page1"))
        self.assertTrue(scanner._same_domain("http://target.com"))
        self.assertFalse(scanner._same_domain("https://other.com"))

    def test_finding_deduplication(self):
        scanner = Scanner("https://target.com")
        finding = {'type': 'Missing Security Header', 'name': 'Content-Security-Policy', 'url': 'https://target.com'}
        self.assertFalse(scanner._is_duplicate(finding))
        # Second time should be marked duplicate
        self.assertTrue(scanner._is_duplicate(finding))

    def test_js_shannon_entropy_filter(self):
        # Low entropy common strings should be rejected (< 3.2)
        self.assertLess(shannon_entropy("undefined"), 3.2)
        self.assertLess(shannon_entropy("passwordpassword"), 3.2)
        # High entropy random token should pass (>= 3.2)
        high_entropy_token = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        self.assertGreaterEqual(shannon_entropy(high_entropy_token), 3.2)

    def test_headers_hsts_skipped_on_http_and_localhost(self):
        plugin = HeadersPlugin()
        mock_resp = MagicMock()
        mock_resp.headers = {}

        # HTTP localhost: HSTS should NOT be flagged as missing
        vulns_http = plugin.scan("http://localhost:3000", mock_resp)
        vuln_names = [v['name'] for v in vulns_http]
        self.assertNotIn("Strict-Transport-Security", vuln_names)

    def test_forms_no_false_positive_on_normal_input(self):
        plugin = FormsPlugin()
        html = '<form action="/search" method="get"><input type="text" name="query"><input type="submit"></form>'
        soup = BeautifulSoup(html, "html.parser")
        mock_resp = MagicMock()

        vulns = plugin.scan("https://example.com", mock_resp, soup)
        # Normal search input should NOT be tagged as 'Possible XSS or SQLi Input' Medium risk
        for v in vulns:
            self.assertNotEqual(v.get('type'), 'Possible XSS or SQLi Input')
            self.assertNotEqual(v.get('risk'), 'Medium')

    def test_sensitive_files_rejects_html_soft_404_for_env(self):
        plugin = SensitiveFilesPlugin()
        mock_resp = MagicMock()
        mock_resp.headers = {"Content-Type": "text/html"}
        mock_resp.text = "<!DOCTYPE html><html><body>404 Not Found Page</body></html>"

        is_genuine, risk = plugin._verify_content(".env", mock_resp)
        self.assertFalse(is_genuine)

if __name__ == "__main__":
    unittest.main()

