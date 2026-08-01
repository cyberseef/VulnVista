import pytest
from core.scanner import Scanner

def test_plugin_loading():
    scanner = Scanner("http://localhost")
    plugins = scanner.plugins
    assert len(plugins) > 0, "No plugins were loaded"
    
    plugin_names = [p.name for p in plugins]
    assert "Sensitive Files Scanner" in plugin_names
    assert "Insecure Cookies Scanner" in plugin_names
    assert "Forms & Input Scanner" in plugin_names
    assert "Security Headers Scanner" in plugin_names
    assert "JavaScript Token Scanner" in plugin_names
    assert "Passive SQLi Error Scanner" in plugin_names

def test_url_normalization():
    scanner = Scanner("http://example.com/test/")
    # the start_url should be normalized
    assert scanner.start_url == "http://example.com/test"

def test_same_domain():
    scanner = Scanner("https://target.com")
    assert scanner._same_domain("https://target.com/page1") == True
    assert scanner._same_domain("http://target.com") == True
    assert scanner._same_domain("https://other.com") == False
