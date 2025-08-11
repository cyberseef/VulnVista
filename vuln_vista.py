#!/usr/bin/env python3
"""
VulnVista - Minimal non-intrusive web app scanner (Module 7 brief)
Usage example:
  python3 vuln_vista.py -u http://127.0.0.1/DVWA/ --max-pages 200 --pdf-report
"""
import argparse
import urllib.parse
import requests
from collections import deque
import time
import os

from modules import headers, cookies, forms, js_parser, report
import re

# simple configuration
COMMON_DIRS = ["uploads/", "backup/", "admin/", "config/", ".git/", "robots.txt", "sitemap.xml"]
USER_AGENT = "VulnVistaScanner/1.0 (+https://example.local)"

def is_valid_url(url):
    try:
        p = urllib.parse.urlparse(url)
        return p.scheme in ("http", "https") and p.netloc != ""
    except:
        return False

def normalize(url):
    # remove fragments
    u = urllib.parse.urldefrag(url)[0]
    return u.rstrip('/')

def same_domain(base, url):
    return urllib.parse.urlparse(base).netloc == urllib.parse.urlparse(url).netloc

def head_request(url, timeout=6):
    try:
        return requests.head(url, headers={"User-Agent": USER_AGENT}, timeout=timeout, allow_redirects=True)
    except:
        return None

def get_request(url, cookies_in=None, timeout=8):
    try:
        return requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=timeout, cookies=cookies_in, allow_redirects=True)
    except:
        return None

def detect_open_dirs(base, sess):
    findings = []
    parsed = urllib.parse.urlparse(base)
    base_root = f"{parsed.scheme}://{parsed.netloc}/"
    for d in COMMON_DIRS:
        candidate = urllib.parse.urljoin(base_root, d)
        r = head_request(candidate)
        if r and r.status_code in (200, 403, 301, 302):
            findings.append({'type': 'Open Directory / Public File', 'name': d, 'url': candidate, 'risk': 'Medium', 'status': r.status_code})
    return findings

def crawl_and_scan(start_url, max_pages=100, take_screenshots=False):
    start_url = normalize(start_url)
    domain = urllib.parse.urlparse(start_url).netloc

    q = deque([start_url])
    visited = set()
    found_pages = []
    vulns = []

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    while q and len(found_pages) < max_pages:
        url = q.popleft()
        url = normalize(url)
        if url in visited:
            continue
        visited.add(url)

        resp = get_request(url, cookies_in=None)
        if not resp:
            continue

        if resp.status_code >= 400:
            continue

        found_pages.append(url)

        # basic checks per page
        headers.check_headers(resp.headers, url, vulns)
        # pass full response to cookies to allow HttpOnly via Set-Cookie
        cookies.check_cookies(resp, url, vulns)
        forms.check_forms(url, resp.text, vulns)
        js_parser.check_js_tokens(url, resp.text, vulns)

        # Passive SQL error signature detection
        error_patterns = [
            r"SQL syntax;",
            r"warning: mysql",
            r"unclosed quotation mark after the character string",
            r"quoted string not properly terminated",
            r"psql: FATAL:",
            r"PostgreSQL.*ERROR",
            r"SQLite/JDBCDriver",
            r"ODBC SQL Server Driver",
            r"Oracle error",
            r"ORA-\d{5}",
            r"PG::\w+Error",
        ]
        body_lower = resp.text.lower() if isinstance(resp.text, str) else ""
        for pat in error_patterns:
            try:
                if re.search(pat, body_lower, re.IGNORECASE):
                    vulns.append({
                        'type': 'Possible SQL Injection Indicator',
                        'name': f"Error signature: {pat}",
                        'url': url,
                        'risk': 'Medium'
                    })
                    break
            except re.error:
                continue

        # server tech detection
        server = resp.headers.get("Server") or resp.headers.get("X-Powered-By")
        if server:
            vulns.append({'type': 'Server Stack Disclosure', 'name': server, 'url': url, 'risk': 'Low'})

        # discover links (simple)
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(resp.text, "html.parser")
        for a in soup.find_all("a", href=True):
            raw = a['href']
            full = urllib.parse.urljoin(url, raw)
            full = normalize(full)
            if same_domain(start_url, full) and full not in visited:
                q.append(full)

        # enumerate GET parameters on the discovered page URL itself
        parsed_url = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed_url.query)
        for param_name in params.keys():
            vulns.append({
                'type': 'URL Query Parameter Detected',
                'name': param_name,
                'url': url,
                'risk': 'Info'
            })

        # optional: check common directories once from base
        if len(found_pages) == 1:
            dir_findings = detect_open_dirs(start_url, session)
            for d in dir_findings:
                vulns.append(d)

    return found_pages, vulns

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", required=True, help="Target URL (include http/https)")
    parser.add_argument("--max-pages", type=int, default=200, help="Max pages to crawl")
    parser.add_argument("--pdf-report", action="store_true", help="Also generate PDF (requires wkhtmltopdf installed)")
    parser.add_argument("--take-screenshots", action="store_true", help="Take screenshots using wkhtmltoimage if available")
    args = parser.parse_args()

    if not is_valid_url(args.url):
        print("[!] Invalid URL. Include http:// or https://")
        return

    print(f"[*] Starting scan of {args.url}")
    start = time.strftime("%Y%m%d_%H%M%S")
    pages, vulns = crawl_and_scan(args.url, max_pages=args.max_pages, take_screenshots=args.take_screenshots)
    out_paths = report.generate(args.url, pages, vulns, pdf=args.pdf_report, timestamp=start, take_screenshots=args.take_screenshots)
    print("[*] Scan finished.")
    print(f"[+] Outputs: {out_paths}")

if __name__ == "__main__":
    main()
