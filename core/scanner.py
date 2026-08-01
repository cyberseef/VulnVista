import concurrent.futures
import requests
import urllib.parse
from bs4 import BeautifulSoup
import importlib
import pkgutil
import sys
import os

from core.plugin import BasePlugin
from typing import List, Tuple

USER_AGENT = "VulnVistaScanner/2.0 (+https://github.com/cyberseef/VulnVista)"

class Scanner:
    def __init__(self, start_url: str, max_pages: int = 100, threads: int = 5, delay: float = 0):
        self.start_url = self._normalize(start_url)
        self.domain = urllib.parse.urlparse(self.start_url).netloc
        self.max_pages = max_pages
        self.threads = threads
        self.delay = delay
        self.visited = set()
        self.found_pages = []
        self.vulns = []
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})
        self.plugins = self._load_plugins()

    def _normalize(self, url: str) -> str:
        u = urllib.parse.urldefrag(url)[0]
        return u.rstrip('/')

    def _same_domain(self, url: str) -> bool:
        return urllib.parse.urlparse(url).netloc == self.domain
        
    def _load_plugins(self) -> List[BasePlugin]:
        plugins = []
        import modules
        modules_path = os.path.dirname(modules.__file__)
        if not modules_path:
            modules_path = os.path.abspath('modules')
            
        for _, module_name, _ in pkgutil.iter_modules([modules_path]):
            module = importlib.import_module(f"modules.{module_name}")
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if isinstance(attr, type) and issubclass(attr, BasePlugin) and attr is not BasePlugin:
                    plugins.append(attr())
        return plugins

    def _fetch(self, url: str) -> Tuple[str, requests.Response, BeautifulSoup]:
        try:
            resp = self.session.get(url, timeout=8, allow_redirects=True)
            if resp.status_code < 400:
                # Basic check to skip non-HTML content for soup parsing
                content_type = resp.headers.get("Content-Type", "")
                if "text/html" in content_type:
                    soup = BeautifulSoup(resp.text, "html.parser")
                else:
                    soup = None
                return url, resp, soup
        except Exception:
            pass
        return url, None, None

    def _extract_links(self, url: str, soup: BeautifulSoup) -> List[str]:
        links = []
        if soup:
            for a in soup.find_all("a", href=True):
                raw = a['href']
                full = self._normalize(urllib.parse.urljoin(url, raw))
                if self._same_domain(full) and full not in self.visited:
                    links.append(full)
        return links

    def _scan_page(self, url: str, resp: requests.Response, soup: BeautifulSoup):
        page_vulns = []
        for plugin in self.plugins:
            try:
                findings = plugin.scan(url, resp, soup)
                if findings:
                    page_vulns.extend(findings)
            except Exception:
                pass
        return page_vulns

    def run(self, progress_callback=None):
        queue = [self.start_url]
        self.visited.add(self.start_url)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            while queue and len(self.found_pages) < self.max_pages:
                batch = queue[:self.threads]
                queue = queue[self.threads:]
                
                futures = {executor.submit(self._fetch, u): u for u in batch}
                for future in concurrent.futures.as_completed(futures):
                    url, resp, soup = future.result()
                    if progress_callback:
                        progress_callback(url)
                    
                    if resp:
                        self.found_pages.append(url)
                        
                        # Find new links
                        new_links = self._extract_links(url, soup)
                        for link in new_links:
                            if link not in self.visited:
                                self.visited.add(link)
                                queue.append(link)
                        
                        # Run plugins
                        self.vulns.extend(self._scan_page(url, resp, soup))
                        
                if self.delay > 0:
                    import time
                    time.sleep(self.delay)
