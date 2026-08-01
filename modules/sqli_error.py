import re
from core.plugin import BasePlugin

class SQLiErrorPlugin(BasePlugin):
    @property
    def name(self) -> str:
        return "Passive SQLi Error Scanner"

    def scan(self, url: str, response, soup=None) -> list:
        vulns = []
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
        
        body_lower = response.text.lower() if isinstance(response.text, str) else ""
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
        return vulns
