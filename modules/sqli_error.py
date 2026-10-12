import re
from core.plugin import BasePlugin

ERROR_PATTERNS = [
    (r"you have an error in your sql syntax;", "MySQL"),
    (r"warning: mysql_", "MySQL (PHP Driver)"),
    (r"unclosed quotation mark after the character string", "MSSQL"),
    (r"quoted string not properly terminated", "Oracle"),
    (r"psql: FATAL:", "PostgreSQL"),
    (r"PostgreSQL.*ERROR", "PostgreSQL"),
    (r"SQLite/JDBCDriver", "SQLite"),
    (r"sqlite3\.OperationalError:", "SQLite (Python)"),
    (r"ODBC SQL Server Driver", "MSSQL (ODBC)"),
    (r"ORA-\d{5}", "Oracle"),
    (r"PG::\w*Error", "PostgreSQL (Ruby/PG)"),
]

class SQLiErrorPlugin(BasePlugin):
    @property
    def name(self) -> str:
        return "Passive SQLi Error Scanner"

    def scan(self, url: str, response, soup=None) -> list:
        vulns = []
        body_text = response.text or ""
        status_code = getattr(response, 'status_code', 200)

        # Check if matches are only inside code/pre/doc blocks
        for pattern, engine in ERROR_PATTERNS:
            try:
                if re.search(pattern, body_text, re.IGNORECASE):
                    if soup:
                        # Ensure pattern occurs in page body outside code/pre/style/script blocks
                        non_code_strings = [
                            s for s in soup.stripped_strings
                            if not (hasattr(s, 'parent') and s.parent and s.parent.name in ('code', 'pre', 'samp', 'script', 'style'))
                        ]
                        cleaned_text = " ".join(non_code_strings)
                        if not re.search(pattern, cleaned_text, re.IGNORECASE):
                            continue

                    # Unhandled DB exceptions often return HTTP 500
                    risk = 'High' if status_code >= 500 else 'Medium'
                    vulns.append({
                        'type': 'Possible SQL Injection Indicator',
                        'name': f"Database error signature detected: {engine}",
                        'url': url,
                        'risk': risk,
                        'status': status_code
                    })
                    break
            except re.error:
                continue


        return vulns

