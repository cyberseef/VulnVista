#!/usr/bin/env python3
"""
VulnVista - Professional Open-Source Web Vulnerability Scanner
"""
import argparse
import time
import sys

# Force UTF-8 for Windows console to fix rich UnicodeEncodeError
if sys.platform == "win32" and hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich import print as rprint

from core.scanner import Scanner
from modules import report

console = Console()

def banner():
    art = r"""[bold cyan]
 __      __   _     __      __ _       _        
 \ \    / /  | |    \ \    / /(_)     | |       
  \ \  / /_ _| |____ \ \  / /  _ ___  | |_ __ _ 
   \ \/ / _` | |  _ \ \ \/ /  | / __| | __/ _` |
    \  / (_| | | | | | \  /   | \__ \ | || (_| |
     \/ \__,_|_|_| |_|  \/    |_|___/  \__\__,_|
    [/bold cyan]
    [white]Lightweight, modular, non-intrusive web vulnerability scanner.[/white]
    """
    console.print(art)

def main():
    parser = argparse.ArgumentParser(description="VulnVista - Open-Source Web Vulnerability Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target URL (include http/https)")
    parser.add_argument("--max-pages", type=int, default=200, help="Max pages to crawl")
    parser.add_argument("--threads", type=int, default=5, help="Number of concurrent threads")
    parser.add_argument("--delay", type=float, default=0, help="Delay between requests in seconds")
    parser.add_argument("--pdf-report", action="store_true", help="Also generate PDF (requires wkhtmltopdf installed)")
    parser.add_argument("--take-screenshots", action="store_true", help="Take screenshots using wkhtmltoimage if available")
    args = parser.parse_args()

    banner()

    if not (args.url.startswith("http://") or args.url.startswith("https://")):
        console.print("[bold red][!] Invalid URL. Must include http:// or https://[/bold red]")
        sys.exit(1)

    console.print(Panel.fit(f"[bold green]Target:[/bold green] {args.url}\n[bold green]Threads:[/bold green] {args.threads}\n[bold green]Max Pages:[/bold green] {args.max_pages}\n[bold green]Delay:[/bold green] {args.delay}s", title="Scan Configuration"))

    scanner = Scanner(args.url, max_pages=args.max_pages, threads=args.threads, delay=args.delay)
    
    console.print(f"[*] Loaded [bold yellow]{len(scanner.plugins)}[/bold yellow] plugins...")
    for p in scanner.plugins:
        console.print(f"  - {p.name}")

    console.print("\n[*] Starting scan...")
    start_time_str = time.strftime("%Y%m%d_%H%M%S")
    start_time = time.time()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task_id = progress.add_task("[cyan]Crawling & Scanning...", total=args.max_pages)
        
        def update_progress(url):
            progress.update(task_id, advance=1, description=f"[cyan]Scanning: [white]{url[:50]}...")
            
        scanner.run(progress_callback=update_progress)

    end_time = time.time()
    
    console.print("\n[bold green][+] Scan complete![/bold green]")
    console.print(f"Pages Crawled: {len(scanner.found_pages)}")
    console.print(f"Time Taken: {end_time - start_time:.2f} seconds")

    # Present Findings
    if scanner.vulns:
        table = Table(title="Vulnerabilities Found", show_header=True, header_style="bold magenta")
        table.add_column("Risk", justify="center")
        table.add_column("Type")
        table.add_column("Name/Detail")
        table.add_column("URL", overflow="fold")

        for v in scanner.vulns:
            risk = v.get('risk', 'Info')
            color = "white"
            if risk == "High": color = "red"
            elif risk == "Medium": color = "yellow"
            elif risk == "Low": color = "cyan"
            elif risk == "Info": color = "blue"
            
            table.add_row(f"[{color}]{risk}[/{color}]", v.get('type'), v.get('name'), v.get('url'))
            
        console.print(table)
    else:
        console.print("[bold yellow][!] No non-intrusive vulnerabilities detected.[/bold yellow]")

    console.print("\n[*] Generating reports...")
    out_paths = report.generate(args.url, scanner.found_pages, scanner.vulns, 
                                pdf=args.pdf_report, json_out=True, 
                                timestamp=start_time_str, take_screenshots=args.take_screenshots)
    
    console.print("[bold green]Reports Saved:[/bold green]")
    for k, v in out_paths.items():
        if v:
            if isinstance(v, list):
                console.print(f"  - {k}: {len(v)} files saved.")
            else:
                console.print(f"  - {k}: {v}")

if __name__ == "__main__":
    main()
