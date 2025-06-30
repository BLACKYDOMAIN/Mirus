import sys
import asyncio
from pathlib import Path
import vt
from rich.console import Console
from rich.progress import Progress

console = Console()

# Hardcoded API key and file path to scan
API_KEY = open("apikey.txt",'r').read()
URLS_FILE_PATH = Path("./urls.txt")  # File containing URLs to scan
WAIT_FOR_COMPLETION = True  # Set to False if you don't want to wait for scan completion

async def scan_urls():
    """Scan URLs from a file using VirusTotal."""
    async with vt.Client(API_KEY) as client:
        try:
            if not URLS_FILE_PATH.exists():
                console.print(f"[red]Error: File {URLS_FILE_PATH} not found[/red]")
                sys.exit(1)

            with URLS_FILE_PATH.open("r") as file:
                urls = [line.strip() for line in file if line.strip()]

            with Progress() as progress:
                task = progress.add_task("Scanning URLs...", total=len(urls))

                for url in urls:
                    analysis = await client.scan_url_async(url, wait_for_completion=WAIT_FOR_COMPLETION)
                    console.print(f"[green]URL {url} enqueued for scanning.[/green]")
                    progress.update(task, advance=1)

                    # Print scan results
                    console.print(f"[blue]Scan Results for {url}:[/blue]")
                    console.print(f"Status: {analysis.status}")
                    if hasattr(analysis, "stats"):
                        console.print("Detection Stats:")
                        for k, v in analysis.stats.items():
                            console.print(f"  {k}: {v}")
        except vt.error.APIError as e:
            console.print(f"[red]API Error: {e}[/red]")
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")

if __name__ == "__main__":
    asyncio.run(scan_urls())
