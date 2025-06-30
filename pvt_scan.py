import sys
import asyncio
from pathlib import Path
import vt
from rich.console import Console
from rich.progress import Progress

console = Console()

# Hardcoded API key and file path to scan
API_KEY = open("apikey.txt","r").read()
FILE_PATH = Path("./logo.jpg")
WAIT_FOR_COMPLETION = True  # Set to False if you don't want to wait for scan completion

async def scan_file_private():
    """Scan a file privately on VirusTotal."""
    async with vt.Client(API_KEY) as client:
        try:
            with Progress() as progress:
                task = progress.add_task("Scanning file...", total=None if WAIT_FOR_COMPLETION else 1)

                with FILE_PATH.open("rb") as file:
                    analysis = await client.scan_file_private_async(
                        file, wait_for_completion=WAIT_FOR_COMPLETION
                    )

                progress.update(task, advance=1)

                console.print("\n[green]Scan submitted successfully[/green]")
                console.print(f"Analysis ID: {analysis.id}")

                if WAIT_FOR_COMPLETION:
                    console.print(f"\nScan Status: {analysis.status}")
                    if hasattr(analysis, "stats"):
                        console.print("Detection Stats:")
                        for k, v in analysis.stats.items():
                            console.print(f"  {k}: {v}")
        except vt.error.APIError as e:
            console.print(f"[red]API Error: {e}[/red]")
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")

if __name__ == "__main__":
    if not FILE_PATH.exists():
        console.print(f"[red]Error: File {FILE_PATH} not found[/red]")
        sys.exit(1)
    if not FILE_PATH.is_file():
        console.print(f"[red]Error: {FILE_PATH} is not a file[/red]")
        sys.exit(1)
    asyncio.run(scan_file_private())
