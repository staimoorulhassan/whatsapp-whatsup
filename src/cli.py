import asyncio
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import typer
from typing import Optional, List
from rich.console import Console
from rich.table import Table

from config.settings import CAPTURE_TIMEOUT
from src.packet_capture import get_available_interfaces, select_best_interface
from src.orchestrator import WhatsAppHunterOrchestrator

app = typer.Typer()
console = Console()


def _run_async(coro):
    """Run a single async coroutine, reusing a running loop when available."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    return loop.run_until_complete(coro)


def resolve_interface(interface: Optional[str]) -> str:
    if interface:
        return interface
    interfaces = get_available_interfaces()
    if not interfaces:
        console.print("[red]No network interfaces found[/red]")
        raise typer.Exit(1)
    chosen = select_best_interface(interfaces)
    console.print(f"[cyan]Auto-selected interface: {chosen}[/cyan]")
    return chosen


def map_link(res: dict) -> str:
    lat = res.get("latitude")
    lon = res.get("longitude")
    if lat is None or lon is None:
        return ""
    return f"https://www.google.com/maps?q={lat},{lon}"


def location_line(ip: str, res: dict) -> str:
    place = ", ".join(p for p in (res.get("city"), res.get("country")) if p)
    coords = ""
    if res.get("latitude") is not None and res.get("longitude") is not None:
        coords = f" ({res['latitude']}, {res['longitude']})"
    link = map_link(res)
    pin = f" {link}" if link else ""
    return f"{res.get('ip', ip)} - {place}{coords}{pin}"


def print_results(title: str, result: dict):
    if not result["success"]:
        console.print(f"[red]Error: {result['error']}[/red]")
        raise typer.Exit(1)

    table = Table(title=title)
    table.add_column("IP Address", style="red")
    table.add_column("Place", style="green")
    table.add_column("Coordinates", style="yellow")
    table.add_column("Map", style="cyan", overflow="fold")

    for ip, res in result["results"].items():
        if "error" not in res:
            coords = ""
            if res.get("latitude") is not None and res.get("longitude") is not None:
                coords = f"{res['latitude']}, {res['longitude']}"
            place = ", ".join(p for p in (res.get("city"), res.get("country")) if p) or "Unknown"
            table.add_row(res.get("ip", ip), place, coords or "n/a", map_link(res) or "n/a")

    console.print(table)
    console.print(f"\n[green]Found {result['ips_found']} IP(s)[/green]")


@app.command()
def hunt(
    phone_number: str = typer.Argument(..., help="Target phone number in international format (+CountryNumber)"),
    capture_time: int = typer.Option(CAPTURE_TIMEOUT, "--seconds", "-t", help="Capture duration in seconds"),
    interface: Optional[str] = typer.Option(None, "--interface", "-i", help="Network interface to use"),
):
    """Capture while you call this number from the WhatsApp Desktop app."""
    chosen = resolve_interface(interface)

    async def run():
        orchestrator = WhatsAppHunterOrchestrator(interface=chosen)
        print_results("IP Hunt Results", await orchestrator.run_hunt(phone_number, capture_time))

    _run_async(run())


@app.command()
def capture(
    capture_time: int = typer.Option(CAPTURE_TIMEOUT, "--seconds", "-t", help="Capture window in seconds"),
    interface: Optional[str] = typer.Option(None, "--interface", "-i", help="Network interface to use"),
):
    """Capture while you place a call from the WhatsApp Desktop app."""
    chosen = resolve_interface(interface)

    async def run():
        orchestrator = WhatsAppHunterOrchestrator(interface=chosen)
        print_results("Captured IP Results", await orchestrator.run_capture(capture_time))

    _run_async(run())


@app.command()
def bulk_hunt(
    phone_numbers: List[str] = typer.Argument(..., help="Multiple phone numbers"),
    capture_time: int = typer.Option(CAPTURE_TIMEOUT, "--seconds", "-t", help="Capture duration per target"),
    interface: Optional[str] = typer.Option(None, "--interface", "-i", help="Network interface to use"),
):
    """Hunt several numbers, one desktop-app call at a time."""
    chosen = resolve_interface(interface)

    async def run():
        orchestrator = WhatsAppHunterOrchestrator(interface=chosen)
        result = await orchestrator.run_bulk_hunt(phone_numbers, capture_time)
        if not result["success"]:
            console.print(f"[red]Error: {result['error']}[/red]")
            raise typer.Exit(1)
        for item in result["results"]:
            phone = item["phone"]
            res = item["result"]
            console.print(f"\n[cyan]{phone}:[/cyan]")
            if res["success"]:
                for ip, ip_res in res["results"].items():
                    if "error" not in ip_res:
                        console.print(f"  {location_line(ip, ip_res)}")
            else:
                console.print(f"  Error: {res['error']}")

    _run_async(run())


@app.command(name="continuous-mode")
def continuous_mode(
    phone_file: str = typer.Argument(..., help="File with phone numbers"),
    capture_time: int = typer.Option(CAPTURE_TIMEOUT, "--seconds", "-t", help="Capture duration"),
    interface: Optional[str] = typer.Option(None, "--interface", "-i", help="Network interface to use"),
):
    """Hunt every number in a file via the WhatsApp Desktop app."""
    chosen = resolve_interface(interface)

    async def run():
        orchestrator = WhatsAppHunterOrchestrator(interface=chosen)
        result = await orchestrator.run_continuous_mode(phone_file, capture_time)
        if result["success"]:
            console.print("[green]Continuous hunt completed[/green]")
        else:
            console.print(f"[red]Error: {result['error']}[/red]")
            raise typer.Exit(1)

    _run_async(run())


@app.command()
def interfaces():
    """List available network interfaces"""
    found = get_available_interfaces()
    table = Table(title="Available Network Interfaces")
    table.add_column("Interface", style="cyan")
    table.add_column("Description", style="green")
    for iface, desc in found.items():
        table.add_row(iface, desc)
    console.print(table)


if __name__ == "__main__":
    app()
