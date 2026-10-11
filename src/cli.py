import asyncio
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import typer
from typing import Optional, List
from rich.console import Console
from rich.table import Table

from src.packet_capture import get_available_interfaces
from src.orchestrator import WhatsAppHunterOrchestrator

app = typer.Typer()
console = Console()

@app.command()
def hunt(
    phone_number: str = typer.Argument(..., help="Target phone number in international format (+CountryNumber)"),
    capture_time: int = typer.Option(5, "--seconds", "-t", help="Capture duration in seconds"),
    interface: Optional[str] = typer.Option(None, "--interface", "-i", help="Network interface to use"),
    headless: bool = typer.Option(True, "--head/--no-head", help="Run browser in headless mode")
):
    """Main IP hunting command"""

    # Get available interfaces if none specified
    if not interface:
        interfaces = get_available_interfaces()
        if not interfaces:
            console.print("[red]No network interfaces found[/red]")
            raise typer.Exit(1)

        # Prefer WiFi interface for capturing WhatsApp traffic
        # Look for interface with WiFi/WLAN in description or 192.168.x.x private IP
        wifi_iface = next(
            (iface for iface, desc in interfaces.items() 
             if ("WiFi" in desc or "WLAN" in desc or "192.168." in desc) and "0.0.0.0" not in desc), None
        )
        if wifi_iface:
            interface = wifi_iface
        else:
            # Fallback: use first non-loopback interface with a real IP (not 0.0.0.0)
            for iface, desc in interfaces.items():
                if not iface.startswith("lo") and "0.0.0.0" not in desc:
                    interface = iface
                    break
            if not interface:
                interface = list(interfaces.keys())[0]

        console.print(f"[cyan]Auto-selected interface: {interface}[/cyan]")

    async def run_hunt():
        orchestrator = WhatsAppHunterOrchestrator(interface=interface, headless=headless)
        result = await orchestrator.run_hunt(phone_number, capture_time)

        if result["success"]:
            # Display results - geo_results is a dict {ip: {country, city, ...}}
            table = Table(title="IP Hunt Results")
            table.add_column("IP Address", style="red")
            table.add_column("Country", style="green")
            table.add_column("Region", style="blue")
            table.add_column("City", style="yellow")

            for ip, res in result["results"].items():
                if "error" not in res:
                    table.add_row(
                        res.get("ip", ip),
                        res.get("country", "Unknown"),
                        res.get("country_code", "Unknown"),
                        res.get("city", "Unknown")
                    )

            console.print(table)
            console.print(f"\n[green]Found {result['ips_found']} IP(s)[/green]")
        else:
            console.print(f"[red]Error: {result['error']}[/red]")
            raise typer.Exit(1)

    asyncio.run(run_hunt())

@app.command()
def bulk_hunt(
    phone_numbers: List[str] = typer.Argument(..., help="Multiple phone numbers"),
    capture_time: int = typer.Option(3, "--seconds", "-t", help="Capture duration per target"),
    interface: Optional[str] = typer.Option(None, "--interface", "-i", help="Network interface to use")
):
    """Bulk hunt multiple targets simultaneously"""

    if not interface:
        interfaces = get_available_interfaces()
        wifi_iface = next(
            (iface for iface, desc in interfaces.items() 
             if ("WiFi" in desc or "WLAN" in desc or "192.168." in desc) and "0.0.0.0" not in desc), None
        )
        if wifi_iface:
            interface = wifi_iface
        else:
            interface = next((iface for iface in interfaces.keys() if not iface.startswith("lo") and "0.0.0.0" not in interfaces[iface]), list(interfaces.keys())[0])

    async def run_bulk():
        orchestrator = WhatsAppHunterOrchestrator(interface=interface, headless=True)
        result = await orchestrator.run_bulk_hunt(phone_numbers, capture_time)

        if result["success"]:
            for item in result["results"]:
                phone = item["phone"]
                res = item["result"]
                console.print(f"\n[cyan]{phone}:[/cyan]")
                if res["success"]:
                    for ip, ip_res in res["results"].items():
                        if "error" not in ip_res:
                            console.print(f"  {ip_res.get('ip')} - {ip_res.get('country')}, {ip_res.get('city')}")
                else:
                    console.print(f"  Error: {res['error']}")
        else:
            console.print(f"[red]Error: {result['error']}[/red]")

    asyncio.run(run_bulk())

@app.command(name="continuous-mode")
def continuous_mode(
    phone_file: str = typer.Argument(..., help="File with phone numbers"),
    capture_time: int = typer.Option(2, "--seconds", "-t", help="Capture duration"),
    interface: Optional[str] = typer.Option(None, "--interface", "-i", help="Network interface to use")
):
    """Continuous mode - hunt from file"""

    if not interface:
        interfaces = get_available_interfaces()
        wifi_iface = next(
            (iface for iface, desc in interfaces.items() 
             if ("WiFi" in desc or "WLAN" in desc or "192.168." in desc) and "0.0.0.0" not in desc), None
        )
        if wifi_iface:
            interface = wifi_iface
        else:
            interface = next((iface for iface in interfaces.keys() if not iface.startswith("lo") and "0.0.0.0" not in interfaces[iface]), list(interfaces.keys())[0])

    async def run_continuous():
        orchestrator = WhatsAppHunterOrchestrator(interface=interface, headless=True)
        result = await orchestrator.run_continuous_mode(phone_file, capture_time)

        if result["success"]:
            console.print("[green]Continuous hunt completed[/green]")
        else:
            console.print(f"[red]Error: {result['error']}[/red]")

    asyncio.run(run_continuous())

@app.command()
def interfaces():
    """List available network interfaces"""
    interfaces = get_available_interfaces()
    table = Table(title="Available Network Interfaces")
    table.add_column("Interface", style="cyan")
    table.add_column("Description", style="green")

    for iface, desc in interfaces.items():
        table.add_row(iface, desc)

    console.print(table)

if __name__ == "__main__":
    app()
