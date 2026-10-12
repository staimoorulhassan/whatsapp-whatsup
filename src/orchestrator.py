import signal
import sys
import asyncio
from typing import Dict, List, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from config.settings import CAPTURE_TIMEOUT
from src.packet_capture import PacketCaptureEngine
from src.geolocation import GeoLocationService

console = Console()


class WhatsAppHunterOrchestrator:
    def __init__(self, interface: str):
        self.interface = interface
        self.capture_engine = None
        self.geo_service = None
        self.running = False

    def setup_signal_handlers(self):
        def signal_handler(sig, frame):
            console.print("\n[yellow]Stopping execution...[/yellow]")
            self.cleanup()
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)

    def cleanup(self):
        self.running = False
        console.print("[yellow]Cleaning up resources...[/yellow]")

        if self.capture_engine:
            self.capture_engine.stop_capture()

        if self.geo_service:
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    asyncio.ensure_future(self.geo_service.close())
                else:
                    asyncio.run(self.geo_service.close())
            except RuntimeError:
                pass
            except Exception:
                pass

    async def _wait_for_enter(self):
        try:
            await asyncio.to_thread(input)
        except EOFError:
            pass

    def _print_capture_diagnostics(self):
        try:
            diag = self.capture_engine.get_capture_diagnostics()
        except Exception as e:
            console.print(f"[yellow]Diagnosis unavailable: {e}[/yellow]")
            return

        total = diag["total_packets"]
        stun = diag["stun_packets"]
        classified: Dict[str, str] = diag["classified"]

        console.print(Panel.fit(
            f"[bold]Capture diagnostics[/bold]\n"
            f"Packets captured : [cyan]{total}[/cyan]\n"
            f"STUN packets     : [cyan]{stun}[/cyan]\n"
            f"Distinct IPs     : [cyan]{len(classified)}[/cyan]",
            border_style="yellow"
        ))

        if total == 0:
            console.print("[red]No packets at all. Wrong interface, no call made, "
                          "or capture requires admin. Confirm the WiFi adapter and "
                          "that the call stayed active.[/red]")
            return

        if not classified:
            console.print("[yellow]Packets captured but no readable IPs.[/yellow]")
            flows = diag.get("stun_flows") or []
            if flows:
                console.print(Panel.fit(
                    "[bold]STUN flows[/bold]\n" + "\n".join(f"[cyan]{f}[/cyan]" for f in flows[:20]),
                    border_style="dim"
                ))
            return

        tbl = Table(title="IP classification")
        tbl.add_column("IP", style="cyan")
        tbl.add_column("Classification")
        for ip, cat in sorted(classified.items()):
            style = "green" if cat == "public_potential_target" else "dim"
            tbl.add_row(ip, f"[{style}]{cat}[/{style}]")
        console.print(tbl)

        flows = diag.get("stun_flows") or []
        if flows:
            console.print(Panel.fit(
                "[bold]STUN flows[/bold]\n" + "\n".join(f"[cyan]{f}[/cyan]" for f in flows[:20]),
                border_style="dim"
            ))

        if not diag["targets"]:
            console.print("[yellow]All seen IPs were private/Meta/corporate, so none "
                          "qualified as a target. Dial from the WhatsApp Desktop app "
                          "on this PC with VPNs off and keep the call connected.[/yellow]")

    async def _run_session(self, capture_duration: int, phone_number: Optional[str], title: str) -> Dict:
        self.setup_signal_handlers()
        self.running = True
        console.print(Panel.fit(f"[bold green]{title}[/bold green]", border_style="green"))

        self.capture_engine = PacketCaptureEngine(self.interface)
        self.geo_service = GeoLocationService()

        try:
            self.geo_service.print_banner()

            if phone_number:
                prompt = (
                    f"[bold]Dial {phone_number} from the WhatsApp Desktop app.[/bold]\n\n"
                    "The desktop app runs on this PC, so call traffic crosses this adapter.\n"
                    "Open that chat, press [bold cyan]Enter[/bold cyan], then click Call "
                    "and keep it connected."
                )
            else:
                prompt = (
                    "[bold]Dial from the WhatsApp Desktop app.[/bold]\n\n"
                    "The web browser cannot place calls. The desktop app runs on this PC, "
                    "so call traffic crosses this adapter.\n"
                    "Open the chat, press [bold cyan]Enter[/bold cyan], then click Call "
                    "and keep it connected."
                )
            console.print(Panel.fit(prompt, border_style="yellow"))
            await self._wait_for_enter()

            console.print(f"[cyan]Capturing for {capture_duration}s on {self.interface}. Place the call now.[/cyan]")
            console.print("[yellow]Keep the call active. Press Ctrl+C to stop early.[/yellow]")
            self.capture_engine.start_capture(duration=capture_duration)

            for i in range(capture_duration):
                if not self.running:
                    break
                remaining = capture_duration - i
                if remaining % 5 == 0 or remaining == 1:
                    console.print(f"  [{remaining}s remaining...]")
                await asyncio.sleep(1)

            self.capture_engine.stop_capture()
            console.print("[cyan]Analyzing captured packets...[/cyan]")
            ips = self.capture_engine.get_candidate_ips()

            if not ips:
                self._print_capture_diagnostics()
                return {"success": False, "error": "No candidate IPs found"}

            console.print(f"[green]Found {len(ips)} candidate IP(s)[/green]")
            console.print("[cyan]Performing geolocation lookup...[/cyan]")
            geo_results = await self.geo_service.lookup_bulk(ips)
            return {"success": True, "ips_found": len(ips), "results": geo_results}

        except KeyboardInterrupt:
            return {"success": False, "error": "Interrupted by user"}
        except Exception as e:
            return {"success": False, "error": str(e)}
        finally:
            self.cleanup()

    async def run_hunt(self, phone_number: str, capture_duration: int = None) -> Dict:
        duration = capture_duration if capture_duration is not None else CAPTURE_TIMEOUT
        return await self._run_session(duration, phone_number, "WhatsApp IP Hunter")

    async def run_capture(self, capture_duration: int = None) -> Dict:
        duration = capture_duration if capture_duration is not None else CAPTURE_TIMEOUT
        return await self._run_session(duration, None, "WhatsApp IP Capture")

    async def run_bulk_hunt(self, phone_numbers: List[str], capture_duration: int = None) -> Dict:
        results = []
        for phone in phone_numbers:
            console.print(f"\n[cyan]Hunting: {phone}[/cyan]")
            result = await self.run_hunt(phone, capture_duration)
            results.append({"phone": phone, "result": result})
        return {"success": True, "results": results}

    async def run_continuous_mode(self, phone_file: str, capture_duration: int = None) -> Dict:
        try:
            lines = await asyncio.to_thread(self._read_phone_file, phone_file)
            phones = [line.strip() for line in lines if line.strip()]
            return await self.run_bulk_hunt(phones, capture_duration)
        except FileNotFoundError:
            return {"success": False, "error": f"File not found: {phone_file}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    @staticmethod
    def _read_phone_file(phone_file: str) -> List[str]:
        with open(phone_file, "r", encoding="utf-8") as f:
            return f.readlines()
