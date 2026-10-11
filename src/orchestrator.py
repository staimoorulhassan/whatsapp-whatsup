import time
import signal
import sys
import asyncio
from typing import Dict, Optional, List
from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.panel import Panel

from src.packet_capture import PacketCaptureEngine, get_available_interfaces
from src.ip_extractor import IPExtractor
from src.whatsapp_client import WhatsAppClient
from src.geolocation import GeoLocationService

console = Console()

class WhatsAppHunterOrchestrator:
    def __init__(self, interface: str, headless: bool = True):
        self.interface = interface
        self.headless = headless
        self.capture_engine = None
        self.whatsapp_client = None
        self.geo_service = None
        self.running = False
        
    def setup_signal_handlers(self):
        """Setup Ctrl+C handler"""
        def signal_handler(sig, frame):
            console.print("\n[yellow]Stopping execution...[/yellow]")
            self.cleanup()
            sys.exit(0)
            
        signal.signal(signal.SIGINT, signal_handler)
    
    def cleanup(self):
        """Cleanup resources"""
        self.running = False
        console.print("[yellow]Cleaning up resources...[/yellow]")

        if self.capture_engine:
            self.capture_engine.stop_capture()

        if self.whatsapp_client:
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    # We're in an async context, schedule the cleanup
                    asyncio.ensure_future(self.whatsapp_client.cleanup())
                else:
                    asyncio.run(self.whatsapp_client.cleanup())
            except RuntimeError:
                # No running loop, just skip async cleanup
                pass
            except Exception:
                pass

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
    
    async def run_hunt(self, phone_number: str, capture_duration: int = 10) -> Dict:
        """Main hunting workflow"""
        self.setup_signal_handlers()
        self.running = True
        
        console.print(Panel.fit("[bold green]WhatsApp IP Hunter Starting[/bold green]", border_style="green"))
        
        # Initialize components
        self.capture_engine = PacketCaptureEngine(self.interface)
        self.whatsapp_client = WhatsAppClient(headless=self.headless)
        self.geo_service = GeoLocationService()
        
        try:
            # Show banner
            self.geo_service.print_banner()
            
            # Step 1: Connect to WhatsApp Web
            console.print("[cyan]Step 1: Connecting to WhatsApp Web...[/cyan]")
            connect_result = await self.whatsapp_client.connect()
            
            if not connect_result["success"]:
                return {"success": False, "error": f"WhatsApp connection failed: {connect_result['error']}"}
            
            if connect_result["method"] == "qr_required":
                console.print("[yellow]QR code generated. Scan with WhatsApp mobile app.[/yellow]")
                
                if not await self.whatsapp_client.wait_for_login(timeout=300):
                    return {"success": False, "error": "Login timeout"}
                
                # Set logged_in flag after successful login
                self.whatsapp_client.logged_in = True
                console.print("[green]Successfully logged in![/green]")
            
            # Step 2: Start packet capture
            console.print(f"[cyan]Step 2: Starting packet capture on {self.interface}...[/cyan]")
            self.capture_engine.start_capture(duration=capture_duration)
            
            # Step 3: Prompt user to make call from phone
            console.print(f"[cyan]Step 3: WhatsApp Web connected.[/cyan]")
            console.print(f"[yellow]Please make a voice/video call to {phone_number} from your phone's WhatsApp app.[/yellow]")
            console.print(f"[yellow]The tool will capture STUN packets for {capture_duration} seconds during the call.[/yellow]")
            
            # Navigate to chat page (for reference)
            clean_number = ''.join(filter(str.isdigit, phone_number))
            chat_url = f"https://web.whatsapp.com/send?phone={clean_number}"
            try:
                await self.whatsapp_client.page.goto(chat_url, wait_until="domcontentloaded", timeout=15000)
            except:
                pass  # Page might not load if number not registered
            
            # Step 4: Wait for capture duration
            console.print(f"[cyan]Step 4: Capturing packets for {capture_duration} seconds...[/cyan]")
            console.print("[yellow]Press Ctrl+C to stop early[/yellow]")
            
            for i in range(capture_duration):
                if not self.running:
                    break
                remaining = capture_duration - i
                console.print(f"  [{remaining}s remaining...]")
                await asyncio.sleep(1)
            
            # Step 5: Stop capture and extract IPs
            self.capture_engine.stop_capture()
            console.print(f"[cyan]Step 5: Analyzing captured packets...[/cyan]")
            ips = self.capture_engine.get_candidate_ips()
            
            if not ips:
                return {"success": False, "error": "No candidate IPs found"}
            
            console.print(f"[green]Found {len(ips)} candidate IP(s)[/green]")
            
            # Step 7: Geolocation
            console.print("[cyan]Step 6: Performing geolocation lookup...[/cyan]")
            geo_results = await self.geo_service.lookup_bulk(ips)
            
            return {
                "success": True,
                "ips_found": len(ips),
                "results": geo_results
            }
            
        except KeyboardInterrupt:
            return {"success": False, "error": "Interrupted by user"}
        except Exception as e:
            return {"success": False, "error": str(e)}
        finally:
            self.cleanup()

    async def run_bulk_hunt(self, phone_numbers: List[str], capture_duration: int = 5) -> Dict:
        """Bulk hunt multiple targets"""
        results = []
        
        for phone in phone_numbers:
            if not self.running:
                break
                
            console.print(f"\n[cyan]Hunting: {phone}[/cyan]")
            result = await self.run_hunt(phone, capture_duration)
            results.append({"phone": phone, "result": result})
            
            # Small delay between targets
            await asyncio.sleep(0.1)
            
        return {"success": True, "results": results}

    async def run_continuous_mode(self, phone_file: str, capture_duration: int = 2, delay_between: int = 0) -> Dict:
        """Continuous mode from file"""
        try:
            with open(phone_file, 'r') as f:
                phones = [line.strip() for line in f if line.strip()]
                
            return await self.run_bulk_hunt(phones, capture_duration)
            
        except FileNotFoundError:
            return {"success": False, "error": f"File not found: {phone_file}"}
        except Exception as e:
            return {"success": False, "error": str(e)}