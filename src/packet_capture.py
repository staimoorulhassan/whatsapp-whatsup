import threading
import time
from scapy.all import sniff, IP, UDP, Raw
from typing import Dict, List, Optional
from rich.console import Console
from rich.table import Table

console = Console()


class PacketCaptureEngine:
    """
    Packet capture engine for intercepting STUN/TURN traffic.
    Runs sniffer in a background thread to capture UDP packets on specified ports.
    """

    def __init__(self, interface: str):
        self.interface = interface
        self.capture_active = False
        self.packets: List = []
        self.capture_thread: Optional[threading.Thread] = None

    @staticmethod
    def get_available_interfaces() -> Dict[str, str]:
        """Return available network interfaces with friendly names and IPs."""
        import scapy.all as scapy
        interfaces = {}
        for name, iface in scapy.conf.ifaces.items():
            ip = getattr(iface, 'ip', None)
            friendly = getattr(iface, 'name', name)
            if ip:
                interfaces[name] = f"{friendly} ({ip})"
            else:
                interfaces[name] = f"{friendly} (no IP)"
        return interfaces

    def start_capture(self, duration: int = 10):
        """Start packet capture for specified duration."""
        self.capture_active = True
        self.packets = []

        def capture_worker():
            try:
                # Use broad filter on Windows (BPF filters can be problematic)
                # We filter for STUN packets in get_stun_packets()
                self.packets = sniff(
                    iface=self.interface,
                    timeout=duration,
                    stop_filter=lambda x: not self.capture_active,
                    filter="udp"
                )
            except Exception as e:
                console.print(f"[red]Capture error: {e}[/red]")
            finally:
                self.capture_active = False

        self.capture_thread = threading.Thread(target=capture_worker, daemon=True)
        self.capture_thread.start()

        console.print(f"[green]Started packet capture on {self.interface} for {duration}s[/green]")

    def stop_capture(self):
        """Stop packet capture"""
        self.capture_active = False
        if self.capture_thread:
            self.capture_thread.join(timeout=5)

    def get_stun_packets(self) -> List:
        """Extract STUN-related packets from captured data."""
        stun_packets = []
        for packet in self.packets:
            if packet.haslayer(UDP) and packet.haslayer(IP):
                sport = packet[UDP].sport
                dport = packet[UDP].dport

                # Standard STUN ports range
                if (sport >= 3478 and sport <= 65535) or (dport >= 3478 and dport <= 65535):
                    # Check for STUN magic cookie in payload
                    if packet.haslayer(Raw):
                        payload = bytes(packet[Raw].payload)[:4]
                        # STUN magic cookie: 0x2112a442
                        if payload == b'\x21\x12\xa4\x42':
                            stun_packets.append(packet)
                        elif len(payload) >= 16:
                            if payload[:4] == b'\x21\x12\xa4\x42':
                                stun_packets.append(packet)
                    else:
                        # Include packets on STUN ports even without payload
                        stun_packets.append(packet)

        return stun_packets

    def get_candidate_ips(self) -> List[str]:
        """Get candidate target IPs from captured packets."""
        from src.ip_extractor import IPExtractor

        if not self.packets:
            return []

        extractor = IPExtractor()
        stun_packets = self.get_stun_packets()

        # Try to extract from STUN payloads first
        if stun_packets:
            ips = extractor.extract_ips_from_stun(stun_packets)
        else:
            # Fall back to all captured packets
            ips = extractor.extract_ips(self.packets)

        # Filter to public, non-corporate targets
        return extractor.filter_target_ips(ips)


def get_available_interfaces() -> Dict[str, str]:
    """Module-level function for backward compatibility."""
    return PacketCaptureEngine.get_available_interfaces()
