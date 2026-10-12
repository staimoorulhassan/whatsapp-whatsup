import threading
import time
from scapy.all import sniff, IP, UDP, Raw
from src.ip_extractor import STUN_MAGIC_COOKIE
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

                if 3478 <= sport <= 60000 or 3478 <= dport <= 60000:
                    if packet.haslayer(Raw):
                        payload = bytes(packet[Raw].load)
                        # STUN magic cookie is at bytes 4-8 of the header.
                        if len(payload) >= 8 and payload[4:8] == STUN_MAGIC_COOKIE:
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

    def get_capture_diagnostics(self) -> Dict[str, object]:
        """Return a breakdown of what was captured and why it filtered out.

        Used to explain an empty result: how many packets, how many STUN,
        which IPs were seen and how each was classified.
        """
        from src.ip_extractor import IPExtractor

        extractor = IPExtractor()
        total = len(self.packets)
        stun_packets = self.get_stun_packets()

        if stun_packets:
            raw_ips = extractor.extract_ips_from_stun(stun_packets)
        else:
            raw_ips = extractor.extract_ips(self.packets)

        classified: Dict[str, str] = {}
        for ip in set(raw_ips):
            classified[ip] = extractor.classify_ip(ip)

        flows: List[str] = []
        for p in stun_packets:
            ip_l = p[IP]
            udp_l = p[UDP]
            label = f"{ip_l.src}:{udp_l.sport} -> {ip_l.dst}:{udp_l.dport}"
            if label not in flows:
                flows.append(label)

        return {
            "total_packets": total,
            "stun_packets": len(stun_packets),
            "raw_ips": sorted(set(raw_ips)),
            "classified": classified,
            "targets": extractor.filter_target_ips(set(raw_ips)),
            "stun_flows": flows,
        }


def get_available_interfaces() -> Dict[str, str]:
    """Module-level function for backward compatibility."""
    return PacketCaptureEngine.get_available_interfaces()


def select_best_interface(interfaces: Dict[str, str]) -> Optional[str]:
    """Pick the interface most likely carrying live user traffic.

    Priority: explicit WiFi/WLAN adapter, then any 192.168.x private IP,
    then any non-loopback adapter with a real IP. Avoids matching on
    "192.168." in a hotspot/mobile adapter while a real WiFi adapter exists.
    """
    if not interfaces:
        return None

    # 1) Explicit WiFi/WLAN adapter (by description keyword).
    for iface, desc in interfaces.items():
        if ("WiFi" in desc or "WLAN" in desc) and "0.0.0.0" not in desc:
            return iface

    # 2) Any private LAN IP (192.168.x).
    for iface, desc in interfaces.items():
        if "192.168." in desc and "0.0.0.0" not in desc:
            return iface

    # 3) First non-loopback adapter with a real IP.
    for iface, desc in interfaces.items():
        if not iface.startswith("lo") and "0.0.0.0" not in desc and "no IP" not in desc:
            return iface

    # 4) Last resort.
    return next(iter(interfaces), None)
