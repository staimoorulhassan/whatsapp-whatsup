import functools
import ipaddress
import struct
from typing import List, Dict, Optional, Set

STUN_MAGIC_COOKIE = b'\x21\x12\xa4\x42'
STUN_MAGIC_COOKIE_INT = 0x2112a442
STUN_PORTS = {3478, 3479, 5349, 5350, 19302}

# STUN attribute types
STUN_ATTR_MAPPED_ADDRESS = 0x0001
STUN_ATTR_XOR_MAPPED_ADDRESS = 0x0020
STUN_ATTR_SOURCE_ADDRESS = 0x0002
STUN_ATTR_CHANGED_ADDRESS = 0x0004
STUN_ATTR_REFLECTED_FROM = 0x0008
STUN_ATTR_XOR_PEER_ADDRESS = 0x0012
STUN_ATTR_XOR_RELAYED_ADDRESS = 0x0016
SERVER_ATTRS = {
    STUN_ATTR_MAPPED_ADDRESS,
    STUN_ATTR_SOURCE_ADDRESS,
    STUN_ATTR_CHANGED_ADDRESS,
    STUN_ATTR_REFLECTED_FROM,
    STUN_ATTR_XOR_MAPPED_ADDRESS,
    STUN_ATTR_XOR_RELAYED_ADDRESS,
}


class IPExtractor:
    """
    Extracts and classifies IP addresses from captured network packets.
    Focuses on STUN protocol analysis to discover target IP addresses.
    """

    _PRIVATE_CIDRS = (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
    )
    _META_CIDRS = (
        "31.13.0.0/16",
        "157.240.0.0/16",
        "185.60.216.0/22",
        "179.6.0.0/16",
        "102.133.0.0/16",
        "158.168.0.0/16",
        "148.113.0.0/16",
        "57.144.0.0/14",
        "57.141.0.0/16",
        "69.63.176.0/20",
        "69.171.224.0/19",
        "66.220.144.0/20",
        "173.252.64.0/18",
        "129.134.0.0/16",
        "163.70.128.0/17",
        "204.15.20.0/22",
        "45.64.40.0/22",
        "103.4.96.0/22",
    )
    _CORPORATE_CIDRS = (
        "8.8.8.0/24",
        "8.8.4.0/24",
        "1.1.1.0/24",
        "9.9.9.0/24",
        "142.250.0.0/15",
        "172.217.0.0/16",
        "216.58.192.0/19",
        "74.125.0.0/16",
        "173.194.0.0/16",
        "209.85.128.0/17",
        "64.233.160.0/19",
        "66.102.0.0/20",
        "108.177.0.0/17",
        "172.253.0.0/16",
        "142.251.0.0/16",
        "104.16.0.0/13",
        "172.64.0.0/13",
        "162.158.0.0/15",
        "141.101.64.0/18",
        "188.114.96.0/20",
        "190.93.240.0/20",
        "197.234.240.0/22",
        "198.41.128.0/17",
        "173.245.48.0/20",
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22",
        "131.0.72.0/22",
        "64.68.96.0/19",
        "216.93.246.0/24",
        "66.151.32.0/21",
    )

    def __init__(self):
        self.private_ranges = [ipaddress.ip_network(r, strict=False) for r in self._PRIVATE_CIDRS]
        self.meta_ranges = [ipaddress.ip_network(r, strict=False) for r in self._META_CIDRS]
        self.corporate_ranges = [ipaddress.ip_network(r, strict=False) for r in self._CORPORATE_CIDRS]

    @functools.lru_cache(maxsize=4096)
    def classify_ip(self, ip: str) -> str:
        """Classify an IP address into a category."""
        try:
            ip_obj = ipaddress.ip_address(ip)
        except (ValueError, TypeError):
            return "invalid"

        if ip_obj.is_loopback or ip_obj.is_multicast or ip_obj.is_unspecified:
            return "private"

        for network in self.private_ranges:
            if ip_obj in network:
                return "private"

        for network in self.meta_ranges:
            if ip_obj in network:
                return "meta_infrastructure"

        for network in self.corporate_ranges:
            if ip_obj in network:
                return "corporate"

        return "public_potential_target"

    def filter_private_ips(self, ips: List[str]) -> List[str]:
        """Filter out private IP addresses."""
        public_ips = []
        for ip in ips:
            classification = self.classify_ip(ip)
            if classification != "private" and classification != "invalid":
                public_ips.append(ip)
        return public_ips

    def filter_corporate_ips(self, ips: List[str]) -> List[str]:
        """Filter out corporate/CDN infrastructure IPs."""
        non_corporate = []
        for ip in ips:
            classification = self.classify_ip(ip)
            if classification not in ("corporate", "meta_infrastructure"):
                non_corporate.append(ip)
        return non_corporate

    def filter_target_ips(self, ips: List[str]) -> List[str]:
        """Filter to keep only potential target IPs (exclude private, corporate, meta)."""
        targets = []
        for ip in ips:
            classification = self.classify_ip(ip)
            if classification == "public_potential_target":
                targets.append(ip)
        return targets

    def extract_ips(self, packets) -> List[str]:
        """Extract IP addresses from captured packets."""
        ips = set()
        for packet in packets:
            extracted = self._extract_from_headers(packet)
            for ip in extracted:
                ips.add(ip)
        return list(ips)

    def extract_ips_from_stun(self, packets) -> List[str]:
        """Receiver public IP from outbound STUN binding requests.

        The report's leak is the destination of the caller's own binding
        request during ringing, not XOR-MAPPED-ADDRESS (that is our own NAT
        mapping) and not a Meta TURN relay.
        """
        if not packets:
            return []

        counts: Dict[str, int] = {}
        for packet in packets:
            for ip in self._receiver_candidates(packet):
                counts[ip] = counts.get(ip, 0) + 2
            for ip in self._peer_from_headers(packet):
                counts[ip] = counts.get(ip, 0) + 1

        if not counts:
            return []

        best = max(counts.values())
        return [ip for ip, n in counts.items() if n == best]

    def _ip_layer(self, packet):
        from scapy.all import IP, IPv6

        if packet.haslayer(IPv6):
            return packet[IPv6]
        if packet.haslayer(IP):
            return packet[IP]
        return None

    def _receiver_candidates(self, packet) -> List[str]:
        from scapy.all import IP, IPv6, UDP, Raw

        if packet is None or not hasattr(packet, "haslayer"):
            return []
        ip_layer = self._ip_layer(packet)
        if ip_layer is None or not packet.haslayer(UDP) or not packet.haslayer(Raw):
            return []
        try:
            payload = bytes(packet[Raw].load)
            if len(payload) < 20 or payload[4:8] != STUN_MAGIC_COOKIE:
                return []
            msg_type = struct.unpack("!H", payload[:2])[0] & 0x3FFF
            src = ipaddress.ip_address(ip_layer.src)
            dst = ipaddress.ip_address(ip_layer.dst)
            outbound = src.is_private or src.is_loopback or src.is_link_local
            inbound = dst.is_private or dst.is_loopback or dst.is_link_local
            if msg_type == 0x0001 and (outbound or not dst.is_private):
                return [str(dst)]
            if msg_type == 0x0101 and (inbound or not src.is_private):
                return [str(src)]
        except Exception:
            return []
        return []

    def _peer_from_headers(self, packet) -> List[str]:
        """Remote address only. Local source and STUN server ports are not the peer."""
        from scapy.all import IP, IPv6, UDP

        if packet is None or not hasattr(packet, "haslayer"):
            return []
        ip_layer = self._ip_layer(packet)
        if ip_layer is None or not packet.haslayer(UDP):
            return []
        try:
            src = ip_layer.src
            dst = ip_layer.dst
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            local = ipaddress.ip_address(src)
            remote = dst if (local.is_private or local.is_loopback or local.is_link_local) else src
            return [remote] if self._is_valid_ip(remote) else []
        except Exception:
            return []

    def _extract_from_headers(self, packet) -> List[str]:
        """Extract IP addresses from packet IP headers."""
        if packet is None:
            return []

        try:
            if not hasattr(packet, 'haslayer'):
                return []

            ip_layer = self._ip_layer(packet)
            if ip_layer is not None:
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst

                results = []
                for ip in [src_ip, dst_ip]:
                    if self._is_valid_ip(ip):
                        results.append(ip)
                return results
        except Exception:
            pass

        return []

    def _extract_from_stun_payload(self, packet) -> List[str]:
        """Extract IPs from STUN packet payloads."""
        from scapy.all import IP, IPv6, UDP, Raw

        if packet is None:
            return []

        try:
            # Check if this is a UDP packet with STUN data
            if not hasattr(packet, 'haslayer'):
                return []

            if packet.haslayer(UDP) and packet.haslayer(Raw):
                payload = bytes(packet[Raw].load)

                # STUN magic cookie is at bytes 4-8 of the 20-byte header.
                if len(payload) >= 8 and payload[4:8] == STUN_MAGIC_COOKIE:
                    return self._parse_stun_attributes(payload)

            # Also check IP layer for STUN-like traffic
            if self._ip_layer(packet) is not None and packet.haslayer(UDP):
                sport = packet[UDP].sport
                dport = packet[UDP].dport

                # STUN ports range
                if sport in STUN_PORTS or dport in STUN_PORTS:
                    if packet.haslayer(Raw):
                        payload = bytes(packet[Raw].load)
                        if len(payload) >= 2:
                            # First 2 bytes should be message type
                            msg_type = struct.unpack("!H", payload[:2])[0]
                            # Request/Response message types in STUN
                            if 0x0001 <= msg_type <= 0x0013:
                                return self._parse_stun_attributes(payload)

            return []

        except Exception:
            return []

    def _parse_stun_attributes(self, payload: bytes) -> List[str]:
        """Parse STUN packet attributes to extract embedded IP addresses."""
        ips = []

        try:
            # STUN header is 20 bytes:
            # - 2 bytes message type
            # - 2 bytes message length
            # - 4 bytes magic cookie
            # - 4 bytes transaction ID (first part)
            # - 8 bytes transaction ID (second part)
            if len(payload) < 20:
                return ips

            msg_type = struct.unpack("!H", payload[:2])[0]
            msg_length = struct.unpack("!H", payload[2:4])[0]
            magic_cookie = struct.unpack("!I", payload[4:8])[0]

            # Verify magic cookie
            if magic_cookie != STUN_MAGIC_COOKIE_INT:
                return ips

            # Parse attributes starting at byte 20
            offset = 20
            end = min(20 + msg_length, len(payload))

            while offset + 4 <= end:
                attr_type = struct.unpack("!H", payload[offset:offset+2])[0]
                attr_length = struct.unpack("!H", payload[offset+2:offset+4])[0]

                if offset + 4 + attr_length > len(payload):
                    break

                attr_data = payload[offset+4:offset+4+attr_length]

                if attr_type in SERVER_ATTRS:
                    pass
                elif attr_type == STUN_ATTR_XOR_PEER_ADDRESS:
                    ip = self._parse_address_attribute(attr_data, is_xor=True)
                    if ip:
                        ips.append(ip)

                # Move to next attribute (padded to 4-byte boundary)
                offset += 4 + attr_length
                padding = attr_length % 4
                if padding:
                    offset += 4 - padding

        except Exception:
            pass

        return ips

    def _parse_address_attribute(self, data: bytes, is_xor: bool = False) -> Optional[str]:
        """Parse an ADDRESS attribute to extract IP address.

        Supports both standard STUN format (with reserved byte) and
        simplified format (without reserved byte).

        Standard format: [reserved(1)] [family(1)] [port(2)] [ip(4 or 16)]
        Simplified format: [family(1)] [port(2)] [ip(4 or 16)]
        """
        try:
            if not data or len(data) < 4:
                return None

            # Address families: 0x01 = IPv4, 0x02 = IPv6
            # Reserved byte in standard format is always 0x00

            if data[0] in (0x01, 0x02):
                # Simplified format: family first (no reserved byte)
                addr_family = data[0]
                port_start = 1
                ip_start = 3
                ip_len = 4
            elif len(data) >= 2 and data[1] in (0x01, 0x02):
                # Standard format: reserved (0x00) + family
                addr_family = data[1]
                port_start = 2
                ip_start = 4
                ip_len = 4
            else:
                return None

            if addr_family == 0x01:  # IPv4
                required_len = ip_start + 4
                if len(data) < required_len:
                    return None

                port = struct.unpack("!H", data[port_start:port_start+2])[0]
                ip_bytes = data[ip_start:ip_start+4]

                if is_xor:
                    port ^= (STUN_MAGIC_COOKIE_INT >> 16) & 0xFFFF
                    # XOR with magic cookie - need to handle endianness correctly
                    ip_int = struct.unpack("<I", ip_bytes)[0] ^ STUN_MAGIC_COOKIE_INT
                    # Pack back in big-endian for IP address parsing
                    ip_bytes = struct.pack(">I", ip_int)

                ip_str = self._bytes_to_ip(ip_bytes)
                return ip_str

            elif addr_family == 0x02:  # IPv6
                required_len = ip_start + 16
                if len(data) < required_len:
                    return None

                port = struct.unpack("!H", data[port_start:port_start+2])[0]
                ip_bytes = data[ip_start:ip_start+16]

                if is_xor:
                    port ^= (STUN_MAGIC_COOKIE_INT >> 16) & 0xFFFF
                    # XOR with magic cookie and top 32 bits of transaction ID
                    ip_int = struct.unpack("!I", ip_bytes[:4])[0] ^ STUN_MAGIC_COOKIE_INT
                    ip_bytes = struct.pack("!I", ip_int) + ip_bytes[4:]

                ip_str = self._bytes_to_ip(ip_bytes, ipv6=True)
                return ip_str

        except Exception:
            return None

        return None

    def _bytes_to_ip(self, ip_bytes: bytes, ipv6: bool = False) -> Optional[str]:
        """Convert bytes to IP string."""
        try:
            if ipv6:
                ip_obj = ipaddress.IPv6Address(ip_bytes)
                return str(ip_obj)
            else:
                ip_obj = ipaddress.IPv4Address(ip_bytes)
                return str(ip_obj)
        except (ValueError, TypeError):
            return None

    def _is_valid_ip(self, ip: str) -> bool:
        """Check if a string is a valid IP address."""
        try:
            ipaddress.ip_address(ip)
            return True
        except (ValueError, TypeError):
            return False

    def get_most_relevant_ip(self, ips: List[str]) -> Optional[str]:
        """Get the most relevant target IP from a list."""
        # Filter to only public, non-corporate targets
        targets = self.filter_target_ips(ips)

        if not targets:
            return None

        # Return the first valid target IP
        return targets[0]

    def summarize_extraction(self, packets) -> Dict:
        """Generate a summary of extracted information."""
        ips = self.extract_ips(packets)

        classified = {}
        classification_counts = {}

        for ip in ips:
            classification = self.classify_ip(ip)
            classified[ip] = classification
            classification_counts[classification] = classification_counts.get(classification, 0) + 1

        target_ips = self.filter_target_ips(ips)

        return {
            "total_extracted": len(ips),
            "potential_targets": len(target_ips),
            "target_ips": target_ips,
            "classification_counts": classification_counts,
            "classified_ips": classified
        }
