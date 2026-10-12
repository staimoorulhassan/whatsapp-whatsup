import asyncio
import struct
from unittest.mock import MagicMock

import pytest
from scapy.all import IP, UDP, Raw

from src.ip_extractor import STUN_MAGIC_COOKIE


@pytest.fixture
def sample_interfaces():
    """Return a realistic set of network interfaces for tests."""
    return {
        "\\Device\\NPF_Loopback": "Loopback Pseudo-Interface 1 (127.0.0.1)",
        "\\Device\\NPF_{12345678-1234-1234-1234-123456789012}": "Wi-Fi (192.168.1.42)",
        "\\Device\\NPF_{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}": "Ethernet (10.0.0.5)",
    }


@pytest.fixture
def best_interface(sample_interfaces):
    """Return the interface select_best_interface would pick."""
    for iface, desc in sample_interfaces.items():
        if "WiFi" in desc or "WLAN" in desc:
            return iface
    for iface, desc in sample_interfaces.items():
        if "192.168." in desc:
            return iface
    for iface, desc in sample_interfaces.items():
        if not iface.startswith("lo") and "0.0.0.0" not in desc and "no IP" not in desc:
            return iface
    return next(iter(sample_interfaces), None)


@pytest.fixture
def public_target_ip():
    """A public IP that should classify as a potential target.

    Uses example.com (93.184.216.34) rather than a TEST-NET address so
    Python's ipaddress module does not flag it as private.
    """
    return "93.184.216.34"


@pytest.fixture
def stun_request_packet(public_target_ip):
    """Build a synthetic outbound STUN binding request packet."""
    src_ip = "192.168.1.42"
    dst_ip = public_target_ip
    sport = 12345
    dport = 3478

    msg_type = 0x0001
    msg_length = 0
    magic_cookie = struct.unpack("!I", STUN_MAGIC_COOKIE)[0]
    # STUN transaction ID is 12 bytes (96 bits)
    transaction_id = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c"

    header = struct.pack("!H", msg_type)
    header += struct.pack("!H", msg_length)
    header += struct.pack("!I", magic_cookie)
    header += transaction_id

    packet = IP(src=src_ip, dst=dst_ip) / UDP(sport=sport, dport=dport) / Raw(load=header)
    return packet


@pytest.fixture
def stun_response_packet(public_target_ip):
    """Build a synthetic inbound STUN binding response packet."""
    src_ip = public_target_ip
    dst_ip = "192.168.1.42"
    sport = 3478
    dport = 12345

    msg_type = 0x0101
    msg_length = 0
    magic_cookie = struct.unpack("!I", STUN_MAGIC_COOKIE)[0]
    transaction_id = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c"

    header = struct.pack("!H", msg_type)
    header += struct.pack("!H", msg_length)
    header += struct.pack("!I", magic_cookie)
    header += transaction_id

    packet = IP(src=src_ip, dst=dst_ip) / UDP(sport=sport, dport=dport) / Raw(load=header)
    return packet


@pytest.fixture
def mock_capture_engine(monkeypatch, public_target_ip):
    """Patch PacketCaptureEngine in the orchestrator so captures run without a real interface."""
    from src import orchestrator

    started = {"calls": 0}

    class FakeCaptureEngine:
        def __init__(self, interface: str):
            self.interface = interface
            self.capture_active = False
            self.packets = []

        def start_capture(self, duration: int = 10):
            self.capture_active = True
            started["calls"] += 1

        def stop_capture(self):
            self.capture_active = False

        def get_candidate_ips(self):
            return [public_target_ip]

        def get_capture_diagnostics(self):
            return {
                "total_packets": 10,
                "stun_packets": 4,
                "classified": {public_target_ip: "public_potential_target"},
                "targets": [public_target_ip],
                "stun_flows": [],
            }

    monkeypatch.setattr(orchestrator, "PacketCaptureEngine", FakeCaptureEngine)
    return started


@pytest.fixture
def mock_geo_service(monkeypatch, public_target_ip):
    """Patch GeoLocationService in the orchestrator so lookups do not hit external APIs."""
    from src import orchestrator

    class FakeGeoService:
        def __init__(self, *args, **kwargs):
            pass

        def print_banner(self):
            pass

        async def lookup_bulk(self, ips):
            return {
                ip: {
                    "ip": ip,
                    "country": "Exampleland",
                    "country_code": "EX",
                    "city": "Test City",
                    "latitude": 12.34,
                    "longitude": 56.78,
                    "timezone": "UTC",
                    "asn": None,
                    "organization": None,
                    "source": "test",
                }
                for ip in ips
            }

        async def close(self):
            pass

    monkeypatch.setattr(orchestrator, "GeoLocationService", FakeGeoService)
    return public_target_ip


@pytest.fixture
def mock_async_input(monkeypatch):
    """Patch orchestrator input prompts so tests can proceed automatically."""
    from src import orchestrator

    async def fake_wait_for_enter(self):
        return None

    monkeypatch.setattr(orchestrator.WhatsAppHunterOrchestrator, "_wait_for_enter", fake_wait_for_enter)


@pytest.fixture(scope="session")
def event_loop():
    """Provide a consistent event loop for async tests."""
    policy = asyncio.get_event_loop_policy()
    loop = policy.new_event_loop()
    yield loop
    loop.close()
