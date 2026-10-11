import pytest
from unittest.mock import patch, MagicMock
from src.packet_capture import PacketCaptureEngine, get_available_interfaces

def test_get_available_interfaces():
    interfaces = get_available_interfaces()
    assert isinstance(interfaces, dict)
    assert len(interfaces) > 0

def test_capture_engine_initialization():
    engine = PacketCaptureEngine(interface="lo")
    assert engine.interface == "lo"
    assert engine.capture_active == False

def test_start_stop_capture():
    engine = PacketCaptureEngine(interface="lo")
    engine.start_capture(duration=1)
    assert engine.capture_active == True
    engine.stop_capture()
    assert engine.capture_active == False