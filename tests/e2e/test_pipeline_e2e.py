"""
End-to-end tests for the capture-to-location pipeline.

These tests pass synthetic Scapy packets through the real
PacketCaptureEngine/IPExtractor/GeoLocationService wiring while mocking
only external network calls.
"""

import struct

import pytest
from scapy.all import IP, UDP, Raw

from src.ip_extractor import IPExtractor, STUN_MAGIC_COOKIE
from src.packet_capture import PacketCaptureEngine


class TestCaptureToExtractionPipeline:
    def test_capture_engine_extracts_public_target_from_stun_request(
        self, stun_request_packet, public_target_ip
    ):
        engine = PacketCaptureEngine(interface="fake")
        engine.packets = [stun_request_packet]

        ips = engine.get_candidate_ips()

        assert public_target_ip in ips

    def test_capture_engine_extracts_public_target_from_stun_response(
        self, stun_response_packet, public_target_ip
    ):
        engine = PacketCaptureEngine(interface="fake")
        engine.packets = [stun_response_packet]

        ips = engine.get_candidate_ips()

        assert public_target_ip in ips

    def test_capture_engine_filters_meta_and_private_ips(self):
        engine = PacketCaptureEngine(interface="fake")
        engine.packets = [
            IP(src="192.168.1.42", dst="31.13.75.17") / UDP(sport=12345, dport=3478),
            IP(src="192.168.1.42", dst="8.8.8.8") / UDP(sport=12345, dport=3478),
        ]

        ips = engine.get_candidate_ips()

        assert "31.13.75.17" not in ips
        assert "8.8.8.8" not in ips
        assert "192.168.1.42" not in ips

    def test_capture_engine_diagnostics_match_extraction(self, stun_request_packet, public_target_ip):
        engine = PacketCaptureEngine(interface="fake")
        engine.packets = [stun_request_packet]

        diag = engine.get_capture_diagnostics()

        assert diag["total_packets"] == 1
        assert diag["stun_packets"] == 1
        assert public_target_ip in diag["classified"]
        assert diag["classified"][public_target_ip] == "public_potential_target"
        assert public_target_ip in diag["targets"]


class TestIPExtractorSTUNHandling:
    def test_stun_xor_mapped_address_extraction(self):
        extractor = IPExtractor()
        magic_cookie = struct.unpack("!I", STUN_MAGIC_COOKIE)[0]
        original_ip = 0xCBCF0A01  # 203.207.10.1
        xor_ip = original_ip ^ magic_cookie

        ip_bytes = struct.pack("<I", xor_ip)
        data = b"\x01\x00\x00" + ip_bytes

        result = extractor._parse_address_attribute(data, is_xor=True)
        assert result == "203.207.10.1"

    def test_receiver_candidates_prefers_outbound_binding_request_destination(
        self, stun_request_packet, public_target_ip
    ):
        extractor = IPExtractor()
        candidates = extractor._receiver_candidates(stun_request_packet)

        assert public_target_ip in candidates

    def test_full_extraction_summary(self, stun_request_packet):
        extractor = IPExtractor()
        summary = extractor.summarize_extraction([stun_request_packet])

        assert summary["total_extracted"] >= 1
        assert summary["potential_targets"] >= 1
        assert summary["classification_counts"]["public_potential_target"] >= 1


class TestGeolocationPipeline:
    @pytest.mark.asyncio
    async def test_geo_lookup_bulk_with_mocked_session(self, public_target_ip, monkeypatch):
        from src import geolocation

        class FakeResponse:
            status = 200

            async def json(self):
                return {
                    "ip": public_target_ip,
                    "country_name": "Exampleland",
                    "countryCode": "EX",
                    "city": "Test City",
                    "lat": 12.34,
                    "lon": 56.78,
                    "timezone": "UTC",
                }

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

        class FakeSession:
            def get(self, url, headers=None):
                return FakeResponse()

            async def close(self):
                pass

        service = geolocation.GeoLocationService()
        service._session = FakeSession()

        results = await service.lookup_bulk([public_target_ip])

        assert public_target_ip in results
        assert results[public_target_ip]["country"] == "Exampleland"
        assert results[public_target_ip]["latitude"] == 12.34

    @pytest.mark.asyncio
    async def test_geo_lookup_falls_back_gracefully(self, public_target_ip, monkeypatch):
        from src import geolocation

        class FailingSession:
            def get(self, url, headers=None):
                raise RuntimeError("network down")

            async def close(self):
                pass

        service = geolocation.GeoLocationService()
        service._reader = None
        service._session = FailingSession()

        results = await service.lookup_bulk([public_target_ip])

        assert public_target_ip in results
        assert results[public_target_ip]["source"] == "failed"
