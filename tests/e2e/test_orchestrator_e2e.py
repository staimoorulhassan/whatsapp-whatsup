"""
End-to-end tests for the orchestrator layer.

These exercises run_hunt, run_capture, run_bulk_hunt, and
run_continuous_mode from end to end while replacing the real packet
capture engine and geolocation service with deterministic fakes.
"""

import pytest

from src.orchestrator import WhatsAppHunterOrchestrator


class TestOrchestratorHunt:
    @pytest.mark.asyncio
    async def test_run_hunt_finds_target_ip(
        self, best_interface, public_target_ip, mock_capture_engine, mock_geo_service, mock_async_input
    ):
        orchestrator = WhatsAppHunterOrchestrator(interface=best_interface)
        result = await orchestrator.run_hunt("+1234567890", capture_duration=1)

        assert result["success"] is True
        assert result["ips_found"] == 1
        assert public_target_ip in result["results"]
        assert result["results"][public_target_ip]["country"] == "Exampleland"

    @pytest.mark.asyncio
    async def test_run_capture_finds_target_ip(
        self, best_interface, public_target_ip, mock_capture_engine, mock_geo_service, mock_async_input
    ):
        orchestrator = WhatsAppHunterOrchestrator(interface=best_interface)
        result = await orchestrator.run_capture(capture_duration=1)

        assert result["success"] is True
        assert result["ips_found"] == 1
        assert public_target_ip in result["results"]


class TestOrchestratorBulkAndContinuous:
    @pytest.mark.asyncio
    async def test_run_bulk_hunt(
        self, best_interface, public_target_ip, mock_capture_engine, mock_geo_service, mock_async_input
    ):
        orchestrator = WhatsAppHunterOrchestrator(interface=best_interface)
        result = await orchestrator.run_bulk_hunt(["+1111111111", "+2222222222"], capture_duration=1)

        assert result["success"] is True
        assert len(result["results"]) == 2
        for item in result["results"]:
            assert item["result"]["success"] is True
            assert public_target_ip in item["result"]["results"]

    @pytest.mark.asyncio
    async def test_run_continuous_mode(
        self, best_interface, public_target_ip, mock_capture_engine, mock_geo_service, mock_async_input, tmp_path
    ):
        phone_file = tmp_path / "phones.txt"
        phone_file.write_text("+1111111111\n+2222222222\n")

        orchestrator = WhatsAppHunterOrchestrator(interface=best_interface)
        result = await orchestrator.run_continuous_mode(str(phone_file), capture_duration=1)

        assert result["success"] is True
        assert len(result["results"]) == 2

    @pytest.mark.asyncio
    async def test_run_continuous_mode_missing_file(self, best_interface):
        orchestrator = WhatsAppHunterOrchestrator(interface=best_interface)
        result = await orchestrator.run_continuous_mode("missing.txt", capture_duration=1)

        assert result["success"] is False
        assert "File not found" in result["error"]


class TestOrchestratorDiagnostics:
    @pytest.mark.asyncio
    async def test_run_hunt_no_candidates_shows_diagnostics(
        self, best_interface, mock_geo_service, mock_async_input, monkeypatch
    ):
        from src import packet_capture

        class EmptyCaptureEngine:
            def __init__(self, interface: str):
                self.interface = interface

            def start_capture(self, duration: int = 10):
                pass

            def stop_capture(self):
                pass

            def get_candidate_ips(self):
                return []

            def get_capture_diagnostics(self):
                return {
                    "total_packets": 0,
                    "stun_packets": 0,
                    "classified": {},
                    "targets": [],
                    "stun_flows": [],
                }

        monkeypatch.setattr(packet_capture, "PacketCaptureEngine", EmptyCaptureEngine)

        orchestrator = WhatsAppHunterOrchestrator(interface=best_interface)
        result = await orchestrator.run_hunt("+1234567890", capture_duration=1)

        assert result["success"] is False
        assert "No candidate IPs found" in result["error"]
