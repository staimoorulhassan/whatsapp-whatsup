"""
End-to-end tests for the CLI entry points.

These tests invoke the Typer app through its test runner and verify the
full command flow without requiring a real network interface, WhatsApp
session, or external geolocation API.
"""

from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from src.cli import app


runner = CliRunner()


class TestCLIHelp:
    def test_help_command(self):
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "hunt" in result.stdout
        assert "capture" in result.stdout
        assert "interfaces" in result.stdout

    def test_hunt_help(self):
        result = runner.invoke(app, ["hunt", "--help"])
        assert result.exit_code == 0
        assert "phone_number" in result.stdout
        assert "--seconds" in result.stdout
        assert "--interface" in result.stdout

    def test_capture_help(self):
        result = runner.invoke(app, ["capture", "--help"])
        assert result.exit_code == 0
        assert "--seconds" in result.stdout


class TestCLIInterfaces:
    def test_interfaces_command_lists_adapters(self, sample_interfaces, monkeypatch):
        with patch("src.cli.get_available_interfaces", return_value=sample_interfaces):
            result = runner.invoke(app, ["interfaces"])

        assert result.exit_code == 0
        assert "Available Network Interfaces" in result.stdout
        # Rich tables may truncate very long GUID-style interface names, so assert
        # on the human-readable descriptions that are always present.
        for desc in sample_interfaces.values():
            assert desc.split("(")[0].strip() in result.stdout


class TestCLIHunt:
    def test_hunt_command_happy_path(
        self,
        sample_interfaces,
        best_interface,
        public_target_ip,
        mock_capture_engine,
        mock_geo_service,
        mock_async_input,
    ):
        with patch("src.cli.get_available_interfaces", return_value=sample_interfaces), \
             patch("src.cli.select_best_interface", return_value=best_interface):
            result = runner.invoke(app, ["hunt", "+1234567890", "--seconds", "1"])

        assert result.exit_code == 0, result.stdout
        assert "IP Hunt Results" in result.stdout
        assert public_target_ip in result.stdout
        assert "Found 1 IP" in result.stdout

    def test_hunt_command_no_interface(self, monkeypatch):
        with patch("src.cli.get_available_interfaces", return_value={}):
            result = runner.invoke(app, ["hunt", "+1234567890"])

        assert result.exit_code == 1
        assert "No network interfaces found" in result.stdout


class TestCLICapture:
    def test_capture_command_happy_path(
        self,
        sample_interfaces,
        best_interface,
        public_target_ip,
        mock_capture_engine,
        mock_geo_service,
        mock_async_input,
    ):
        with patch("src.cli.get_available_interfaces", return_value=sample_interfaces), \
             patch("src.cli.select_best_interface", return_value=best_interface):
            result = runner.invoke(app, ["capture", "--seconds", "1"])

        assert result.exit_code == 0, result.stdout
        assert "Captured IP Results" in result.stdout
        assert public_target_ip in result.stdout


class TestCLIBulkHunt:
    def test_bulk_hunt_command(
        self,
        sample_interfaces,
        best_interface,
        public_target_ip,
        mock_capture_engine,
        mock_geo_service,
        mock_async_input,
    ):
        with patch("src.cli.get_available_interfaces", return_value=sample_interfaces), \
             patch("src.cli.select_best_interface", return_value=best_interface):
            result = runner.invoke(
                app, ["bulk-hunt", "+1111111111", "+2222222222", "--seconds", "1"]
            )

        assert result.exit_code == 0, result.stdout
        assert "+1111111111" in result.stdout
        assert "+2222222222" in result.stdout
        assert public_target_ip in result.stdout


class TestCLIContinuousMode:
    def test_continuous_mode_command(
        self,
        sample_interfaces,
        best_interface,
        public_target_ip,
        mock_capture_engine,
        mock_geo_service,
        mock_async_input,
        tmp_path,
    ):
        phone_file = tmp_path / "phones.txt"
        phone_file.write_text("+1111111111\n+2222222222\n")

        with patch("src.cli.get_available_interfaces", return_value=sample_interfaces), \
             patch("src.cli.select_best_interface", return_value=best_interface):
            result = runner.invoke(
                app, ["continuous-mode", str(phone_file), "--seconds", "1"]
            )

        assert result.exit_code == 0, result.stdout
        assert "Continuous hunt completed" in result.stdout

    def test_continuous_mode_missing_file(self, sample_interfaces, best_interface):
        with patch("src.cli.get_available_interfaces", return_value=sample_interfaces), \
             patch("src.cli.select_best_interface", return_value=best_interface):
            result = runner.invoke(
                app, ["continuous-mode", "does_not_exist.txt", "--seconds", "1"]
            )

        assert result.exit_code == 1
        assert "File not found" in result.stdout
