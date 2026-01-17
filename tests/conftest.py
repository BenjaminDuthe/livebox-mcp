"""Fixtures pytest pour les tests livebox-mcp."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from typing import Any

from livebox_mcp.livebox_api import LiveboxAPI
from livebox_mcp.server import LiveboxMCPServer


@pytest.fixture
def mock_response_factory():
    """Factory pour créer des réponses API mockées."""

    def _create_response(data: dict[str, Any], status: int = 0) -> dict[str, Any]:
        return {"status": status, "data": data}

    return _create_response


@pytest.fixture
def mock_session():
    """Mock aiohttp ClientSession."""
    session = MagicMock()
    session.close = AsyncMock()
    return session


@pytest.fixture
def livebox_api():
    """Instance LiveboxAPI pour les tests."""
    return LiveboxAPI(host="192.168.1.1", password="test_password")


@pytest.fixture
def mock_livebox_api():
    """LiveboxAPI avec toutes les méthodes mockées."""
    api = MagicMock(spec=LiveboxAPI)

    # Mock async methods
    api.authenticate = AsyncMock(return_value="mock_context_id")
    api.get_device_info = AsyncMock(return_value={
        "Manufacturer": "Sagemcom",
        "ModelName": "Livebox 6",
        "SerialNumber": "ABC123",
        "SoftwareVersion": "1.0.0",
        "UpTime": 86400,
    })
    api.get_time = AsyncMock(return_value={
        "CurrentLocalTime": "2025-01-17T10:00:00",
        "TimeZone": "Europe/Paris",
    })
    api.get_wan_status = AsyncMock(return_value={
        "LinkState": "up",
        "IPAddress": "90.1.2.3",
        "IPv6Address": "2001:db8::1",
    })
    api.get_traffic_stats = AsyncMock(return_value={
        "BytesSent": 1000000,
        "BytesReceived": 5000000,
    })
    api.get_wifi_status = AsyncMock(return_value={
        "Enable": True,
        "Status": "Up",
    })
    api.get_ssid_list = AsyncMock(return_value={
        "ssid": [
            {"SSID": "Livebox-TEST", "Enable": True},
            {"SSID": "Livebox-TEST-5G", "Enable": True},
        ]
    })
    api.get_wifi_stats = AsyncMock(return_value={
        "BytesSent": 500000,
        "BytesReceived": 2000000,
    })
    api.toggle_wifi = AsyncMock(return_value={})
    api.set_wifi_password = AsyncMock(return_value={})
    api.set_wifi_channel = AsyncMock(return_value={})
    api.get_devices = AsyncMock(return_value={
        "status": {
            "AA:BB:CC:DD:EE:FF": {
                "Name": "MonPC",
                "Active": True,
                "IPAddress": "192.168.1.10",
            },
            "11:22:33:44:55:66": {
                "Name": "Smartphone",
                "Active": False,
                "IPAddress": "192.168.1.11",
            },
        }
    })
    api.get_device_by_mac = AsyncMock(return_value={
        "Name": "MonPC",
        "Active": True,
        "IPAddress": "192.168.1.10",
        "MACAddress": "AA:BB:CC:DD:EE:FF",
    })
    api.set_device_name = AsyncMock(return_value={})
    api.get_dhcp_leases = AsyncMock(return_value={
        "leases": [
            {"MACAddress": "AA:BB:CC:DD:EE:FF", "IPAddress": "192.168.1.10"},
        ]
    })
    api.get_static_addresses = AsyncMock(return_value={
        "reservations": []
    })
    api.add_dhcp_reservation = AsyncMock(return_value={})
    api.delete_dhcp_reservation = AsyncMock(return_value={})
    api.get_firewall_level = AsyncMock(return_value={"level": "Medium"})
    api.set_firewall_level = AsyncMock(return_value={})
    api.get_port_forwards = AsyncMock(return_value={"rules": []})
    api.add_port_forward = AsyncMock(return_value={"id": "rule_1"})
    api.delete_port_forward = AsyncMock(return_value={})
    api.get_dmz = AsyncMock(return_value={"Enable": False})
    api.set_dmz = AsyncMock(return_value={})
    api.get_voice_status = AsyncMock(return_value={"Status": "Registered"})
    api.get_call_history = AsyncMock(return_value={"calls": []})
    api.ping = AsyncMock(return_value={
        "host": "8.8.8.8",
        "packets_sent": 4,
        "packets_received": 4,
        "avg_time": 10.5,
    })
    api.traceroute = AsyncMock(return_value={"hops": []})
    api.speedtest = AsyncMock(return_value={
        "download": 100.0,
        "upload": 50.0,
    })
    api.reboot = AsyncMock(return_value={})
    api.change_password = AsyncMock(return_value={})

    # Context manager support
    api.__aenter__ = AsyncMock(return_value=api)
    api.__aexit__ = AsyncMock(return_value=None)

    return api


@pytest.fixture
def livebox_server():
    """Instance LiveboxMCPServer pour les tests."""
    return LiveboxMCPServer(host="192.168.1.1", password="test_password")


@pytest.fixture
def sample_device_info():
    """Exemple de réponse DeviceInfo."""
    return {
        "Manufacturer": "Sagemcom",
        "ModelName": "Livebox 6",
        "SerialNumber": "SG1234567890",
        "HardwareVersion": "SG_LB6_1.0",
        "SoftwareVersion": "SG40_sip-fr-6.62.12.1",
        "UpTime": 172800,
        "ExternalIPAddress": "90.1.2.3",
    }


@pytest.fixture
def sample_wifi_ssids():
    """Exemple de liste SSID."""
    return {
        "ssid": [
            {
                "SSID": "Livebox-ABC123",
                "Enable": True,
                "BSSID": "AA:BB:CC:DD:EE:FF",
                "SecurityMode": "WPA2-Personal",
            },
            {
                "SSID": "Livebox-ABC123-5GHz",
                "Enable": True,
                "BSSID": "AA:BB:CC:DD:EE:00",
                "SecurityMode": "WPA3-Personal",
            },
        ]
    }


@pytest.fixture
def sample_devices():
    """Exemple de liste d'appareils."""
    return {
        "status": {
            "AA:BB:CC:DD:EE:FF": {
                "Name": "PC-Bureau",
                "Active": True,
                "IPAddress": "192.168.1.10",
                "InterfaceType": "Ethernet",
                "FirstSeen": "2025-01-01T00:00:00",
            },
            "11:22:33:44:55:66": {
                "Name": "iPhone",
                "Active": True,
                "IPAddress": "192.168.1.20",
                "InterfaceType": "802.11",
                "FirstSeen": "2025-01-15T00:00:00",
            },
            "77:88:99:AA:BB:CC": {
                "Name": "Tablette",
                "Active": False,
                "IPAddress": "192.168.1.30",
                "InterfaceType": "802.11",
                "FirstSeen": "2025-01-10T00:00:00",
            },
        }
    }
