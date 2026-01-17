"""Tests pour le serveur MCP Livebox."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import json

from livebox_mcp.server import LiveboxMCPServer, main
from livebox_mcp.tools import LIVEBOX_TOOLS


class TestLiveboxMCPServerInit:
    """Tests d'initialisation du serveur."""

    def test_init_default_values(self):
        """Test initialisation valeurs par défaut."""
        server = LiveboxMCPServer()
        assert server.host == "192.168.1.1"
        assert server.password == ""
        assert server.api is None

    def test_init_custom_values(self):
        """Test initialisation valeurs personnalisées."""
        server = LiveboxMCPServer(host="192.168.2.1", password="secret")
        assert server.host == "192.168.2.1"
        assert server.password == "secret"

    def test_server_name(self):
        """Test nom du serveur MCP."""
        server = LiveboxMCPServer()
        assert server.server.name == "livebox-mcp"


class TestLiveboxMCPServerHandlers:
    """Tests des handlers MCP."""

    def test_tools_registered(self, livebox_server):
        """Test que les outils sont enregistrés."""
        # Vérifie que le serveur a bien les outils configurés
        assert len(LIVEBOX_TOOLS) > 0

    def test_expected_tools_in_list(self):
        """Test présence des outils attendus."""
        tool_names = [t.name for t in LIVEBOX_TOOLS]

        expected_tools = [
            "livebox_get_info",
            "livebox_get_wan_status",
            "livebox_get_wifi_status",
            "livebox_list_devices",
            "livebox_ping",
            "livebox_reboot",
        ]

        for tool in expected_tools:
            assert tool in tool_names


class TestLiveboxMCPServerToolHandling:
    """Tests de l'exécution des outils."""

    @pytest.mark.asyncio
    async def test_handle_tool_get_info(self, livebox_server, mock_livebox_api):
        """Test outil livebox_get_info."""
        livebox_server.api = mock_livebox_api

        result = await livebox_server._handle_tool("livebox_get_info", {})

        mock_livebox_api.get_device_info.assert_called_once()
        assert "ModelName" in result

    @pytest.mark.asyncio
    async def test_handle_tool_get_time(self, livebox_server, mock_livebox_api):
        """Test outil livebox_get_time."""
        livebox_server.api = mock_livebox_api

        result = await livebox_server._handle_tool("livebox_get_time", {})

        mock_livebox_api.get_time.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_tool_get_wan_status(self, livebox_server, mock_livebox_api):
        """Test outil livebox_get_wan_status."""
        livebox_server.api = mock_livebox_api

        result = await livebox_server._handle_tool("livebox_get_wan_status", {})

        mock_livebox_api.get_wan_status.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_tool_get_traffic_stats(self, livebox_server, mock_livebox_api):
        """Test outil livebox_get_traffic_stats."""
        livebox_server.api = mock_livebox_api

        result = await livebox_server._handle_tool("livebox_get_traffic_stats", {})

        mock_livebox_api.get_traffic_stats.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_tool_get_wifi_status(self, livebox_server, mock_livebox_api):
        """Test outil livebox_get_wifi_status."""
        livebox_server.api = mock_livebox_api

        result = await livebox_server._handle_tool("livebox_get_wifi_status", {})

        mock_livebox_api.get_wifi_status.assert_called_once()
        mock_livebox_api.get_ssid_list.assert_called_once()
        assert "status" in result
        assert "ssids" in result

    @pytest.mark.asyncio
    async def test_handle_tool_get_wifi_stats(self, livebox_server, mock_livebox_api):
        """Test outil livebox_get_wifi_stats."""
        livebox_server.api = mock_livebox_api

        result = await livebox_server._handle_tool("livebox_get_wifi_stats", {})

        mock_livebox_api.get_wifi_stats.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_tool_toggle_wifi(self, livebox_server, mock_livebox_api):
        """Test outil livebox_toggle_wifi."""
        livebox_server.api = mock_livebox_api

        await livebox_server._handle_tool("livebox_toggle_wifi", {"enable": True})

        mock_livebox_api.toggle_wifi.assert_called_once_with(True)

    @pytest.mark.asyncio
    async def test_handle_tool_set_wifi_password(self, livebox_server, mock_livebox_api):
        """Test outil livebox_set_wifi_password."""
        livebox_server.api = mock_livebox_api

        await livebox_server._handle_tool(
            "livebox_set_wifi_password",
            {"ssid_name": "Livebox-TEST", "password": "newpass123"},
        )

        mock_livebox_api.set_wifi_password.assert_called_once_with(
            "Livebox-TEST", "newpass123"
        )

    @pytest.mark.asyncio
    async def test_handle_tool_set_wifi_channel(self, livebox_server, mock_livebox_api):
        """Test outil livebox_set_wifi_channel."""
        livebox_server.api = mock_livebox_api

        await livebox_server._handle_tool(
            "livebox_set_wifi_channel",
            {"ssid_name": "Livebox-TEST", "channel": 6},
        )

        mock_livebox_api.set_wifi_channel.assert_called_once_with("Livebox-TEST", 6)

    @pytest.mark.asyncio
    async def test_handle_tool_list_devices(self, livebox_server, mock_livebox_api):
        """Test outil livebox_list_devices."""
        livebox_server.api = mock_livebox_api

        result = await livebox_server._handle_tool("livebox_list_devices", {})

        mock_livebox_api.get_devices.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_tool_list_devices_active_only(
        self, livebox_server, mock_livebox_api
    ):
        """Test outil livebox_list_devices avec active_only."""
        livebox_server.api = mock_livebox_api

        result = await livebox_server._handle_tool(
            "livebox_list_devices", {"active_only": True}
        )

        # Should filter to only active devices
        assert all(
            v.get("Active", False)
            for v in result.get("status", {}).values()
            if isinstance(v, dict)
        )

    @pytest.mark.asyncio
    async def test_handle_tool_get_device_info(self, livebox_server, mock_livebox_api):
        """Test outil livebox_get_device_info."""
        livebox_server.api = mock_livebox_api

        await livebox_server._handle_tool(
            "livebox_get_device_info", {"mac_address": "AA:BB:CC:DD:EE:FF"}
        )

        mock_livebox_api.get_device_by_mac.assert_called_once_with("AA:BB:CC:DD:EE:FF")

    @pytest.mark.asyncio
    async def test_handle_tool_set_device_name(self, livebox_server, mock_livebox_api):
        """Test outil livebox_set_device_name."""
        livebox_server.api = mock_livebox_api

        await livebox_server._handle_tool(
            "livebox_set_device_name",
            {"mac_address": "AA:BB:CC:DD:EE:FF", "name": "NouveauNom"},
        )

        mock_livebox_api.set_device_name.assert_called_once_with(
            "AA:BB:CC:DD:EE:FF", "NouveauNom"
        )

    @pytest.mark.asyncio
    async def test_handle_tool_get_dhcp_leases(self, livebox_server, mock_livebox_api):
        """Test outil livebox_get_dhcp_leases."""
        livebox_server.api = mock_livebox_api

        await livebox_server._handle_tool("livebox_get_dhcp_leases", {})

        mock_livebox_api.get_dhcp_leases.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_tool_get_dhcp_reservations(
        self, livebox_server, mock_livebox_api
    ):
        """Test outil livebox_get_dhcp_reservations."""
        livebox_server.api = mock_livebox_api

        await livebox_server._handle_tool("livebox_get_dhcp_reservations", {})

        mock_livebox_api.get_static_addresses.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_tool_add_dhcp_reservation(
        self, livebox_server, mock_livebox_api
    ):
        """Test outil livebox_add_dhcp_reservation."""
        livebox_server.api = mock_livebox_api

        await livebox_server._handle_tool(
            "livebox_add_dhcp_reservation",
            {
                "mac_address": "AA:BB:CC:DD:EE:FF",
                "ip_address": "192.168.1.100",
                "name": "Serveur",
            },
        )

        mock_livebox_api.add_dhcp_reservation.assert_called_once_with(
            "AA:BB:CC:DD:EE:FF", "192.168.1.100", "Serveur"
        )

    @pytest.mark.asyncio
    async def test_handle_tool_delete_dhcp_reservation(
        self, livebox_server, mock_livebox_api
    ):
        """Test outil livebox_delete_dhcp_reservation."""
        livebox_server.api = mock_livebox_api

        await livebox_server._handle_tool(
            "livebox_delete_dhcp_reservation", {"mac_address": "AA:BB:CC:DD:EE:FF"}
        )

        mock_livebox_api.delete_dhcp_reservation.assert_called_once_with(
            "AA:BB:CC:DD:EE:FF"
        )

    @pytest.mark.asyncio
    async def test_handle_tool_get_firewall_status(
        self, livebox_server, mock_livebox_api
    ):
        """Test outil livebox_get_firewall_status."""
        livebox_server.api = mock_livebox_api

        await livebox_server._handle_tool("livebox_get_firewall_status", {})

        mock_livebox_api.get_firewall_level.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_tool_set_firewall_level(
        self, livebox_server, mock_livebox_api
    ):
        """Test outil livebox_set_firewall_level."""
        livebox_server.api = mock_livebox_api

        await livebox_server._handle_tool(
            "livebox_set_firewall_level", {"level": "High"}
        )

        mock_livebox_api.set_firewall_level.assert_called_once_with("High")

    @pytest.mark.asyncio
    async def test_handle_tool_list_port_forwards(
        self, livebox_server, mock_livebox_api
    ):
        """Test outil livebox_list_port_forwards."""
        livebox_server.api = mock_livebox_api

        await livebox_server._handle_tool("livebox_list_port_forwards", {})

        mock_livebox_api.get_port_forwards.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_tool_add_port_forward(self, livebox_server, mock_livebox_api):
        """Test outil livebox_add_port_forward."""
        livebox_server.api = mock_livebox_api

        await livebox_server._handle_tool(
            "livebox_add_port_forward",
            {
                "description": "SSH",
                "protocol": "TCP",
                "external_port": 22,
                "internal_port": 22,
                "internal_ip": "192.168.1.100",
            },
        )

        mock_livebox_api.add_port_forward.assert_called_once_with(
            "SSH", "TCP", 22, 22, "192.168.1.100", ""
        )

    @pytest.mark.asyncio
    async def test_handle_tool_add_port_forward_with_source(
        self, livebox_server, mock_livebox_api
    ):
        """Test outil livebox_add_port_forward avec source_prefix."""
        livebox_server.api = mock_livebox_api

        await livebox_server._handle_tool(
            "livebox_add_port_forward",
            {
                "description": "SSH",
                "protocol": "TCP",
                "external_port": 22,
                "internal_port": 22,
                "internal_ip": "192.168.1.100",
                "source_prefix": "10.0.0.0/8",
            },
        )

        mock_livebox_api.add_port_forward.assert_called_once_with(
            "SSH", "TCP", 22, 22, "192.168.1.100", "10.0.0.0/8"
        )

    @pytest.mark.asyncio
    async def test_handle_tool_delete_port_forward(
        self, livebox_server, mock_livebox_api
    ):
        """Test outil livebox_delete_port_forward."""
        livebox_server.api = mock_livebox_api

        await livebox_server._handle_tool(
            "livebox_delete_port_forward", {"rule_id": "rule_1"}
        )

        mock_livebox_api.delete_port_forward.assert_called_once_with("rule_1")

    @pytest.mark.asyncio
    async def test_handle_tool_get_dmz(self, livebox_server, mock_livebox_api):
        """Test outil livebox_get_dmz."""
        livebox_server.api = mock_livebox_api

        await livebox_server._handle_tool("livebox_get_dmz", {})

        mock_livebox_api.get_dmz.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_tool_set_dmz(self, livebox_server, mock_livebox_api):
        """Test outil livebox_set_dmz."""
        livebox_server.api = mock_livebox_api

        await livebox_server._handle_tool(
            "livebox_set_dmz", {"enable": True, "ip_address": "192.168.1.200"}
        )

        mock_livebox_api.set_dmz.assert_called_once_with(True, "192.168.1.200")

    @pytest.mark.asyncio
    async def test_handle_tool_get_voice_status(self, livebox_server, mock_livebox_api):
        """Test outil livebox_get_voice_status."""
        livebox_server.api = mock_livebox_api

        await livebox_server._handle_tool("livebox_get_voice_status", {})

        mock_livebox_api.get_voice_status.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_tool_get_call_history(self, livebox_server, mock_livebox_api):
        """Test outil livebox_get_call_history."""
        livebox_server.api = mock_livebox_api

        await livebox_server._handle_tool(
            "livebox_get_call_history", {"call_type": "missed"}
        )

        mock_livebox_api.get_call_history.assert_called_once_with("missed")

    @pytest.mark.asyncio
    async def test_handle_tool_ping(self, livebox_server, mock_livebox_api):
        """Test outil livebox_ping."""
        livebox_server.api = mock_livebox_api

        await livebox_server._handle_tool("livebox_ping", {"host": "8.8.8.8"})

        mock_livebox_api.ping.assert_called_once_with("8.8.8.8", 4)

    @pytest.mark.asyncio
    async def test_handle_tool_ping_custom_count(
        self, livebox_server, mock_livebox_api
    ):
        """Test outil livebox_ping avec count personnalisé."""
        livebox_server.api = mock_livebox_api

        await livebox_server._handle_tool(
            "livebox_ping", {"host": "8.8.8.8", "count": 10}
        )

        mock_livebox_api.ping.assert_called_once_with("8.8.8.8", 10)

    @pytest.mark.asyncio
    async def test_handle_tool_traceroute(self, livebox_server, mock_livebox_api):
        """Test outil livebox_traceroute."""
        livebox_server.api = mock_livebox_api

        await livebox_server._handle_tool("livebox_traceroute", {"host": "google.com"})

        mock_livebox_api.traceroute.assert_called_once_with("google.com")

    @pytest.mark.asyncio
    async def test_handle_tool_speedtest(self, livebox_server, mock_livebox_api):
        """Test outil livebox_speedtest."""
        livebox_server.api = mock_livebox_api

        await livebox_server._handle_tool("livebox_speedtest", {})

        mock_livebox_api.speedtest.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_tool_reboot_without_confirm(
        self, livebox_server, mock_livebox_api
    ):
        """Test outil livebox_reboot sans confirmation."""
        livebox_server.api = mock_livebox_api

        result = await livebox_server._handle_tool("livebox_reboot", {"confirm": False})

        assert "error" in result
        mock_livebox_api.reboot.assert_not_called()

    @pytest.mark.asyncio
    async def test_handle_tool_reboot_with_confirm(
        self, livebox_server, mock_livebox_api
    ):
        """Test outil livebox_reboot avec confirmation."""
        livebox_server.api = mock_livebox_api

        await livebox_server._handle_tool("livebox_reboot", {"confirm": True})

        mock_livebox_api.reboot.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_tool_change_password(self, livebox_server, mock_livebox_api):
        """Test outil livebox_change_password."""
        livebox_server.api = mock_livebox_api

        await livebox_server._handle_tool(
            "livebox_change_password",
            {"current_password": "oldpass", "new_password": "newpass"},
        )

        mock_livebox_api.change_password.assert_called_once_with(
            "admin", "oldpass", "newpass"
        )

    @pytest.mark.asyncio
    async def test_handle_tool_unknown(self, livebox_server, mock_livebox_api):
        """Test outil inconnu."""
        livebox_server.api = mock_livebox_api

        with pytest.raises(ValueError, match="Outil inconnu"):
            await livebox_server._handle_tool("unknown_tool", {})

    @pytest.mark.asyncio
    async def test_handle_tool_api_not_initialized(self, livebox_server):
        """Test appel outil avec API non initialisée."""
        livebox_server.api = None

        with pytest.raises(Exception, match="API non initialisée"):
            await livebox_server._handle_tool("livebox_get_info", {})


class TestLiveboxMCPServerCleanup:
    """Tests de nettoyage des ressources."""

    @pytest.mark.asyncio
    async def test_cleanup_with_api(self, livebox_server, mock_livebox_api):
        """Test cleanup avec API active."""
        livebox_server.api = mock_livebox_api

        await livebox_server.cleanup()

        mock_livebox_api.__aexit__.assert_called_once()

    @pytest.mark.asyncio
    async def test_cleanup_without_api(self, livebox_server):
        """Test cleanup sans API."""
        livebox_server.api = None

        # Should not raise
        await livebox_server.cleanup()


class TestMainFunction:
    """Tests de la fonction main."""

    def test_main_with_env_vars(self):
        """Test main avec variables d'environnement."""
        with patch.dict(
            "os.environ",
            {"LIVEBOX_HOST": "10.0.0.1", "LIVEBOX_PASSWORD": "secret"},
        ):
            with patch("livebox_mcp.server.asyncio.run") as mock_run:
                main()
                mock_run.assert_called_once()

    def test_main_default_host(self):
        """Test main avec hôte par défaut."""
        with patch.dict("os.environ", {"LIVEBOX_PASSWORD": "secret"}, clear=True):
            with patch("livebox_mcp.server.asyncio.run") as mock_run:
                main()
                mock_run.assert_called_once()

    def test_main_missing_password_warning(self):
        """Test warning si mot de passe manquant."""
        with patch.dict("os.environ", {}, clear=True):
            with patch("livebox_mcp.server.asyncio.run"):
                with patch("livebox_mcp.server.logger.warning") as mock_warn:
                    main()
                    mock_warn.assert_called_once()
