"""Tests pour le client API Livebox."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import aiohttp

from livebox_mcp.livebox_api import LiveboxAPI


class TestLiveboxAPIInit:
    """Tests d'initialisation de LiveboxAPI."""

    def test_init_default_host(self):
        """Test initialisation avec hôte par défaut."""
        api = LiveboxAPI(password="secret")
        assert api.host == "192.168.1.1"
        assert api.base_url == "http://192.168.1.1"
        assert api.password == "secret"
        assert api.session is None
        assert api.context_id is None

    def test_init_custom_host(self):
        """Test initialisation avec hôte personnalisé."""
        api = LiveboxAPI(host="192.168.2.1", password="secret")
        assert api.host == "192.168.2.1"
        assert api.base_url == "http://192.168.2.1"


class TestLiveboxAPIAuthentication:
    """Tests d'authentification."""

    @pytest.mark.asyncio
    async def test_authenticate_success(self, livebox_api):
        """Test authentification réussie."""
        mock_response = MagicMock()
        mock_response.json = AsyncMock(return_value={
            "status": 0,
            "data": {"contextID": "abc123", "groups": "http,admin"},
        })
        mock_response.raise_for_status = MagicMock()

        # Create proper async context manager mock
        mock_cm = AsyncMock()
        mock_cm.__aenter__.return_value = mock_response
        mock_cm.__aexit__.return_value = None

        mock_session = MagicMock()
        mock_session.post.return_value = mock_cm
        livebox_api.session = mock_session

        context_id = await livebox_api.authenticate()

        assert context_id == "abc123"
        assert livebox_api.context_id == "abc123"

    @pytest.mark.asyncio
    async def test_authenticate_failure(self, livebox_api):
        """Test échec d'authentification."""
        mock_response = MagicMock()
        mock_response.json = AsyncMock(return_value={
            "status": 1,
            "errors": [{"description": "Invalid password"}],
        })
        mock_response.raise_for_status = MagicMock()

        # Create proper async context manager mock
        mock_cm = AsyncMock()
        mock_cm.__aenter__.return_value = mock_response
        mock_cm.__aexit__.return_value = None

        mock_session = MagicMock()
        mock_session.post.return_value = mock_cm
        livebox_api.session = mock_session

        with pytest.raises(Exception, match="Authentification échouée"):
            await livebox_api.authenticate()


class TestLiveboxAPIContextManager:
    """Tests du context manager."""

    @pytest.mark.asyncio
    async def test_context_manager_enter(self):
        """Test entrée dans le context manager."""
        api = LiveboxAPI(password="test")

        with patch.object(api, "authenticate", new_callable=AsyncMock) as mock_auth:
            mock_auth.return_value = "ctx123"

            async with api as entered_api:
                assert entered_api is api
                assert api.session is not None
                mock_auth.assert_called_once()

    @pytest.mark.asyncio
    async def test_context_manager_exit(self):
        """Test sortie du context manager."""
        api = LiveboxAPI(password="test")

        with patch.object(api, "authenticate", new_callable=AsyncMock):
            async with api:
                session = api.session

            # Session should be closed
            assert session is not None


class TestLiveboxAPIRequest:
    """Tests de la méthode request générique via sysbus."""

    @pytest.mark.asyncio
    async def test_request_success(self, livebox_api):
        """Test requête réussie."""
        with patch.object(livebox_api, "sysbus_call", new_callable=AsyncMock) as mock_call:
            mock_call.return_value = {"key": "value"}

            result = await livebox_api.request("TestService", "testMethod", {"param": 1})

            assert result == {"key": "value"}
            mock_call.assert_called_once_with("TestService", "testMethod", {"param": 1})

    @pytest.mark.asyncio
    async def test_request_without_parameters(self, livebox_api):
        """Test requête sans paramètres."""
        with patch.object(livebox_api, "sysbus_call", new_callable=AsyncMock) as mock_call:
            mock_call.return_value = {}

            await livebox_api.request("TestService", "testMethod")

            mock_call.assert_called_once_with("TestService", "testMethod", None)

    @pytest.mark.asyncio
    async def test_request_api_error(self, livebox_api):
        """Test erreur API."""
        with patch.object(livebox_api, "sysbus_call", new_callable=AsyncMock) as mock_call:
            mock_call.side_effect = Exception("Erreur API: Method not found")

            with pytest.raises(Exception, match="Erreur API: Method not found"):
                await livebox_api.request("TestService", "badMethod")

    @pytest.mark.asyncio
    async def test_request_converts_service_path(self, livebox_api):
        """Test conversion du chemin service.sous-service."""
        with patch.object(livebox_api, "sysbus_call", new_callable=AsyncMock) as mock_call:
            mock_call.return_value = {}

            await livebox_api.request("NMC.Wifi", "get")

            # Le chemin doit être converti de NMC.Wifi à NMC/Wifi
            mock_call.assert_called_once_with("NMC/Wifi", "get", None)


class TestLiveboxAPISystemInfo:
    """Tests des méthodes système."""

    @pytest.mark.asyncio
    async def test_get_device_info(self, livebox_api, sample_device_info):
        """Test récupération infos système."""
        with patch.object(livebox_api, "request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = sample_device_info

            result = await livebox_api.get_device_info()

            assert result["ModelName"] == "Livebox 6"
            mock_req.assert_called_once_with("DeviceInfo", "get")

    @pytest.mark.asyncio
    async def test_get_time(self, livebox_api):
        """Test récupération heure système."""
        time_data = {"CurrentLocalTime": "2025-01-17T10:00:00"}

        with patch.object(livebox_api, "request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = time_data

            result = await livebox_api.get_time()

            assert "CurrentLocalTime" in result
            mock_req.assert_called_once_with("Time", "getTime")

    @pytest.mark.asyncio
    async def test_reboot(self, livebox_api):
        """Test redémarrage."""
        with patch.object(livebox_api, "request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = {}

            await livebox_api.reboot()

            mock_req.assert_called_once_with("DeviceInfo", "reboot")


class TestLiveboxAPIWAN:
    """Tests des méthodes WAN/Internet."""

    @pytest.mark.asyncio
    async def test_get_wan_status(self, livebox_api):
        """Test statut WAN."""
        wan_data = {"LinkState": "up", "IPAddress": "90.1.2.3"}

        with patch.object(livebox_api, "request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = wan_data

            result = await livebox_api.get_wan_status()

            assert result["LinkState"] == "up"
            mock_req.assert_called_once_with("NMC", "getWANStatus")

    @pytest.mark.asyncio
    async def test_get_traffic_stats(self, livebox_api):
        """Test statistiques trafic."""
        stats = {"BytesSent": 1000, "BytesReceived": 5000}

        with patch.object(livebox_api, "request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = stats

            result = await livebox_api.get_traffic_stats()

            assert result["BytesSent"] == 1000
            mock_req.assert_called_once_with("NMC", "getNetworkStatistics")


class TestLiveboxAPIWiFi:
    """Tests des méthodes WiFi."""

    @pytest.mark.asyncio
    async def test_get_wifi_status(self, livebox_api):
        """Test statut WiFi."""
        with patch.object(livebox_api, "request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = {"Enable": True, "Status": "Up"}

            result = await livebox_api.get_wifi_status()

            assert result["Enable"] is True
            mock_req.assert_called_once_with("NMC.Wifi", "get")

    @pytest.mark.asyncio
    async def test_toggle_wifi_enable(self, livebox_api):
        """Test activation WiFi."""
        with patch.object(livebox_api, "request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = {}

            await livebox_api.toggle_wifi(True)

            mock_req.assert_called_once_with("NMC.Wifi", "set", {"Enable": True})

    @pytest.mark.asyncio
    async def test_toggle_wifi_disable(self, livebox_api):
        """Test désactivation WiFi."""
        with patch.object(livebox_api, "request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = {}

            await livebox_api.toggle_wifi(False)

            mock_req.assert_called_once_with("NMC.Wifi", "set", {"Enable": False})

    @pytest.mark.asyncio
    async def test_get_ssid_list(self, livebox_api, sample_wifi_ssids):
        """Test liste SSID."""
        with patch.object(livebox_api, "request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = sample_wifi_ssids

            result = await livebox_api.get_ssid_list()

            assert len(result["ssid"]) == 2
            mock_req.assert_called_once_with(
                "NMC.Wifi.SSID", "getMIBs", {"mibs": "ssid"}
            )

    @pytest.mark.asyncio
    async def test_set_wifi_password(self, livebox_api):
        """Test modification mot de passe WiFi."""
        with patch.object(livebox_api, "request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = {}

            await livebox_api.set_wifi_password("Livebox-TEST", "newpassword123")

            mock_req.assert_called_once_with(
                "NMC.Wifi.SSID",
                "setSSIDInfo",
                {
                    "ssid_name": "Livebox-TEST",
                    "parameters": {"WPAPassPhrase": "newpassword123"},
                },
            )

    @pytest.mark.asyncio
    async def test_set_wifi_channel(self, livebox_api):
        """Test modification canal WiFi."""
        with patch.object(livebox_api, "request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = {}

            await livebox_api.set_wifi_channel("Livebox-TEST", 6)

            mock_req.assert_called_once_with(
                "NMC.Wifi.SSID",
                "setSSIDInfo",
                {
                    "ssid_name": "Livebox-TEST",
                    "parameters": {"Channel": 6},
                },
            )


class TestLiveboxAPIDevices:
    """Tests des méthodes appareils."""

    @pytest.mark.asyncio
    async def test_get_devices(self, livebox_api, sample_devices):
        """Test liste appareils."""
        with patch.object(livebox_api, "request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = sample_devices

            result = await livebox_api.get_devices()

            assert "status" in result
            assert len(result["status"]) == 3
            mock_req.assert_called_once_with("Hosts", "getDevices")

    @pytest.mark.asyncio
    async def test_get_device_by_mac(self, livebox_api):
        """Test récupération appareil par MAC."""
        device = {"Name": "MonPC", "Active": True}

        with patch.object(livebox_api, "request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = device

            result = await livebox_api.get_device_by_mac("AA:BB:CC:DD:EE:FF")

            assert result["Name"] == "MonPC"
            mock_req.assert_called_once_with(
                "Hosts", "getDevice", {"macaddress": "AA:BB:CC:DD:EE:FF"}
            )

    @pytest.mark.asyncio
    async def test_set_device_name(self, livebox_api):
        """Test modification nom appareil."""
        with patch.object(livebox_api, "request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = {}

            await livebox_api.set_device_name("AA:BB:CC:DD:EE:FF", "NouveauNom")

            mock_req.assert_called_once_with(
                "Hosts",
                "setDeviceName",
                {"macaddress": "AA:BB:CC:DD:EE:FF", "name": "NouveauNom"},
            )


class TestLiveboxAPIDHCP:
    """Tests des méthodes DHCP."""

    @pytest.mark.asyncio
    async def test_get_dhcp_leases(self, livebox_api):
        """Test liste baux DHCP."""
        with patch.object(livebox_api, "request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = {"leases": []}

            await livebox_api.get_dhcp_leases()

            mock_req.assert_called_once_with("DHCPv4.Server.Pool", "getLeases")

    @pytest.mark.asyncio
    async def test_get_static_addresses(self, livebox_api):
        """Test liste réservations statiques."""
        with patch.object(livebox_api, "request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = {"reservations": []}

            await livebox_api.get_static_addresses()

            mock_req.assert_called_once_with("DHCPv4.Server.Pool.StaticAddress", "get")

    @pytest.mark.asyncio
    async def test_add_dhcp_reservation(self, livebox_api):
        """Test ajout réservation DHCP."""
        with patch.object(livebox_api, "request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = {}

            await livebox_api.add_dhcp_reservation(
                "AA:BB:CC:DD:EE:FF", "192.168.1.100", "Serveur"
            )

            mock_req.assert_called_once_with(
                "DHCPv4.Server.Pool.StaticAddress",
                "add",
                {
                    "macaddress": "AA:BB:CC:DD:EE:FF",
                    "ipaddress": "192.168.1.100",
                    "name": "Serveur",
                },
            )

    @pytest.mark.asyncio
    async def test_delete_dhcp_reservation(self, livebox_api):
        """Test suppression réservation DHCP."""
        with patch.object(livebox_api, "request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = {}

            await livebox_api.delete_dhcp_reservation("AA:BB:CC:DD:EE:FF")

            mock_req.assert_called_once_with(
                "DHCPv4.Server.Pool.StaticAddress",
                "delete",
                {"macaddress": "AA:BB:CC:DD:EE:FF"},
            )


class TestLiveboxAPIFirewall:
    """Tests des méthodes pare-feu."""

    @pytest.mark.asyncio
    async def test_get_firewall_level(self, livebox_api):
        """Test niveau pare-feu."""
        with patch.object(livebox_api, "request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = {"level": "Medium"}

            result = await livebox_api.get_firewall_level()

            assert result["level"] == "Medium"
            mock_req.assert_called_once_with("Firewall", "getFirewallLevel")

    @pytest.mark.asyncio
    async def test_set_firewall_level(self, livebox_api):
        """Test modification niveau pare-feu."""
        with patch.object(livebox_api, "request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = {}

            await livebox_api.set_firewall_level("High")

            mock_req.assert_called_once_with(
                "Firewall", "setFirewallLevel", {"level": "High"}
            )

    @pytest.mark.asyncio
    async def test_get_port_forwards(self, livebox_api):
        """Test liste redirections ports."""
        with patch.object(livebox_api, "request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = {"rules": []}

            await livebox_api.get_port_forwards()

            mock_req.assert_called_once_with("Firewall.PortForwarding", "get")

    @pytest.mark.asyncio
    async def test_add_port_forward(self, livebox_api):
        """Test ajout redirection port."""
        with patch.object(livebox_api, "request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = {"id": "rule_1"}

            result = await livebox_api.add_port_forward(
                description="SSH",
                protocol="TCP",
                external_port=22,
                internal_port=22,
                internal_ip="192.168.1.100",
            )

            mock_req.assert_called_once_with(
                "Firewall.PortForwarding",
                "add",
                {
                    "Enable": True,
                    "Description": "SSH",
                    "Protocol": "TCP",
                    "ExternalPort": 22,
                    "InternalPort": 22,
                    "InternalIPAddress": "192.168.1.100",
                },
            )

    @pytest.mark.asyncio
    async def test_add_port_forward_with_source_prefix(self, livebox_api):
        """Test ajout redirection port avec source."""
        with patch.object(livebox_api, "request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = {}

            await livebox_api.add_port_forward(
                description="SSH",
                protocol="TCP",
                external_port=22,
                internal_port=22,
                internal_ip="192.168.1.100",
                source_prefix="10.0.0.0/8",
            )

            call_args = mock_req.call_args[0][2]
            assert call_args["SourcePrefix"] == "10.0.0.0/8"

    @pytest.mark.asyncio
    async def test_delete_port_forward(self, livebox_api):
        """Test suppression redirection port."""
        with patch.object(livebox_api, "request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = {}

            await livebox_api.delete_port_forward("rule_1")

            mock_req.assert_called_once_with(
                "Firewall.PortForwarding", "delete", {"id": "rule_1"}
            )

    @pytest.mark.asyncio
    async def test_get_dmz(self, livebox_api):
        """Test configuration DMZ."""
        with patch.object(livebox_api, "request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = {"Enable": False}

            result = await livebox_api.get_dmz()

            assert result["Enable"] is False
            mock_req.assert_called_once_with("Firewall.DMZ", "get")

    @pytest.mark.asyncio
    async def test_set_dmz_enable(self, livebox_api):
        """Test activation DMZ."""
        with patch.object(livebox_api, "request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = {}

            await livebox_api.set_dmz(True, "192.168.1.200")

            mock_req.assert_called_once_with(
                "Firewall.DMZ",
                "set",
                {"Enable": True, "IPAddress": "192.168.1.200"},
            )

    @pytest.mark.asyncio
    async def test_set_dmz_disable(self, livebox_api):
        """Test désactivation DMZ."""
        with patch.object(livebox_api, "request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = {}

            await livebox_api.set_dmz(False)

            mock_req.assert_called_once_with("Firewall.DMZ", "set", {"Enable": False})


class TestLiveboxAPIDiagnostics:
    """Tests des méthodes diagnostics."""

    @pytest.mark.asyncio
    async def test_ping(self, livebox_api):
        """Test ping."""
        with patch.object(livebox_api, "request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = {"packets_sent": 4, "packets_received": 4}

            result = await livebox_api.ping("8.8.8.8", count=4)

            mock_req.assert_called_once_with(
                "NMC.NetworkConfig", "ping", {"host": "8.8.8.8", "count": 4}
            )

    @pytest.mark.asyncio
    async def test_ping_default_count(self, livebox_api):
        """Test ping avec count par défaut."""
        with patch.object(livebox_api, "request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = {}

            await livebox_api.ping("google.com")

            call_args = mock_req.call_args[0][2]
            assert call_args["count"] == 4

    @pytest.mark.asyncio
    async def test_traceroute(self, livebox_api):
        """Test traceroute."""
        with patch.object(livebox_api, "request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = {"hops": []}

            await livebox_api.traceroute("google.com")

            mock_req.assert_called_once_with(
                "NMC.NetworkConfig", "traceroute", {"host": "google.com"}
            )

    @pytest.mark.asyncio
    async def test_speedtest(self, livebox_api):
        """Test speedtest."""
        with patch.object(livebox_api, "request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = {"download": 100.0, "upload": 50.0}

            result = await livebox_api.speedtest()

            assert result["download"] == 100.0
            mock_req.assert_called_once_with("NMC.NetworkConfig", "speedtest")


class TestLiveboxAPIVoice:
    """Tests des méthodes téléphonie."""

    @pytest.mark.asyncio
    async def test_get_voice_status(self, livebox_api):
        """Test statut téléphonie."""
        with patch.object(livebox_api, "request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = {"Status": "Registered"}

            result = await livebox_api.get_voice_status()

            assert result["Status"] == "Registered"
            mock_req.assert_called_once_with("VoiceService.VoiceProfile", "get")

    @pytest.mark.asyncio
    async def test_get_call_history(self, livebox_api):
        """Test historique appels."""
        with patch.object(livebox_api, "request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = {"calls": []}

            await livebox_api.get_call_history("missed")

            mock_req.assert_called_once_with(
                "VoiceService.VoiceProfile", "getCallList", {"type": "missed"}
            )

    @pytest.mark.asyncio
    async def test_get_call_history_default_type(self, livebox_api):
        """Test historique appels type par défaut."""
        with patch.object(livebox_api, "request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = {"calls": []}

            await livebox_api.get_call_history()

            call_args = mock_req.call_args[0][2]
            assert call_args["type"] == "all"


class TestLiveboxAPIUserManagement:
    """Tests gestion utilisateurs."""

    @pytest.mark.asyncio
    async def test_change_password(self, livebox_api):
        """Test changement mot de passe."""
        with patch.object(livebox_api, "request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = {}

            await livebox_api.change_password("admin", "oldpass", "newpass")

            mock_req.assert_called_once_with(
                "UserManagement",
                "setPassword",
                {
                    "username": "admin",
                    "currentpassword": "oldpass",
                    "newpassword": "newpass",
                },
            )
