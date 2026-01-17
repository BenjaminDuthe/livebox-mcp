"""Tests pour les définitions d'outils MCP."""

import pytest
from mcp.types import Tool

from livebox_mcp.tools import LIVEBOX_TOOLS


class TestToolsDefinitions:
    """Tests des définitions d'outils."""

    def test_livebox_tools_is_list(self):
        """Test que LIVEBOX_TOOLS est une liste."""
        assert isinstance(LIVEBOX_TOOLS, list)

    def test_livebox_tools_not_empty(self):
        """Test que la liste n'est pas vide."""
        assert len(LIVEBOX_TOOLS) > 0

    def test_all_tools_are_tool_instances(self):
        """Test que tous les éléments sont des instances Tool."""
        for tool in LIVEBOX_TOOLS:
            assert isinstance(tool, Tool)

    def test_all_tools_have_name(self):
        """Test que tous les outils ont un nom."""
        for tool in LIVEBOX_TOOLS:
            assert tool.name is not None
            assert len(tool.name) > 0

    def test_all_tools_have_description(self):
        """Test que tous les outils ont une description."""
        for tool in LIVEBOX_TOOLS:
            assert tool.description is not None
            assert len(tool.description) > 0

    def test_all_tools_have_input_schema(self):
        """Test que tous les outils ont un schéma d'entrée."""
        for tool in LIVEBOX_TOOLS:
            assert tool.inputSchema is not None
            assert isinstance(tool.inputSchema, dict)

    def test_all_tool_names_start_with_livebox(self):
        """Test que tous les noms commencent par 'livebox_'."""
        for tool in LIVEBOX_TOOLS:
            assert tool.name.startswith("livebox_"), f"{tool.name} ne commence pas par 'livebox_'"

    def test_all_tool_names_unique(self):
        """Test que tous les noms sont uniques."""
        names = [tool.name for tool in LIVEBOX_TOOLS]
        assert len(names) == len(set(names)), "Noms d'outils en double détectés"


class TestToolSchemas:
    """Tests des schémas JSON des outils."""

    def test_input_schema_has_type(self):
        """Test que tous les schémas ont un type."""
        for tool in LIVEBOX_TOOLS:
            assert "type" in tool.inputSchema
            assert tool.inputSchema["type"] == "object"

    def test_input_schema_has_properties(self):
        """Test que tous les schémas ont des propriétés."""
        for tool in LIVEBOX_TOOLS:
            assert "properties" in tool.inputSchema

    def test_input_schema_has_required(self):
        """Test que tous les schémas ont une liste required."""
        for tool in LIVEBOX_TOOLS:
            assert "required" in tool.inputSchema
            assert isinstance(tool.inputSchema["required"], list)

    def test_required_properties_exist(self):
        """Test que les propriétés requises existent."""
        for tool in LIVEBOX_TOOLS:
            required = tool.inputSchema.get("required", [])
            properties = tool.inputSchema.get("properties", {})
            for req in required:
                assert req in properties, (
                    f"Propriété requise '{req}' manquante dans {tool.name}"
                )


class TestSpecificTools:
    """Tests pour des outils spécifiques."""

    def _get_tool(self, name: str) -> Tool:
        """Récupère un outil par son nom."""
        for tool in LIVEBOX_TOOLS:
            if tool.name == name:
                return tool
        raise ValueError(f"Outil '{name}' non trouvé")

    def test_livebox_get_info(self):
        """Test définition livebox_get_info."""
        tool = self._get_tool("livebox_get_info")
        assert tool.inputSchema["required"] == []

    def test_livebox_toggle_wifi(self):
        """Test définition livebox_toggle_wifi."""
        tool = self._get_tool("livebox_toggle_wifi")
        assert "enable" in tool.inputSchema["required"]
        assert tool.inputSchema["properties"]["enable"]["type"] == "boolean"

    def test_livebox_set_wifi_password(self):
        """Test définition livebox_set_wifi_password."""
        tool = self._get_tool("livebox_set_wifi_password")
        assert "ssid_name" in tool.inputSchema["required"]
        assert "password" in tool.inputSchema["required"]

    def test_livebox_list_devices(self):
        """Test définition livebox_list_devices."""
        tool = self._get_tool("livebox_list_devices")
        assert "active_only" in tool.inputSchema["properties"]
        assert "active_only" not in tool.inputSchema["required"]

    def test_livebox_get_device_info(self):
        """Test définition livebox_get_device_info."""
        tool = self._get_tool("livebox_get_device_info")
        assert "mac_address" in tool.inputSchema["required"]

    def test_livebox_add_dhcp_reservation(self):
        """Test définition livebox_add_dhcp_reservation."""
        tool = self._get_tool("livebox_add_dhcp_reservation")
        required = tool.inputSchema["required"]
        assert "mac_address" in required
        assert "ip_address" in required
        assert "name" in required

    def test_livebox_set_firewall_level(self):
        """Test définition livebox_set_firewall_level."""
        tool = self._get_tool("livebox_set_firewall_level")
        level_schema = tool.inputSchema["properties"]["level"]
        assert "enum" in level_schema
        assert "High" in level_schema["enum"]
        assert "Medium" in level_schema["enum"]
        assert "Low" in level_schema["enum"]

    def test_livebox_add_port_forward(self):
        """Test définition livebox_add_port_forward."""
        tool = self._get_tool("livebox_add_port_forward")
        required = tool.inputSchema["required"]
        assert "description" in required
        assert "protocol" in required
        assert "external_port" in required
        assert "internal_port" in required
        assert "internal_ip" in required
        # source_prefix est optionnel
        assert "source_prefix" not in required

        protocol_schema = tool.inputSchema["properties"]["protocol"]
        assert "enum" in protocol_schema
        assert "TCP" in protocol_schema["enum"]
        assert "UDP" in protocol_schema["enum"]

    def test_livebox_ping(self):
        """Test définition livebox_ping."""
        tool = self._get_tool("livebox_ping")
        assert "host" in tool.inputSchema["required"]
        # count est optionnel
        assert "count" not in tool.inputSchema["required"]
        assert "count" in tool.inputSchema["properties"]

    def test_livebox_reboot(self):
        """Test définition livebox_reboot."""
        tool = self._get_tool("livebox_reboot")
        assert "confirm" in tool.inputSchema["required"]
        assert tool.inputSchema["properties"]["confirm"]["type"] == "boolean"
        # Vérifier que la description mentionne le danger
        assert "ATTENTION" in tool.description or "indisponible" in tool.description

    def test_livebox_get_call_history(self):
        """Test définition livebox_get_call_history."""
        tool = self._get_tool("livebox_get_call_history")
        call_type_schema = tool.inputSchema["properties"]["call_type"]
        assert "enum" in call_type_schema
        assert "all" in call_type_schema["enum"]
        assert "received" in call_type_schema["enum"]
        assert "missed" in call_type_schema["enum"]
        assert "dialed" in call_type_schema["enum"]


class TestToolCategories:
    """Tests pour vérifier que toutes les catégories d'outils sont présentes."""

    def test_system_tools_exist(self):
        """Test présence outils système."""
        names = [t.name for t in LIVEBOX_TOOLS]
        assert "livebox_get_info" in names
        assert "livebox_get_time" in names
        assert "livebox_reboot" in names

    def test_wan_tools_exist(self):
        """Test présence outils WAN."""
        names = [t.name for t in LIVEBOX_TOOLS]
        assert "livebox_get_wan_status" in names
        assert "livebox_get_traffic_stats" in names

    def test_wifi_tools_exist(self):
        """Test présence outils WiFi."""
        names = [t.name for t in LIVEBOX_TOOLS]
        assert "livebox_get_wifi_status" in names
        assert "livebox_toggle_wifi" in names
        assert "livebox_set_wifi_password" in names
        assert "livebox_set_wifi_channel" in names

    def test_device_tools_exist(self):
        """Test présence outils appareils."""
        names = [t.name for t in LIVEBOX_TOOLS]
        assert "livebox_list_devices" in names
        assert "livebox_get_device_info" in names
        assert "livebox_set_device_name" in names

    def test_dhcp_tools_exist(self):
        """Test présence outils DHCP."""
        names = [t.name for t in LIVEBOX_TOOLS]
        assert "livebox_get_dhcp_leases" in names
        assert "livebox_get_dhcp_reservations" in names
        assert "livebox_add_dhcp_reservation" in names
        assert "livebox_delete_dhcp_reservation" in names

    def test_firewall_tools_exist(self):
        """Test présence outils pare-feu."""
        names = [t.name for t in LIVEBOX_TOOLS]
        assert "livebox_get_firewall_status" in names
        assert "livebox_set_firewall_level" in names
        assert "livebox_list_port_forwards" in names
        assert "livebox_add_port_forward" in names
        assert "livebox_delete_port_forward" in names
        assert "livebox_get_dmz" in names
        assert "livebox_set_dmz" in names

    def test_voice_tools_exist(self):
        """Test présence outils téléphonie."""
        names = [t.name for t in LIVEBOX_TOOLS]
        assert "livebox_get_voice_status" in names
        assert "livebox_get_call_history" in names

    def test_diagnostic_tools_exist(self):
        """Test présence outils diagnostics."""
        names = [t.name for t in LIVEBOX_TOOLS]
        assert "livebox_ping" in names
        assert "livebox_traceroute" in names
        assert "livebox_speedtest" in names


class TestToolCount:
    """Tests du nombre d'outils."""

    def test_expected_tool_count(self):
        """Test nombre d'outils attendu."""
        # 30 outils au total selon l'implémentation
        assert len(LIVEBOX_TOOLS) == 30, (
            f"Nombre d'outils inattendu: {len(LIVEBOX_TOOLS)}"
        )
