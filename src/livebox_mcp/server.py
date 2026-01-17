"""Serveur MCP pour Livebox 6 Orange."""

import asyncio
import json
import logging
import os
from typing import Any, Optional, Sequence

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    EmbeddedResource,
    ImageContent,
    TextContent,
    Tool,
)

from .livebox_api import LiveboxAPI
from .tools import LIVEBOX_TOOLS

logger = logging.getLogger(__name__)


class LiveboxMCPServer:
    """Serveur MCP pour Livebox 6."""

    def __init__(self, host: str = "192.168.1.1", password: str = "") -> None:
        self.host = host
        self.password = password
        self.server = Server("livebox-mcp")
        self.api: Optional[LiveboxAPI] = None

        self._setup_handlers()

    def _setup_handlers(self) -> None:
        """Configure les handlers MCP."""

        @self.server.list_tools()
        async def list_tools() -> list[Tool]:
            """Liste tous les outils disponibles."""
            return LIVEBOX_TOOLS

        @self.server.call_tool()
        async def call_tool(
            name: str, arguments: dict[str, Any]
        ) -> Sequence[TextContent | ImageContent | EmbeddedResource]:
            """Exécute un outil."""
            try:
                if not self.api:
                    self.api = LiveboxAPI(self.host, self.password)
                    await self.api.__aenter__()

                result = await self._handle_tool(name, arguments)

                return [
                    TextContent(
                        type="text",
                        text=json.dumps(result, indent=2, ensure_ascii=False),
                    )
                ]

            except Exception as e:
                logger.exception(f"Erreur outil {name}")
                return [
                    TextContent(
                        type="text",
                        text=json.dumps(
                            {"error": str(e), "tool": name},
                            ensure_ascii=False,
                        ),
                    )
                ]

    async def _handle_tool(self, name: str, args: dict[str, Any]) -> Any:
        """Route l'appel d'outil vers la bonne méthode API."""
        if self.api is None:
            raise Exception("API non initialisée")

        # === Informations système ===
        if name == "livebox_get_info":
            return await self.api.get_device_info()

        elif name == "livebox_get_time":
            return await self.api.get_time()

        # === Connexion Internet ===
        elif name == "livebox_get_wan_status":
            return await self.api.get_wan_status()

        elif name == "livebox_get_traffic_stats":
            return await self.api.get_traffic_stats()

        # === WiFi ===
        elif name == "livebox_get_wifi_status":
            status = await self.api.get_wifi_status()
            ssids = await self.api.get_ssid_list()
            return {"status": status, "ssids": ssids}

        elif name == "livebox_get_wifi_stats":
            return await self.api.get_wifi_stats()

        elif name == "livebox_toggle_wifi":
            return await self.api.toggle_wifi(args["enable"])

        elif name == "livebox_set_wifi_password":
            return await self.api.set_wifi_password(
                args["ssid_name"],
                args["password"],
            )

        elif name == "livebox_set_wifi_channel":
            return await self.api.set_wifi_channel(
                args["ssid_name"],
                args["channel"],
            )

        # === Appareils connectés ===
        elif name == "livebox_list_devices":
            devices = await self.api.get_devices()
            if args.get("active_only"):
                if isinstance(devices, dict) and "status" in devices:
                    devices["status"] = {
                        k: v
                        for k, v in devices.get("status", {}).items()
                        if isinstance(v, dict) and v.get("Active")
                    }
            return devices

        elif name == "livebox_get_device_info":
            return await self.api.get_device_by_mac(args["mac_address"])

        elif name == "livebox_set_device_name":
            return await self.api.set_device_name(
                args["mac_address"],
                args["name"],
            )

        # === DHCP ===
        elif name == "livebox_get_dhcp_leases":
            return await self.api.get_dhcp_leases()

        elif name == "livebox_get_dhcp_reservations":
            return await self.api.get_static_addresses()

        elif name == "livebox_add_dhcp_reservation":
            return await self.api.add_dhcp_reservation(
                args["mac_address"],
                args["ip_address"],
                args["name"],
            )

        elif name == "livebox_delete_dhcp_reservation":
            return await self.api.delete_dhcp_reservation(args["mac_address"])

        # === Pare-feu ===
        elif name == "livebox_get_firewall_status":
            return await self.api.get_firewall_level()

        elif name == "livebox_set_firewall_level":
            return await self.api.set_firewall_level(args["level"])

        elif name == "livebox_list_port_forwards":
            return await self.api.get_port_forwards()

        elif name == "livebox_add_port_forward":
            return await self.api.add_port_forward(
                args["description"],
                args["protocol"],
                args["external_port"],
                args["internal_port"],
                args["internal_ip"],
                args.get("source_prefix", ""),
            )

        elif name == "livebox_delete_port_forward":
            return await self.api.delete_port_forward(args["rule_id"])

        elif name == "livebox_get_dmz":
            return await self.api.get_dmz()

        elif name == "livebox_set_dmz":
            return await self.api.set_dmz(
                args["enable"],
                args.get("ip_address", ""),
            )

        # === Téléphonie ===
        elif name == "livebox_get_voice_status":
            return await self.api.get_voice_status()

        elif name == "livebox_get_call_history":
            return await self.api.get_call_history(
                args.get("call_type", "all"),
            )

        # === Diagnostics ===
        elif name == "livebox_ping":
            return await self.api.ping(
                args["host"],
                args.get("count", 4),
            )

        elif name == "livebox_traceroute":
            return await self.api.traceroute(args["host"])

        elif name == "livebox_speedtest":
            return await self.api.speedtest()

        # === Système ===
        elif name == "livebox_reboot":
            if not args.get("confirm"):
                return {
                    "error": "Confirmation requise",
                    "message": "Définissez confirm=true pour redémarrer la Livebox",
                }
            return await self.api.reboot()

        elif name == "livebox_change_password":
            return await self.api.change_password(
                "admin",
                args["current_password"],
                args["new_password"],
            )

        else:
            raise ValueError(f"Outil inconnu: {name}")

    async def run(self) -> None:
        """Lance le serveur MCP."""
        async with stdio_server() as (read_stream, write_stream):
            await self.server.run(
                read_stream,
                write_stream,
                self.server.create_initialization_options(),
            )

    async def cleanup(self) -> None:
        """Nettoyage des ressources."""
        if self.api:
            await self.api.__aexit__(None, None, None)


def main() -> None:
    """Point d'entrée principal."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    host = os.getenv("LIVEBOX_HOST", "192.168.1.1")
    password = os.getenv("LIVEBOX_PASSWORD", "")

    if not password:
        logger.warning("LIVEBOX_PASSWORD non défini dans l'environnement")

    server = LiveboxMCPServer(host, password)

    async def run_server() -> None:
        try:
            await server.run()
        finally:
            await server.cleanup()

    asyncio.run(run_server())


if __name__ == "__main__":
    main()
