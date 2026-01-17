"""Client API asynchrone pour Livebox 6 Orange.

Note: Orange a restreint l'accès API sur la Livebox 6.
Seuls quelques services sont accessibles:
- DeviceInfo: informations système
- NMC: état WAN/connexion
- UserInterface: langue, état

Les services WiFi, Hosts, DHCP, Firewall, etc. sont bloqués.
"""

import aiohttp
import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)


class LiveboxAPI:
    """Client API pour Livebox 6 via sysbus avec authentification X-Sah-Login."""

    def __init__(self, host: str = "192.168.1.1", password: str = "") -> None:
        self.host = host
        self.base_url = f"http://{host}"
        self.password = password
        self.session: Optional[aiohttp.ClientSession] = None
        self.context_id: Optional[str] = None

    async def __aenter__(self) -> "LiveboxAPI":
        """Context manager entry."""
        self.session = aiohttp.ClientSession()
        await self.authenticate()
        return self

    async def __aexit__(
        self,
        exc_type: Optional[type],
        exc_val: Optional[BaseException],
        exc_tb: Optional[Any],
    ) -> None:
        """Context manager exit."""
        if self.session:
            await self.session.close()

    async def authenticate(self) -> str:
        """
        Authentifie via X-Sah-Login et crée un contexte de session.

        Returns:
            Context ID de session
        """
        if not self.session:
            raise Exception("Session non initialisée")

        payload = {
            "service": "sah.Device.Information",
            "method": "createContext",
            "parameters": {
                "applicationName": "webui",
                "username": "admin",
                "password": self.password,
            },
        }

        headers = {
            "Content-Type": "application/x-sah-ws-4-call+json",
            "Authorization": "X-Sah-Login",
        }

        url = f"{self.base_url}/ws"

        async with self.session.post(
            url, json=payload, headers=headers, timeout=aiohttp.ClientTimeout(total=30)
        ) as response:
            response.raise_for_status()
            data = await response.json()

        if data.get("status") != 0:
            error_msg = data.get("errors", [{}])
            raise Exception(f"Authentification échouée: {error_msg}")

        self.context_id = data["data"]["contextID"]
        groups = data["data"].get("groups", "")
        logger.info(f"Authentification réussie - groupes: {groups}")

        return self.context_id

    async def sysbus_call(
        self,
        path: str,
        method: str,
        parameters: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """
        Effectue un appel via l'API sysbus.

        Args:
            path: Chemin de l'objet (ex: "NMC", "DeviceInfo")
            method: Nom de la méthode
            parameters: Paramètres de la méthode

        Returns:
            Données de réponse
        """
        if not self.session:
            raise Exception("Session non initialisée")

        headers = {
            "Content-Type": "application/json",
            "X-Context": self.context_id or "",
        }

        url = f"{self.base_url}/sysbus/{path}:{method}"

        async with self.session.post(
            url,
            json={"parameters": parameters or {}},
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=30),
        ) as response:
            response.raise_for_status()
            data = await response.json()

        # Gérer les erreurs
        if "error" in data:
            raise Exception(f"Erreur API: {data.get('description', data.get('error'))}")

        result = data.get("result", {})
        if "errors" in result and result["errors"]:
            errors = result["errors"]
            error_msg = errors[0].get("description", "Erreur inconnue") if errors else "Erreur inconnue"
            raise Exception(f"Erreur API: {error_msg}")

        # Retourner les données
        # Certaines réponses ont status=True/False avec data séparé
        if "data" in result and isinstance(result.get("status"), bool):
            return result["data"]
        return result.get("status", result.get("data", result))

    async def request(
        self,
        service: str,
        method: str,
        parameters: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """
        Effectue une requête générique vers l'API Livebox via sysbus.

        Args:
            service: Nom du service (ex: "NMC", "DeviceInfo")
            method: Nom de la méthode
            parameters: Paramètres de la méthode

        Returns:
            Données de réponse
        """
        # Convertir le format service.sous-service en chemin sysbus
        path = service.replace(".", "/")
        return await self.sysbus_call(path, method, parameters)

    # === Informations système ===

    async def get_device_info(self) -> dict[str, Any]:
        """Récupère les informations système de la Livebox."""
        return await self.request("DeviceInfo", "get")

    async def reboot(self) -> dict[str, Any]:
        """Redémarre la Livebox."""
        return await self.request("DeviceInfo", "reboot")

    # === Connexion Internet ===

    async def get_wan_status(self) -> dict[str, Any]:
        """Récupère l'état de la connexion Internet."""
        return await self.request("NMC", "getWANStatus")

    async def get_wan_mibs(self) -> dict[str, Any]:
        """Récupère les MIBs WAN détaillées."""
        result = await self.request(
            "NeMo.Intf.data",
            "getMIBs",
            {"mibs": "wanstatus", "traverse": "down"},
        )
        return result

    async def get_traffic_stats(self) -> dict[str, Any]:
        """Récupère les statistiques de trafic."""
        return await self.request("NMC", "getNetworkStatistics")

    # === WiFi ===

    async def get_wifi_status(self) -> dict[str, Any]:
        """Récupère l'état global du WiFi."""
        return await self.request("NMC.Wifi", "get")

    async def toggle_wifi(self, enable: bool) -> dict[str, Any]:
        """Active ou désactive le WiFi."""
        return await self.request("NMC.Wifi", "set", {"Enable": enable})

    async def get_wifi_stats(self) -> dict[str, Any]:
        """Récupère les statistiques WiFi."""
        return await self.request("NMC.Wifi", "getStats")

    async def get_ssid_list(self) -> dict[str, Any]:
        """Liste tous les SSID configurés."""
        return await self.request(
            "NMC.Wifi.SSID",
            "getMIBs",
            {"mibs": "ssid"},
        )

    async def set_wifi_password(self, ssid_name: str, password: str) -> dict[str, Any]:
        """Modifie le mot de passe WiFi d'un SSID."""
        return await self.request(
            "NMC.Wifi.SSID",
            "setSSIDInfo",
            {
                "ssid_name": ssid_name,
                "parameters": {"WPAPassPhrase": password},
            },
        )

    async def set_wifi_channel(self, ssid_name: str, channel: int) -> dict[str, Any]:
        """Modifie le canal WiFi d'un SSID."""
        return await self.request(
            "NMC.Wifi.SSID",
            "setSSIDInfo",
            {
                "ssid_name": ssid_name,
                "parameters": {"Channel": channel},
            },
        )

    # === Appareils connectés ===

    async def get_devices(self) -> dict[str, Any]:
        """Liste tous les appareils connectés."""
        return await self.request("Hosts", "getDevices")

    async def get_device_by_mac(self, mac_address: str) -> dict[str, Any]:
        """Récupère les infos d'un appareil par son MAC."""
        return await self.request(
            "Hosts",
            "getDevice",
            {"macaddress": mac_address},
        )

    async def set_device_name(self, mac_address: str, name: str) -> dict[str, Any]:
        """Modifie le nom d'un appareil."""
        return await self.request(
            "Hosts",
            "setDeviceName",
            {"macaddress": mac_address, "name": name},
        )

    # === DHCP ===

    async def get_dhcp_config(self) -> dict[str, Any]:
        """Récupère la configuration DHCP."""
        return await self.request(
            "DHCPv4.Server.Pool",
            "getMIBs",
            {"mibs": "dhcp"},
        )

    async def get_dhcp_leases(self) -> dict[str, Any]:
        """Liste les baux DHCP actifs."""
        return await self.request("DHCPv4.Server.Pool", "getLeases")

    async def get_static_addresses(self) -> dict[str, Any]:
        """Liste les réservations IP statiques."""
        return await self.request("DHCPv4.Server.Pool.StaticAddress", "get")

    async def add_dhcp_reservation(
        self,
        mac_address: str,
        ip_address: str,
        name: str,
    ) -> dict[str, Any]:
        """Ajoute une réservation DHCP."""
        return await self.request(
            "DHCPv4.Server.Pool.StaticAddress",
            "add",
            {
                "macaddress": mac_address,
                "ipaddress": ip_address,
                "name": name,
            },
        )

    async def delete_dhcp_reservation(self, mac_address: str) -> dict[str, Any]:
        """Supprime une réservation DHCP."""
        return await self.request(
            "DHCPv4.Server.Pool.StaticAddress",
            "delete",
            {"macaddress": mac_address},
        )

    # === Pare-feu ===

    async def get_firewall_level(self) -> dict[str, Any]:
        """Récupère le niveau du pare-feu."""
        return await self.request("Firewall", "getFirewallLevel")

    async def set_firewall_level(self, level: str) -> dict[str, Any]:
        """Définit le niveau du pare-feu."""
        return await self.request("Firewall", "setFirewallLevel", {"level": level})

    async def get_port_forwards(self) -> dict[str, Any]:
        """Liste les redirections de ports."""
        return await self.request("Firewall.PortForwarding", "get")

    async def add_port_forward(
        self,
        description: str,
        protocol: str,
        external_port: int,
        internal_port: int,
        internal_ip: str,
        source_prefix: str = "",
    ) -> dict[str, Any]:
        """Ajoute une redirection de ports."""
        params: dict[str, Any] = {
            "Enable": True,
            "Description": description,
            "Protocol": protocol,
            "ExternalPort": external_port,
            "InternalPort": internal_port,
            "InternalIPAddress": internal_ip,
        }

        if source_prefix:
            params["SourcePrefix"] = source_prefix

        return await self.request("Firewall.PortForwarding", "add", params)

    async def delete_port_forward(self, rule_id: str) -> dict[str, Any]:
        """Supprime une redirection de ports."""
        return await self.request(
            "Firewall.PortForwarding",
            "delete",
            {"id": rule_id},
        )

    async def get_dmz(self) -> dict[str, Any]:
        """Récupère la configuration DMZ."""
        return await self.request("Firewall.DMZ", "get")

    async def set_dmz(self, enable: bool, ip_address: str = "") -> dict[str, Any]:
        """Configure la DMZ."""
        params: dict[str, Any] = {"Enable": enable}
        if enable and ip_address:
            params["IPAddress"] = ip_address
        return await self.request("Firewall.DMZ", "set", params)

    # === Téléphonie ===

    async def get_voice_status(self) -> dict[str, Any]:
        """Récupère l'état des lignes téléphoniques."""
        return await self.request("VoiceService.VoiceProfile", "get")

    async def get_call_history(
        self,
        call_type: str = "all",
    ) -> dict[str, Any]:
        """Récupère l'historique des appels."""
        return await self.request(
            "VoiceService.VoiceProfile",
            "getCallList",
            {"type": call_type},
        )

    # === Diagnostics ===

    async def ping(self, host: str, count: int = 4) -> dict[str, Any]:
        """Effectue un test ping."""
        return await self.request(
            "NMC.NetworkConfig",
            "ping",
            {"host": host, "count": count},
        )

    async def traceroute(self, host: str) -> dict[str, Any]:
        """Effectue un traceroute."""
        return await self.request(
            "NMC.NetworkConfig",
            "traceroute",
            {"host": host},
        )

    async def speedtest(self) -> dict[str, Any]:
        """Effectue un test de débit."""
        return await self.request("NMC.NetworkConfig", "speedtest")

    # === Système ===

    async def get_time(self) -> dict[str, Any]:
        """Récupère la date/heure système."""
        return await self.request("Time", "getTime")

    async def get_users(self) -> dict[str, Any]:
        """Liste les utilisateurs."""
        return await self.request("UserManagement", "getUsers")

    async def change_password(
        self,
        username: str,
        current_password: str,
        new_password: str,
    ) -> dict[str, Any]:
        """Change le mot de passe d'un utilisateur."""
        return await self.request(
            "UserManagement",
            "setPassword",
            {
                "username": username,
                "currentpassword": current_password,
                "newpassword": new_password,
            },
        )
