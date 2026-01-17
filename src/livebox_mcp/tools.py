"""Définitions des outils MCP pour Livebox 6."""

from mcp.types import Tool

LIVEBOX_TOOLS: list[Tool] = [
    # === Informations système ===
    Tool(
        name="livebox_get_info",
        description="Récupère les informations générales de la Livebox (modèle, version, uptime, etc.)",
        inputSchema={
            "type": "object",
            "properties": {},
            "required": [],
        },
    ),
    Tool(
        name="livebox_get_time",
        description="Récupère la date/heure système de la Livebox",
        inputSchema={
            "type": "object",
            "properties": {},
            "required": [],
        },
    ),
    # === Connexion Internet ===
    Tool(
        name="livebox_get_wan_status",
        description="Récupère l'état de la connexion Internet (LinkState, IPAddress, débits, etc.)",
        inputSchema={
            "type": "object",
            "properties": {},
            "required": [],
        },
    ),
    Tool(
        name="livebox_get_traffic_stats",
        description="Récupère les statistiques de trafic réseau (bytes/packets envoyés et reçus)",
        inputSchema={
            "type": "object",
            "properties": {},
            "required": [],
        },
    ),
    # === WiFi ===
    Tool(
        name="livebox_get_wifi_status",
        description="Récupère l'état global du WiFi et la liste des SSID configurés",
        inputSchema={
            "type": "object",
            "properties": {},
            "required": [],
        },
    ),
    Tool(
        name="livebox_get_wifi_stats",
        description="Récupère les statistiques WiFi (bytes/packets)",
        inputSchema={
            "type": "object",
            "properties": {},
            "required": [],
        },
    ),
    Tool(
        name="livebox_toggle_wifi",
        description="Active ou désactive le WiFi globalement",
        inputSchema={
            "type": "object",
            "properties": {
                "enable": {
                    "type": "boolean",
                    "description": "true pour activer, false pour désactiver",
                },
            },
            "required": ["enable"],
        },
    ),
    Tool(
        name="livebox_set_wifi_password",
        description="Modifie le mot de passe d'un réseau WiFi",
        inputSchema={
            "type": "object",
            "properties": {
                "ssid_name": {
                    "type": "string",
                    "description": "Nom du SSID (ex: Livebox-XXXX)",
                },
                "password": {
                    "type": "string",
                    "description": "Nouveau mot de passe (min 8 caractères)",
                },
            },
            "required": ["ssid_name", "password"],
        },
    ),
    Tool(
        name="livebox_set_wifi_channel",
        description="Modifie le canal WiFi d'un SSID (0 = auto)",
        inputSchema={
            "type": "object",
            "properties": {
                "ssid_name": {
                    "type": "string",
                    "description": "Nom du SSID",
                },
                "channel": {
                    "type": "integer",
                    "description": "Numéro du canal (0 = auto)",
                },
            },
            "required": ["ssid_name", "channel"],
        },
    ),
    # === Appareils connectés ===
    Tool(
        name="livebox_list_devices",
        description="Liste tous les appareils connectés (Ethernet + WiFi) avec leur statut",
        inputSchema={
            "type": "object",
            "properties": {
                "active_only": {
                    "type": "boolean",
                    "description": "Afficher uniquement les appareils actifs (défaut: false)",
                },
            },
            "required": [],
        },
    ),
    Tool(
        name="livebox_get_device_info",
        description="Récupère les détails d'un appareil par son adresse MAC",
        inputSchema={
            "type": "object",
            "properties": {
                "mac_address": {
                    "type": "string",
                    "description": "Adresse MAC (format AA:BB:CC:DD:EE:FF)",
                },
            },
            "required": ["mac_address"],
        },
    ),
    Tool(
        name="livebox_set_device_name",
        description="Modifie le nom d'un appareil",
        inputSchema={
            "type": "object",
            "properties": {
                "mac_address": {
                    "type": "string",
                    "description": "Adresse MAC de l'appareil",
                },
                "name": {
                    "type": "string",
                    "description": "Nouveau nom",
                },
            },
            "required": ["mac_address", "name"],
        },
    ),
    # === DHCP ===
    Tool(
        name="livebox_get_dhcp_leases",
        description="Liste tous les baux DHCP actifs",
        inputSchema={
            "type": "object",
            "properties": {},
            "required": [],
        },
    ),
    Tool(
        name="livebox_get_dhcp_reservations",
        description="Liste toutes les réservations IP statiques",
        inputSchema={
            "type": "object",
            "properties": {},
            "required": [],
        },
    ),
    Tool(
        name="livebox_add_dhcp_reservation",
        description="Ajoute une réservation DHCP (IP statique pour un appareil)",
        inputSchema={
            "type": "object",
            "properties": {
                "mac_address": {
                    "type": "string",
                    "description": "Adresse MAC de l'appareil",
                },
                "ip_address": {
                    "type": "string",
                    "description": "Adresse IP à réserver (ex: 192.168.1.100)",
                },
                "name": {
                    "type": "string",
                    "description": "Nom de la réservation",
                },
            },
            "required": ["mac_address", "ip_address", "name"],
        },
    ),
    Tool(
        name="livebox_delete_dhcp_reservation",
        description="Supprime une réservation DHCP",
        inputSchema={
            "type": "object",
            "properties": {
                "mac_address": {
                    "type": "string",
                    "description": "Adresse MAC de la réservation à supprimer",
                },
            },
            "required": ["mac_address"],
        },
    ),
    # === Pare-feu et NAT ===
    Tool(
        name="livebox_get_firewall_status",
        description="Récupère l'état et le niveau du pare-feu",
        inputSchema={
            "type": "object",
            "properties": {},
            "required": [],
        },
    ),
    Tool(
        name="livebox_set_firewall_level",
        description="Définit le niveau du pare-feu",
        inputSchema={
            "type": "object",
            "properties": {
                "level": {
                    "type": "string",
                    "enum": ["High", "Medium", "Low", "Custom"],
                    "description": "Niveau de sécurité du pare-feu",
                },
            },
            "required": ["level"],
        },
    ),
    Tool(
        name="livebox_list_port_forwards",
        description="Liste toutes les redirections de ports configurées",
        inputSchema={
            "type": "object",
            "properties": {},
            "required": [],
        },
    ),
    Tool(
        name="livebox_add_port_forward",
        description="Ajoute une redirection de ports (NAT/PAT)",
        inputSchema={
            "type": "object",
            "properties": {
                "description": {
                    "type": "string",
                    "description": "Description de la règle",
                },
                "protocol": {
                    "type": "string",
                    "enum": ["TCP", "UDP", "TCP+UDP"],
                    "description": "Protocole",
                },
                "external_port": {
                    "type": "integer",
                    "description": "Port externe",
                },
                "internal_port": {
                    "type": "integer",
                    "description": "Port interne",
                },
                "internal_ip": {
                    "type": "string",
                    "description": "Adresse IP de destination (ex: 192.168.1.100)",
                },
                "source_prefix": {
                    "type": "string",
                    "description": "IP source autorisée (optionnel, vide = toutes)",
                },
            },
            "required": ["description", "protocol", "external_port", "internal_port", "internal_ip"],
        },
    ),
    Tool(
        name="livebox_delete_port_forward",
        description="Supprime une redirection de ports",
        inputSchema={
            "type": "object",
            "properties": {
                "rule_id": {
                    "type": "string",
                    "description": "ID de la règle à supprimer",
                },
            },
            "required": ["rule_id"],
        },
    ),
    Tool(
        name="livebox_get_dmz",
        description="Récupère la configuration DMZ",
        inputSchema={
            "type": "object",
            "properties": {},
            "required": [],
        },
    ),
    Tool(
        name="livebox_set_dmz",
        description="Configure la DMZ",
        inputSchema={
            "type": "object",
            "properties": {
                "enable": {
                    "type": "boolean",
                    "description": "Activer ou désactiver la DMZ",
                },
                "ip_address": {
                    "type": "string",
                    "description": "Adresse IP de la machine en DMZ (requis si enable=true)",
                },
            },
            "required": ["enable"],
        },
    ),
    # === Téléphonie ===
    Tool(
        name="livebox_get_voice_status",
        description="Récupère l'état des lignes téléphoniques VoIP",
        inputSchema={
            "type": "object",
            "properties": {},
            "required": [],
        },
    ),
    Tool(
        name="livebox_get_call_history",
        description="Récupère l'historique des appels téléphoniques",
        inputSchema={
            "type": "object",
            "properties": {
                "call_type": {
                    "type": "string",
                    "enum": ["all", "received", "missed", "dialed"],
                    "description": "Type d'appels à récupérer (défaut: all)",
                },
            },
            "required": [],
        },
    ),
    # === Diagnostics ===
    Tool(
        name="livebox_ping",
        description="Effectue un test ping vers un hôte",
        inputSchema={
            "type": "object",
            "properties": {
                "host": {
                    "type": "string",
                    "description": "Hôte à pinger (IP ou nom de domaine)",
                },
                "count": {
                    "type": "integer",
                    "description": "Nombre de paquets (défaut: 4)",
                },
            },
            "required": ["host"],
        },
    ),
    Tool(
        name="livebox_traceroute",
        description="Effectue un traceroute vers un hôte",
        inputSchema={
            "type": "object",
            "properties": {
                "host": {
                    "type": "string",
                    "description": "Hôte destination (IP ou nom de domaine)",
                },
            },
            "required": ["host"],
        },
    ),
    Tool(
        name="livebox_speedtest",
        description="Effectue un test de débit Internet",
        inputSchema={
            "type": "object",
            "properties": {},
            "required": [],
        },
    ),
    # === Système ===
    Tool(
        name="livebox_reboot",
        description="Redémarre la Livebox. ATTENTION: La box sera indisponible pendant 2-3 minutes!",
        inputSchema={
            "type": "object",
            "properties": {
                "confirm": {
                    "type": "boolean",
                    "description": "Doit être true pour confirmer le redémarrage",
                },
            },
            "required": ["confirm"],
        },
    ),
    Tool(
        name="livebox_change_password",
        description="Modifie le mot de passe administrateur",
        inputSchema={
            "type": "object",
            "properties": {
                "current_password": {
                    "type": "string",
                    "description": "Mot de passe actuel",
                },
                "new_password": {
                    "type": "string",
                    "description": "Nouveau mot de passe",
                },
            },
            "required": ["current_password", "new_password"],
        },
    ),
]
