# Livebox MCP Server

> **🚧 Work in Progress** - Ce projet est en cours de développement.

MCP Server pour la gestion et le monitoring de routeur Orange Livebox 6 via son API REST locale.

## Installation

```bash
uv sync
```

## Usage

```bash
uv run livebox-mcp
```

## Variables d'environnement

- `LIVEBOX_HOST` - IP du routeur (défaut: 192.168.1.1)
- `LIVEBOX_PASSWORD` - Mot de passe admin (requis)

## Développement

```bash
# Lancer les tests
uv run pytest

# Vérification de types
uv run mypy src/
```

---

## 🚧 Points de blocage rencontrés

### 1. Authentification non documentée

L'API Livebox 6 utilise un mécanisme d'authentification spécifique **non documenté par Orange**.

**Problème initial:** Les requêtes avec `Authorization: Basic` ou des headers standards échouaient avec l'erreur `"Object or parameter not found"`.

**Solution découverte:**
```http
POST /ws HTTP/1.1
Content-Type: application/x-sah-ws-4-call+json
Authorization: X-Sah-Login

{
  "service": "sah.Device.Information",
  "method": "createContext",
  "parameters": {
    "applicationName": "webui",
    "username": "admin",
    "password": "votre_mot_de_passe"
  }
}
```

La réponse contient un `contextID` à inclure dans le header `X-Context` pour les requêtes suivantes.

### 2. Endpoint sysbus vs /ws

**Problème:** L'endpoint `/ws` ne fonctionne que pour l'authentification.

**Solution:** Les appels API doivent utiliser l'endpoint sysbus:
```
POST /sysbus/{service}:{method}
```

Exemple: `POST /sysbus/DeviceInfo:get`

### 3. 🔒 Restrictions API majeures sur Livebox 6

**C'est le blocage principal.** Orange a sévèrement restreint l'accès API sur le firmware Livebox 6.

#### Services accessibles ✅

| Service | Méthode | Description |
|---------|---------|-------------|
| `DeviceInfo` | `get` | Informations système (modèle, version, uptime) |
| `NMC` | `getWANStatus` | État connexion Internet |
| `NMC` | `get` | Informations réseau |
| `UserInterface` | `getLanguage` | Langue interface |

#### Services bloqués ❌ ("Permission denied")

| Service | Description | Statut |
|---------|-------------|--------|
| `NMC.Wifi` | Contrôle WiFi | 🔒 Bloqué |
| `Hosts` | Appareils connectés | 🔒 Bloqué |
| `DHCPv4.Server` | Configuration DHCP | 🔒 Bloqué |
| `Firewall` | Pare-feu, port forwarding | 🔒 Bloqué |
| `VoiceService` | Téléphonie | 🔒 Bloqué |
| `Time` | Horloge système | 🔒 Bloqué |
| `NMC.NetworkConfig` | Diagnostics (ping, traceroute) | 🔒 Bloqué |
| `UserManagement` | Gestion utilisateurs | 🔒 Bloqué |

### 4. Tentatives de contournement échouées

Nous avons testé plusieurs approches sans succès:

| Approche | Résultat |
|----------|----------|
| Utilisateurs alternatifs (`root`, `su`, `support`) | Seul `admin` fonctionne |
| HTTPS (port 443) | Non disponible |
| Endpoints alternatifs (`/api/`, `/cgi-bin/`) | 404 |
| Headers supplémentaires (`X-Requested-With`, etc.) | Aucun effet |
| Scan de tous les services sysbus | Mêmes restrictions |

### 5. Hypothèses sur les restrictions

- **Firmware Livebox 6:** Orange semble avoir volontairement limité l'API locale
- **Groupe utilisateur:** L'authentification retourne `groups: "http"` - un groupe avec permissions limitées
- **Sécurité renforcée:** Probablement pour éviter les modifications non autorisées via des scripts

### 6. Comparaison avec Livebox 5

D'après la documentation communautaire, la Livebox 5 offrait un accès API beaucoup plus complet. La Livebox 6 représente une régression significative en termes d'accessibilité API.

---

## État actuel du projet

### Ce qui fonctionne ✅

- Authentification X-Sah-Login
- Récupération infos système (`DeviceInfo`)
- Statut connexion Internet (`NMC.getWANStatus`)
- Suite de tests complète (123 tests)

### Ce qui est implémenté mais bloqué par Orange 🔒

- 30 outils MCP définis (WiFi, DHCP, Firewall, etc.)
- Client API complet
- Handlers pour toutes les fonctionnalités

### Prochaines étapes potentielles

1. Surveiller les mises à jour firmware Orange
2. Explorer d'autres méthodes d'accès (Telnet si activé?)
3. Documenter les différences entre versions Livebox
4. Contacter la communauté pour solutions alternatives

---

## Ressources

- [API Livebox (non officielle)](https://github.com/rene-music/livebox)
- [Forum LaFibre.info](https://lafibre.info/orange-livebox/)
