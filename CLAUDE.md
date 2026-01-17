# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

MCP Server for Orange Livebox 6 router management and monitoring via its local REST API. Exposes Livebox functionality to Claude for network monitoring, WiFi management, device listing, port forwarding, DHCP configuration, and system administration.

## Build & Development Commands

```bash
# Install dependencies
uv sync

# Run the MCP server
uv run livebox-mcp

# Run tests
uv run pytest

# Type checking
uv run mypy src/
```

## Architecture

### Livebox API Structure

All API calls go through a single endpoint: `http://192.168.1.1/ws`

Requests are POST JSON with this structure:
```json
{
  "service": "service.name",
  "method": "methodName",
  "parameters": {}
}
```

Authentication uses a token-based flow:
1. Call `sah.Device.Information.createContext` with admin credentials
2. Include returned `contextID` in `X-Context` header for subsequent requests

### Project Structure

```
src/livebox_mcp/
├── server.py        # MCP server, tool handlers, routing
├── livebox_api.py   # Async HTTP client for Livebox API
└── tools.py         # MCP tool definitions (Tool objects with inputSchema)
```

### Key API Services

- `DeviceInfo` - System info, reboot, reset
- `NMC` - WAN status, network statistics
- `NMC.Wifi` / `NMC.Wifi.SSID` - WiFi control and configuration
- `Hosts` - Connected devices management
- `DHCPv4.Server.Pool` - DHCP leases and static reservations
- `Firewall.PortForwarding` - NAT/PAT rules
- `NMC.NetworkConfig` - Diagnostics (ping, traceroute, speedtest)

## Configuration

Environment variables:
- `LIVEBOX_HOST` - Router IP (default: 192.168.1.1)
- `LIVEBOX_PASSWORD` - Admin password (required)

Claude Desktop config (`claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "livebox": {
      "command": "uv",
      "args": ["--directory", "/path/to/livebox-mcp", "run", "livebox-mcp"],
      "env": {
        "LIVEBOX_HOST": "192.168.1.1",
        "LIVEBOX_PASSWORD": "your_password"
      }
    }
  }
}
```

## Dependencies

- `mcp>=1.3.0` - Model Context Protocol SDK
- `aiohttp>=3.9.0` - Async HTTP client
