# Livebox MCP Server

MCP Server for Orange Livebox 6 router management and monitoring via its local REST API.

## Installation

```bash
uv sync
```

## Usage

```bash
uv run livebox-mcp
```

## Environment Variables

- `LIVEBOX_HOST` - Router IP (default: 192.168.1.1)
- `LIVEBOX_PASSWORD` - Admin password (required)

## Development

```bash
# Run tests
uv run pytest

# Type checking
uv run mypy src/
```
