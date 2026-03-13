# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

TrapStack — a web interface for managing CrowdSec firewall scenarios and decisions via its Local API (LAPI). Built with FastAPI + Jinja2 + HTMX + DaisyUI.

## Commands

### Development
```bash
source venv/bin/activate
pip install -r requirements.txt
python run.py                    # Starts on http://0.0.0.0:5000 (reload=True)
```

### Docker
```bash
docker compose up --build        # Build and run container (host networking, port 5000)
```

No test suite, linter, or CI/CD is configured.

## Architecture

### Stack: FastAPI + Jinja2 + HTMX + DaisyUI

**Entry point:** `run.py` → runs uvicorn with `app.main:app`.

**Backend** (`app/`):
- `main.py` — FastAPI app, router registration, httpx.AsyncClient lifespan
- `deps.py` — Shared dependencies (Jinja2Templates, httpx client getter) to avoid circular imports
- `crowdsec_client.py` — Async HTTP client wrapping CrowdSec LAPI (`/v1/decisions`, `/v1/alerts`) using httpx. Auth via `X-Api-Key` header (bouncer) and JWT (machine), 5s timeout.
- `routes/` — Six FastAPI APIRouters: `dashboard`, `decisions`, `alerts`, `config_editor`, `logs`, `scenarios`. Each router owns its routes and returns Jinja2 TemplateResponse.
- `config.py` — Reads all settings from environment variables (no hardcoded values). Module-level variables, no class.
- `crowdsec_scenarios.py` — Pre-built CrowdSec scenario templates. Uses `config` module for conf dir.
- `threat_detection.py` — Classifies log entries into attack categories (unchanged).

**Frontend** (`app/templates/`):
- `base.html` — layout with fixed sidebar (264px) + DaisyUI dark theme via `data-theme="dark"`. Tailwind CSS + DaisyUI via CDN.
- Page templates extend `base.html`. HTMX handles partial updates (auto-refresh stats every 30s, inline delete, expandable rows).
- `partials/` — fragment templates returned by HTMX endpoints (no full-page reload).
- DaisyUI components: `menu`, `table table-zebra`, `card`, `badge`, `btn`, `input`, `select`, `textarea`, `alert`, `stats`, `join` (pagination), `toast`.

**Data flow:** Browser → FastAPI route → `CrowdSecClient` (httpx async) → CrowdSec LAPI (HTTP). No database — all state comes from the LAPI or filesystem.

### External Dependencies
- **CrowdSec LAPI** — the firewall management API this GUI wraps
- **CrowdSec config directory** (`CROWDSEC_CONF_DIR`) — YAML files edited via the config editor
- **Nginx log directory** (`NPMPLUS_LOG_DIR`) — read-only access for the log viewer

### Security Patterns
- Path traversal protection in config editor: `os.path.abspath()` validation against base directory
- YAML validation (`yaml.safe_load_all()`) before saving config files
- All sensitive config via environment variables

### Flash Messages
FastAPI does not have Flask's `flash()`. Messages are passed via query parameters (`?msg=...&msg_type=success`) for full-page redirects. HTMX responses return inline HTML fragments directly.

## Environment Variables

See `.env.example`. Required: `CROWDSEC_LAPI_URL`, `CROWDSEC_API_KEY`, `CROWDSEC_CONF_DIR`. Optional: `NPMPLUS_LOG_DIR`, `CROWDSEC_MACHINE_ID`, `CROWDSEC_MACHINE_PASSWORD`.

## README Maintenance

Keep `README.md` up to date when making changes that affect:
- Features (new pages, removed features, changed functionality)
- Environment variables (new, renamed, or removed)
- Dependencies or setup steps
- Project structure (new top-level modules)
- Docker configuration
