# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

CrowdSec Firewall GUI — a web interface for managing CrowdSec firewall via its Local API (LAPI). Currently a Flask + HTMX app with a planned migration to Nuxt 3 + Nuxt UI v4 (see `NUXT-UI-MIGRATION.md`).

## Commands

### Development (Flask — current)
```bash
source venv/bin/activate
pip install -r requirements.txt
python run.py                    # Starts on http://0.0.0.0:5000 (debug=True)
```

### Docker
```bash
docker compose up --build        # Build and run container (host networking, port 5000)
```

### Development (Nuxt — after migration)
```bash
pnpm dev                         # Dev server
docker compose up --build        # Production container
```

No test suite, linter, or CI/CD is configured.

## Architecture

### Current Stack: Flask + Jinja2 + HTMX

**Entry point:** `run.py` → calls `create_app()` from `app/__init__.py` (factory pattern).

**Backend** (`app/`):
- `crowdsec_client.py` — HTTP client wrapping CrowdSec LAPI (`/v1/decisions`, `/v1/alerts`). Auth via `X-Api-Key` header, 5s timeout.
- `routes/` — Five Flask Blueprints: `dashboard`, `decisions`, `alerts`, `config_editor`, `logs`. Each blueprint owns its routes and renders Jinja2 templates.
- `config.py` — Reads all settings from environment variables (no hardcoded values).

**Frontend** (`app/templates/`):
- `base.html` — layout with fixed sidebar (264px) + Tailwind CSS via CDN (custom dark `cs-*` color palette).
- Page templates extend `base.html`. HTMX handles partial updates (auto-refresh stats every 30s, inline delete, expandable rows).
- `partials/` — fragment templates returned by HTMX endpoints (no full-page reload).

**Data flow:** Browser → Flask route → `CrowdSecClient` → CrowdSec LAPI (HTTP). No database — all state comes from the LAPI or filesystem.

### External Dependencies
- **CrowdSec LAPI** — the firewall management API this GUI wraps
- **CrowdSec config directory** (`CROWDSEC_CONF_DIR`) — YAML files edited via the config editor
- **Nginx log directory** (`NPMPLUS_LOG_DIR`) — read-only access for the log viewer

### Security Patterns
- Path traversal protection in config editor: `os.path.abspath()` validation against base directory
- YAML validation (`yaml.safe_load_all()`) before saving config files
- All sensitive config via environment variables

## Planned Migration to Nuxt 3

`NUXT-UI-MIGRATION.md` contains the full 8-phase migration plan. Key decisions:
- Replace Flask entirely with Nuxt 3 server routes (`server/api/`)
- Nuxt UI v4 dashboard components for the frontend
- Reference docs for Nuxt UI v4 are in `.claude/nuxt-ui/` (skill + component references)
- Same 5 features: Dashboard, Decisions, Alerts, Config Editor, Logs
- Dark theme, full-width layout (4K optimized), `useToast()` instead of flash messages
- Path security via Node.js `path.resolve()` (equivalent to Python's `os.path.abspath()`)

## Environment Variables

See `.env.example`. Required: `CROWDSEC_LAPI_URL`, `CROWDSEC_API_KEY`, `FLASK_SECRET_KEY`, `CROWDSEC_CONF_DIR`. Optional: `NPMPLUS_LOG_DIR`.
