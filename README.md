# TrapStack

A web interface for managing [CrowdSec](https://www.crowdsec.net/) firewall scenarios and decisions via its Local API (LAPI). Built for homelabs and self-hosted environments running CrowdSec behind an Nginx reverse proxy (NPMPlus).

**Stack:** FastAPI + Jinja2 + HTMX + DaisyUI (dark theme)

## Features

### Dashboard
Live stats (auto-refresh every 30s): active bans, alerts, top scenario, top country. Quick view of recent decisions and alerts.

### Decisions
Manage active firewall bans. Search by IP/scenario/origin, filter by decision origin, manually ban IPs with custom duration, inline delete.

### Alerts
Browse CrowdSec alert history with pagination. Filter by scenario type, expand alert details inline.

### Log Viewer
Real-time nginx access log viewer with support for rotated logs. Filter by hostname and HTTP status. Built-in threat detection classifies requests into 6 attack types (RDP brute force, path traversal, TLS probing, SSH scanning, binary garbage, generic probe). Ban individual IPs or bulk-ban all detected threats.

### Config Editor
Edit CrowdSec YAML config files (scenarios, acquisition, whitelists) directly from the browser. YAML validation before save, path traversal protection.

### Scenario Library
6 pre-built CrowdSec scenario templates ready to deploy. Deploy/undeploy individually or all at once. Backup as ZIP, upload scenarios from ZIP.

### AI Log Analysis
Feed recent access logs to an LLM (Claude, GPT, or local models via Ollama/LM Studio) to generate CrowdSec scenario recommendations for attack patterns not covered by existing rules. Save to library or deploy directly. Auto-detects your public IP to prevent self-banning.

## Quick Start

### Docker (recommended)

```bash
cp .env.example .env
# Edit .env with your CrowdSec API credentials
docker compose up --build
```

Open `http://localhost:5000`

### Local Development

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Edit .env
python run.py
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `CROWDSEC_LAPI_URL` | Yes | `http://127.0.0.1:8078` | CrowdSec LAPI endpoint |
| `CROWDSEC_API_KEY` | Yes | | Bouncer API key (read operations) |
| `CROWDSEC_CONF_DIR` | Yes | `/opt/crowdsec/conf` | CrowdSec config directory |
| `CROWDSEC_MACHINE_ID` | No | | Machine ID for write operations (banning, alerts) |
| `CROWDSEC_MACHINE_PASSWORD` | No | | Machine password (pair with MACHINE_ID) |
| `NPMPLUS_LOG_DIR` | No | `/opt/npmplus/nginx/logs` | Nginx log directory |
| `AI_PROVIDER` | No | | `anthropic` or `openai` (enables AI analysis) |
| `AI_API_KEY` | No | | API key for AI provider |
| `AI_API_URL` | No | | Override API endpoint (e.g., `http://localhost:1234/v1` for LM Studio) |
| `AI_MODEL` | No | | Override model name |
| `TRUSTED_IPS` | No | | Comma-separated IPs excluded from AI analysis |

### CrowdSec Setup

```bash
# Create a bouncer API key (read access)
cscli bouncers add trapstack

# Create machine credentials (write access — needed for banning/alerts)
cscli machines add trapstack -p your-password
```

### AI Provider Examples

**Anthropic Claude:**
```env
AI_PROVIDER=anthropic
AI_API_KEY=sk-ant-...
```

**OpenAI:**
```env
AI_PROVIDER=openai
AI_API_KEY=sk-...
```

**Local model (LM Studio / Ollama):**
```env
AI_PROVIDER=openai
AI_API_URL=http://localhost:1234/v1
AI_MODEL=openai/gpt-oss-20b
```

## Docker Compose

```yaml
services:
  trapstack:
    build: .
    restart: always
    network_mode: host
    volumes:
      - "/opt/crowdsec/conf:/opt/crowdsec/conf"
      - "/opt/npmplus/nginx/logs:/opt/npmplus/nginx/logs:ro"
    env_file:
      - .env
```

Host networking is used so TrapStack can reach the CrowdSec LAPI on localhost.

## Project Structure

```
app/
├── main.py                  # FastAPI app & router registration
├── config.py                # Environment variable loading
├── deps.py                  # Shared dependencies (templates, HTTP client)
├── crowdsec_client.py       # Async CrowdSec LAPI client
├── crowdsec_scenarios.py    # Scenario library loader & deployer
├── ai_client.py             # Multi-provider AI client (Claude/OpenAI/Ollama)
├── log_analyzer.py          # Log aggregation pipeline for AI analysis
├── threat_detection.py      # Attack classification (6 threat types)
├── routes/                  # FastAPI routers (7 modules)
├── templates/               # Jinja2 templates + HTMX partials
└── scenario_library/        # Pre-built CrowdSec scenario YAMLs
```

## License

MIT
