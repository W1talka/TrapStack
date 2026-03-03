# Rewrite CrowdSec FW GUI: Flask → Nuxt 3 + Nuxt UI v4

## Context
The current app is Flask + Jinja2 templates with Tailwind CSS. The user wants to rewrite it using Nuxt 3 with Nuxt UI v4 dashboard components. They have a 4K monitor and want full-width layout with no max-width constraints.

## Architecture
- **Replace Flask entirely** with a single Nuxt 3 app
- Server routes (`server/api/`) replace Flask routes — proxy CrowdSec LAPI calls, read files/logs
- Client pages use Nuxt UI Dashboard components (`UDashboardGroup`, `UDashboardSidebar`, `UDashboardPanel`)
- All sensitive config (API key, LAPI URL, file paths) stays server-side via `runtimeConfig`
- Single Docker container (Node.js)

## Project Structure
```
crowdsec-gui/
├── nuxt.config.ts              # Nuxt config + runtimeConfig for env vars
├── app.config.ts               # Nuxt UI colors (primary: blue, neutral: slate)
├── app.vue                     # <UApp><NuxtLayout><NuxtPage /></NuxtLayout></UApp>
├── package.json
├── Dockerfile                  # Node 22 multi-stage build
├── docker-compose.yml
├── .env.example
├── assets/css/main.css         # @import tailwindcss + @nuxt/ui, dark mode defaults
│
├── types/index.ts              # Decision, Alert, ConfigFileEntry, AccessLogEntry types
│
├── layouts/
│   └── dashboard.vue           # UDashboardGroup + UDashboardSidebar + UNavigationMenu
│
├── pages/
│   ├── index.vue               # Dashboard — stat cards + recent decisions table
│   ├── decisions.vue           # Decisions — add ban form, search, UTable, delete
│   ├── alerts/index.vue        # Alerts — scenario filter, expandable rows
│   ├── config.vue              # Config editor — file sidebar + textarea editor
│   └── logs.vue                # Logs — host filter pills, access/error toggle, UTable
│
├── composables/
│   └── useCrowdsec.ts          # Client-side $fetch wrappers for /api/* routes
│
└── server/
    ├── utils/
    │   ├── crowdsec.ts         # LAPI client ($fetch with X-Api-Key header)
    │   └── config-paths.ts     # Path traversal validation (resolve() like abspath)
    └── api/
        ├── dashboard/stats.get.ts
        ├── decisions/index.get.ts, index.post.ts, [id].delete.ts
        ├── alerts/index.get.ts, [id].get.ts
        ├── config/files.get.ts, file.get.ts, file.put.ts
        └── logs/access.get.ts, error.get.ts, hosts.get.ts
```

## Implementation Phases

### Phase 1: Scaffold + Layout
- `package.json` (deps: @nuxt/ui, tailwindcss, @iconify-json/lucide)
- `nuxt.config.ts` with runtimeConfig for env vars (CROWDSEC_LAPI_URL, CROWDSEC_API_KEY, CROWDSEC_CONF_DIR, NPMPLUS_LOG_DIR)
- `app.config.ts` — colors: primary=blue, neutral=slate
- `assets/css/main.css` — dark mode, no container limit
- `app.vue` — UApp wrapper
- `types/index.ts` — all shared interfaces
- `layouts/dashboard.vue` — UDashboardGroup + UDashboardSidebar with UNavigationMenu (Dashboard, Decisions, Alerts, Config, Logs) + collapsed support

### Phase 2: Server Utils
- `server/utils/crowdsec.ts` — getDecisions(), addDecision(), deleteDecision(), getAlerts(), getAlertDetail() using $fetch with X-Api-Key header
- `server/utils/config-paths.ts` — validateConfigPath(), listConfigFiles() using Node.js path.resolve() for symlink-safe traversal prevention

### Phase 3: Dashboard Page
- `server/api/dashboard/stats.get.ts` — aggregates decisions + alerts into stats
- `pages/index.vue` — UDashboardPanel with stat UCards in responsive grid + UTable for recent decisions, auto-refresh every 30s

### Phase 4: Decisions Page
- `server/api/decisions/` — GET (list + search), POST (add ban), DELETE (remove)
- `pages/decisions.vue` — UDashboardPanel with:
  - Add ban form (UInput for IP, USelect for duration, UInput for reason)
  - Search UInput
  - UTable with columns: IP, Scenario, Action (UBadge), Origin, Scope, Expiry, Remove (UButton)
  - Delete confirmation via useOverlay or UModal
  - useToast() for success/error notifications

### Phase 5: Alerts Page
- `server/api/alerts/` — GET (list), GET by ID (detail with events)
- `pages/alerts/index.vue` — UDashboardPanel with:
  - USelect for scenario filter
  - UTable with expandable rows (click to show events)
  - Columns: Source IP, Scenario, Country, AS Info, Decisions (UBadge), Time

### Phase 6: Config Editor Page
- `server/api/config/` — GET files list, GET file content, PUT file (with YAML validation)
- `pages/config.vue` — Two-panel layout:
  - Left: file tree grouped by category (Custom Scenarios, Acquisition, Whitelists)
  - Right: textarea editor with save button
  - useToast() for save success/YAML errors

### Phase 7: Logs Page
- `server/api/logs/` — GET hosts, GET access entries (parsed, filtered), GET error lines
- `pages/logs.vue` — UDashboardPanel with:
  - Toggle buttons: Access / Error
  - Host filter pill bar (UBadge/UButton pills)
  - Access: UTable (Time, Host, Remote IP, Request, Status as colored UBadge, User Agent)
  - Error: monospace text display
  - Full-width table spanning entire 4K viewport

### Phase 8: Docker + Deployment
- `Dockerfile` — Node 22-slim, multi-stage (build + runtime)
- `docker-compose.yml` — host networking, volumes for /opt/crowdsec/conf and /opt/npmplus/nginx/logs:ro
- `.env.example`
- `.gitignore` for Nuxt (.nuxt, .output, node_modules)

## Key Patterns
- **Nuxt UI Table**: `<UTable :data="data" :columns="columns" />` with column definitions
- **Status badges**: `<UBadge :color="status >= 500 ? 'error' : status >= 400 ? 'warning' : 'success'" :label="status" />`
- **Notifications**: `useToast().add({ title: 'Banned', color: 'success' })` instead of flash messages
- **Server config**: `useRuntimeConfig()` in server/ for env vars — never exposed to client
- **Path security**: `path.resolve()` (equivalent to Python's `os.path.abspath()`) for symlink-safe traversal prevention
- **4K**: UDashboardPanel #body fills available width naturally — no max-width needed

## Verification
1. `pnpm dev` — all 5 pages load
2. Dashboard shows stats from LAPI
3. Decisions: add ban, search, delete work with toast notifications
4. Alerts: filter by scenario, expand to see events
5. Config: list files (including symlinked scenarios), edit + save with YAML validation
6. Logs: filter by host, toggle access/error, full-width on 4K
7. `docker compose up --build` — runs on port 5000
