import json
import os
import re

from fastapi import APIRouter, Request, Form, Query
from fastapi.responses import HTMLResponse

from app import config
from app.crowdsec_client import CrowdSecClient
from app.deps import templates, get_http_client
from app.threat_detection import classify_entries

router = APIRouter(prefix="/logs")

# Pattern: [timestamp] host remote_addr ...
LOG_PATTERN = re.compile(
    r"\[(?P<timestamp>[^\]]+)\]\s+(?P<host>\S+)\s+(?P<remote_addr>\S+)\s+"
    r"(?P<response_time>\S+)\s+\"(?P<request>[^\"]*)\"\s+(?P<status>\d+)\s+"
    r"(?P<body_bytes>\S+)\s+(?P<total_bytes>\S+)\s+(?P<referer>\S+)\s+"
    r"(?P<user_agent>.+)"
)


def _get_log_dir():
    return config.NPMPLUS_LOG_DIR


def _parse_line(line):
    """Parse a single NPMPlus access log line."""
    m = LOG_PATTERN.match(line.strip())
    if not m:
        return None
    return m.groupdict()


def _get_hosts_from_log(log_path, max_lines=5000):
    """Scan recent log lines to extract unique hostnames."""
    hosts = set()
    try:
        with open(log_path) as f:
            lines = f.readlines()
        for line in lines[-max_lines:]:
            parsed = _parse_line(line)
            if parsed and parsed["host"] not in ("127.0.0.1", "127.0.0.1:81"):
                hosts.add(parsed["host"])
    except (FileNotFoundError, PermissionError):
        pass
    return sorted(hosts)


def _get_status_codes_from_log(log_path, max_lines=5000):
    """Scan recent log lines to extract unique HTTP status codes."""
    codes = set()
    try:
        with open(log_path) as f:
            lines = f.readlines()
        for line in lines[-max_lines:]:
            parsed = _parse_line(line)
            if parsed:
                codes.add(parsed["status"])
    except (FileNotFoundError, PermissionError):
        pass
    return sorted(codes)


def _tail_log(log_path, host_filter=None, status_filter=None, limit=200):
    """Read recent log lines, optionally filtered by host and/or status code."""
    entries = []
    try:
        with open(log_path) as f:
            lines = f.readlines()
    except (FileNotFoundError, PermissionError):
        return []

    for line in reversed(lines):
        parsed = _parse_line(line)
        if not parsed:
            continue
        if host_filter and parsed["host"] != host_filter:
            continue
        if status_filter and parsed["status"] != status_filter:
            continue
        # Skip healthchecks
        if "NPMplus/healthcheck" in parsed.get("user_agent", ""):
            continue
        entries.append(parsed)
        if len(entries) >= limit:
            break

    return entries


def _tail_error_log(log_path, limit=100):
    """Read recent error log lines."""
    lines = []
    try:
        with open(log_path) as f:
            all_lines = f.readlines()
        lines = [l.strip() for l in all_lines[-limit:] if l.strip()]
        lines.reverse()
    except (FileNotFoundError, PermissionError):
        pass
    return lines


async def _get_banned_ips():
    """Fetch currently banned IPs from CrowdSec LAPI."""
    try:
        client = CrowdSecClient(get_http_client())
        decisions = await client.get_decisions()
        return {d.get("value") for d in decisions if d.get("value")}
    except Exception:
        return set()


@router.get("/")
async def index(
    request: Request,
    host: str = Query(default=""),
    status: str = Query(default=""),
    type: str = Query(default="access"),
    limit: int = Query(default=200, le=1000),
):
    log_dir = _get_log_dir()
    log_file = os.path.join(log_dir, "access.log")
    error_log_file = os.path.join(log_dir, "error.log")

    host_filter = host
    status_filter = status
    log_type = type

    hosts = _get_hosts_from_log(log_file)
    status_codes = _get_status_codes_from_log(log_file)
    entries = []
    error_lines = []
    error = None
    banned_ips = set()
    threat_count = 0
    bulk_threats_json = "{}"

    if not os.path.isdir(log_dir):
        error = f"Log directory not found: {log_dir}"
    elif log_type == "error":
        error_lines = _tail_error_log(error_log_file, limit=limit)
    else:
        entries = _tail_log(log_file, host_filter=host_filter or None,
                           status_filter=status_filter or None, limit=limit)
        entries = classify_entries(entries)
        banned_ips = await _get_banned_ips()

        # Build bulk ban data for the "Ban All" button
        threat_data = []
        seen_ips = set()
        for entry in entries:
            threat = entry.get("threat")
            ip = entry["remote_addr"]
            if threat and ip not in banned_ips and ip not in seen_ips:
                seen_ips.add(ip)
                threat_data.append({
                    "ip": ip,
                    "scenario": threat.scenario,
                    "duration": threat.ban_duration,
                    "label": threat.label,
                })
        threat_count = sum(1 for e in entries if e.get("threat"))
        bulk_threats_json = json.dumps(threat_data)

    return templates.TemplateResponse(
        "logs.html",
        {
            "request": request,
            "hosts": hosts,
            "status_codes": status_codes,
            "entries": entries,
            "error_lines": error_lines,
            "selected_host": host_filter,
            "selected_status": status_filter,
            "log_type": log_type,
            "limit": limit,
            "error": error,
            "banned_ips": banned_ips,
            "threat_count": threat_count,
            "bulk_threats_json": bulk_threats_json,
        },
    )


@router.post("/ban")
async def ban_from_log(
    ip: str = Form(default=""),
    scenario: str = Form(default="custom/manual-log-ban"),
    duration: str = Form(default="24h"),
    label: str = Form(default="Detected in logs"),
):
    """HTMX endpoint: ban an IP detected as a threat from the log viewer."""
    ip = ip.strip()
    scenario = scenario.strip()
    duration = duration.strip()
    label = label.strip()

    if not ip:
        return HTMLResponse('<span class="text-error text-xs">No IP</span>', status_code=400)

    try:
        client = CrowdSecClient(get_http_client())
        reason = f"{label} - {scenario}"
        await client.add_decision(ip=ip, duration=duration, reason=reason)
        return HTMLResponse(f'''<span class="inline-flex items-center gap-1 badge badge-error badge-sm">
                     <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                       <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                             d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636"/>
                     </svg>
                     Banned ({duration})
                   </span>''')
    except Exception as e:
        return HTMLResponse(f'<span class="text-error text-xs">Error: {e}</span>', status_code=500)


@router.post("/ban-all-threats")
async def ban_all_threats(
    threats: str = Form(default="[]"),
):
    """HTMX endpoint: ban all detected threat IPs at once."""
    threat_list = json.loads(threats)

    if not threat_list:
        return HTMLResponse('<span class="text-base-content/60 text-xs">No threats to ban</span>')

    client = CrowdSecClient(get_http_client())

    # Deduplicate by IP
    seen = set()
    unique = []
    for t in threat_list:
        if t["ip"] not in seen:
            seen.add(t["ip"])
            unique.append(t)

    banned = 0
    errors = 0
    for t in unique:
        try:
            reason = f"{t.get('label', 'Log threat')} - {t.get('scenario', 'custom/manual-log-ban')}"
            await client.add_decision(ip=t["ip"], duration=t.get("duration", "24h"), reason=reason)
            banned += 1
        except Exception:
            errors += 1

    error_text = f" {errors} failed." if errors else ""
    return HTMLResponse(f'''<span class="inline-flex items-center gap-2 px-4 py-2 rounded-lg">
                 <div class="alert alert-success">
                   <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                     <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
                   </svg>
                   Banned {banned} IPs.{error_text} Refresh to update.
                 </div>
               </span>''')
