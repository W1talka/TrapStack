import os
import re
from collections import defaultdict

from flask import Blueprint, render_template, request, current_app

bp = Blueprint("logs", __name__, url_prefix="/logs")

# Pattern: [timestamp] host remote_addr ...
LOG_PATTERN = re.compile(
    r"\[(?P<timestamp>[^\]]+)\]\s+(?P<host>\S+)\s+(?P<remote_addr>\S+)\s+"
    r"(?P<response_time>\S+)\s+\"(?P<request>[^\"]*)\"\s+(?P<status>\d+)\s+"
    r"(?P<body_bytes>\S+)\s+(?P<total_bytes>\S+)\s+(?P<referer>\S+)\s+"
    r"(?P<user_agent>.+)"
)


def _get_log_dir():
    return current_app.config.get("NPMPLUS_LOG_DIR", "/opt/npmplus/nginx/logs")


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


def _tail_log(log_path, host_filter=None, limit=200):
    """Read recent log lines, optionally filtered by host."""
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


@bp.route("/")
def index():
    log_dir = _get_log_dir()
    log_file = os.path.join(log_dir, "access.log")
    error_log_file = os.path.join(log_dir, "error.log")

    host_filter = request.args.get("host", "")
    log_type = request.args.get("type", "access")
    limit = min(int(request.args.get("limit", 200)), 1000)

    hosts = _get_hosts_from_log(log_file)
    entries = []
    error_lines = []
    error = None

    if not os.path.isdir(log_dir):
        error = f"Log directory not found: {log_dir}"
    elif log_type == "error":
        error_lines = _tail_error_log(error_log_file, limit=limit)
    else:
        entries = _tail_log(log_file, host_filter=host_filter or None, limit=limit)

    return render_template(
        "logs.html",
        hosts=hosts,
        entries=entries,
        error_lines=error_lines,
        selected_host=host_filter,
        log_type=log_type,
        limit=limit,
        error=error,
    )
