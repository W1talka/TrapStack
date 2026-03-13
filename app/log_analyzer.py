"""Log reading utilities and AI analysis aggregation pipeline.

Shared log-reading functions extracted from routes/logs.py for reuse.
The analyze_logs() function aggregates patterns for AI consumption.
"""

import os
import re
from collections import Counter, defaultdict

from app import config
from app.threat_detection import classify_entry
from app.crowdsec_scenarios import get_all_with_status

# Pattern: [timestamp] host remote_addr ...
LOG_PATTERN = re.compile(
    r"\[(?P<timestamp>[^\]]+)\]\s+(?P<host>\S+)\s+(?P<remote_addr>\S+)\s+"
    r"(?P<response_time>\S+)\s+\"(?P<request>[^\"]*)\"\s+(?P<status>\d+)\s+"
    r"(?P<body_bytes>\S+)\s+(?P<total_bytes>\S+)\s+(?P<referer>\S+)\s+"
    r"(?P<user_agent>.+)"
)

# Known scanner/attack paths to flag
SUSPICIOUS_PATHS = [
    "/wp-admin", "/wp-login", "/wp-content", "/wp-includes", "/xmlrpc.php",
    "/.env", "/.git", "/.svn", "/.htaccess", "/.htpasswd",
    "/phpMyAdmin", "/phpmyadmin", "/pma", "/myadmin",
    "/cgi-bin", "/cgi-sys",
    "/actuator", "/api/v1", "/swagger", "/graphql",
    "/config.json", "/config.yml", "/config.yaml",
    "/admin", "/administrator", "/manager",
    "/shell", "/cmd", "/exec", "/eval",
    "/vendor", "/node_modules", "/debug",
    "/solr", "/jenkins", "/struts",
    "/login", "/signin", "/register",
]

# Known malicious user agents
SUSPICIOUS_UA_PATTERNS = [
    "nmap", "masscan", "zgrab", "nuclei", "nikto", "sqlmap", "dirbuster",
    "gobuster", "wpscan", "joomla", "acunetix", "nessus", "openvas",
    "python-requests", "go-http-client", "curl/", "wget/",
    "scrapy", "httpclient", "java/", "ahrefsbot",
]


def get_rotated_files(log_dir, basename):
    """Return list of log files sorted by recency: basename, basename.1, ..."""
    files = []
    base = os.path.join(log_dir, basename)
    if os.path.isfile(base):
        files.append(base)
    i = 1
    while True:
        rotated = f"{base}.{i}"
        if os.path.isfile(rotated):
            files.append(rotated)
            i += 1
        else:
            break
    return files


def read_lines(path):
    """Read all lines from a file, returning [] on error."""
    try:
        with open(path) as f:
            return f.readlines()
    except (FileNotFoundError, PermissionError):
        return []


def parse_line(line):
    """Parse a single NPMPlus access log line."""
    m = LOG_PATTERN.match(line.strip())
    if not m:
        return None
    return m.groupdict()


def tail_log(log_dir, host_filter=None, status_filter=None, limit=200):
    """Read recent log lines across rotated files, optionally filtered."""
    entries = []
    for path in get_rotated_files(log_dir, "access.log"):
        lines = read_lines(path)
        for line in reversed(lines):
            parsed = parse_line(line)
            if not parsed:
                continue
            if host_filter and parsed["host"] != host_filter:
                continue
            if status_filter and parsed["status"] != status_filter:
                continue
            if "NPMplus/healthcheck" in parsed.get("user_agent", ""):
                continue
            entries.append(parsed)
            if len(entries) >= limit:
                return entries
    return entries


def analyze_logs(log_dir=None, limit=2000, trusted_ips=None):
    """Read recent logs and produce an aggregated analysis summary for AI.

    trusted_ips: set of IPs to exclude from IP-based analysis (prevents self-banning).
    """
    log_dir = log_dir or config.NPMPLUS_LOG_DIR
    trusted_ips = trusted_ips or set()

    entries = tail_log(log_dir, limit=limit)
    if not entries:
        return None

    # Classify each entry with existing threat detection
    for entry in entries:
        entry["_threat"] = classify_entry(entry)

    # Time range
    timestamps = [e["timestamp"] for e in entries if e.get("timestamp")]
    time_range = {"start": timestamps[-1] if timestamps else "", "end": timestamps[0] if timestamps else ""}

    # Status distribution
    status_dist = Counter(e["status"] for e in entries)

    # Per-IP aggregation (skip trusted IPs)
    ip_data = defaultdict(lambda: {"count": 0, "statuses": Counter(), "requests": [], "threats": 0})
    for e in entries:
        ip = e["remote_addr"]
        if ip in trusted_ips:
            continue
        ip_data[ip]["count"] += 1
        ip_data[ip]["statuses"][e["status"]] += 1
        if len(ip_data[ip]["requests"]) < 5:
            ip_data[ip]["requests"].append(e["request"])
        if e["_threat"]:
            ip_data[ip]["threats"] += 1

    top_ips = sorted(ip_data.items(), key=lambda x: x[1]["count"], reverse=True)[:20]
    top_ips_list = []
    for ip, data in top_ips:
        error_count = sum(v for k, v in data["statuses"].items() if int(k) >= 400)
        top_ips_list.append({
            "ip": ip,
            "count": data["count"],
            "error_rate": round(error_count / data["count"], 2) if data["count"] > 0 else 0,
            "statuses": dict(data["statuses"].most_common(5)),
            "sample_requests": data["requests"][:3],
        })

    # High error-rate IPs (>70% errors, min 5 requests)
    high_error_ips = []
    for ip, data in ip_data.items():
        if data["count"] < 5:
            continue
        error_count = sum(v for k, v in data["statuses"].items() if int(k) >= 400)
        ratio = error_count / data["count"]
        if ratio > 0.7:
            high_error_ips.append({
                "ip": ip,
                "count": data["count"],
                "error_count": error_count,
                "ratio": round(ratio, 2),
                "sample_requests": data["requests"][:3],
            })
    high_error_ips.sort(key=lambda x: x["count"], reverse=True)

    # Path analysis
    path_counter = Counter()
    for e in entries:
        req = e["request"]
        # Extract path from request line (e.g. "GET /path HTTP/1.1" -> "/path")
        parts = req.split(" ")
        path = parts[1] if len(parts) >= 2 else req
        # Normalize: strip query string
        path = path.split("?")[0]
        path_counter[path] += 1
    top_paths = [{"path": p, "count": c} for p, c in path_counter.most_common(30)]

    # Suspicious path matches (skip trusted IPs)
    suspicious_found = defaultdict(lambda: {"count": 0, "ips": set(), "sample_requests": []})
    for e in entries:
        if e["remote_addr"] in trusted_ips:
            continue
        req_lower = e["request"].lower()
        for sp in SUSPICIOUS_PATHS:
            if sp.lower() in req_lower:
                suspicious_found[sp]["count"] += 1
                suspicious_found[sp]["ips"].add(e["remote_addr"])
                if len(suspicious_found[sp]["sample_requests"]) < 3:
                    suspicious_found[sp]["sample_requests"].append(e["request"])
                break
    suspicious_patterns = [
        {"pattern": k, "count": v["count"], "unique_ips": len(v["ips"]), "sample_requests": v["sample_requests"]}
        for k, v in sorted(suspicious_found.items(), key=lambda x: x[1]["count"], reverse=True)
    ]

    # User agent analysis
    ua_counter = Counter(e["user_agent"] for e in entries)
    top_uas = [{"ua": ua, "count": c} for ua, c in ua_counter.most_common(15)]

    # Suspicious user agents
    suspicious_uas = []
    for ua, count in ua_counter.items():
        ua_lower = ua.lower()
        for pattern in SUSPICIOUS_UA_PATTERNS:
            if pattern in ua_lower:
                suspicious_uas.append({"ua": ua, "count": count, "matched": pattern})
                break
    suspicious_uas.sort(key=lambda x: x["count"], reverse=True)

    # Unclassified suspicious entries (not caught by existing threat detection)
    unclassified = []
    seen_requests = set()
    for e in entries:
        if e["remote_addr"] in trusted_ips:
            continue
        if e["_threat"] is not None:
            continue
        status = int(e["status"])
        if status < 400:
            continue
        req_key = e["request"][:100]
        if req_key in seen_requests:
            continue
        seen_requests.add(req_key)
        unclassified.append({
            "request": e["request"],
            "status": e["status"],
            "ip": e["remote_addr"],
            "ua": e["user_agent"],
            "host": e["host"],
        })
        if len(unclassified) >= 50:
            break

    # Existing scenarios
    scenarios = get_all_with_status()
    deployed = [s for s in scenarios if s.get("deployed")]
    existing_info = []
    for s in scenarios:
        existing_info.append({
            "id": s["id"],
            "name": s["yaml_content"].get("name", ""),
            "description": s.get("description", ""),
            "filter": s["yaml_content"].get("filter", ""),
            "deployed": s.get("deployed", False),
        })

    # Clean up internal keys
    for e in entries:
        del e["_threat"]

    return {
        "total_entries": len(entries),
        "time_range": time_range,
        "status_distribution": dict(status_dist.most_common()),
        "top_ips": top_ips_list,
        "high_error_ips": high_error_ips[:10],
        "top_paths": top_paths,
        "suspicious_patterns": suspicious_patterns,
        "top_user_agents": top_uas,
        "suspicious_user_agents": suspicious_uas,
        "unclassified_suspicious": unclassified,
        "existing_scenarios": existing_info,
    }


def build_prompt(analysis):
    """Format the aggregated analysis dict into a user prompt for the AI."""
    lines = []
    lines.append(f"Analyzed {analysis['total_entries']} recent nginx access log entries.")
    lines.append(f"Time range: {analysis['time_range']['start']} to {analysis['time_range']['end']}")
    lines.append("")

    # Existing scenarios
    lines.append("## Already Deployed Scenarios (DO NOT duplicate these)")
    for s in analysis["existing_scenarios"]:
        status = "DEPLOYED" if s["deployed"] else "not deployed"
        lines.append(f"- {s['name']} ({status}): {s['description']}")
        lines.append(f"  Filter: {s['filter']}")
    lines.append("")

    # Status distribution
    lines.append("## Status Code Distribution")
    for code, count in sorted(analysis["status_distribution"].items()):
        lines.append(f"- {code}: {count}")
    lines.append("")

    # Top IPs
    lines.append("## Top IPs by Request Count")
    for ip_info in analysis["top_ips"][:15]:
        lines.append(f"- {ip_info['ip']}: {ip_info['count']} requests, error_rate={ip_info['error_rate']}, statuses={ip_info['statuses']}")
        for req in ip_info["sample_requests"]:
            lines.append(f"    \"{req}\"")
    lines.append("")

    # High error rate IPs
    if analysis["high_error_ips"]:
        lines.append("## IPs with High Error Rates (>70% errors)")
        for ip_info in analysis["high_error_ips"]:
            lines.append(f"- {ip_info['ip']}: {ip_info['error_count']}/{ip_info['count']} errors ({ip_info['ratio']})")
            for req in ip_info["sample_requests"]:
                lines.append(f"    \"{req}\"")
        lines.append("")

    # Suspicious patterns
    if analysis["suspicious_patterns"]:
        lines.append("## Suspicious Path Patterns Detected")
        for sp in analysis["suspicious_patterns"]:
            lines.append(f"- {sp['pattern']}: {sp['count']} hits from {sp['unique_ips']} unique IPs")
            for req in sp["sample_requests"]:
                lines.append(f"    \"{req}\"")
        lines.append("")

    # Suspicious user agents
    if analysis["suspicious_user_agents"]:
        lines.append("## Suspicious User Agents")
        for sua in analysis["suspicious_user_agents"]:
            lines.append(f"- \"{sua['ua']}\" ({sua['count']} requests, matched: {sua['matched']})")
        lines.append("")

    # Unclassified suspicious
    if analysis["unclassified_suspicious"]:
        lines.append("## Unclassified Suspicious Requests (not caught by existing rules, status >= 400)")
        for entry in analysis["unclassified_suspicious"][:30]:
            lines.append(f"- [{entry['status']}] \"{entry['request']}\" from {entry['ip']} (host={entry['host']}, ua=\"{entry['ua']}\")")
        lines.append("")

    lines.append("Analyze these patterns and recommend CrowdSec scenarios for attack patterns not already covered by existing scenarios.")

    return "\n".join(lines)
