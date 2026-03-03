"""Threat detection for reverse proxy log entries.

Classifies parsed log entries into attack categories and provides
CrowdSec-compatible scenario names for banning.
"""

import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class ThreatClassification:
    scenario: str
    label: str
    severity: str  # critical, high, medium, low
    ban_duration: str


def _check_tls_probing(entry: dict) -> bool:
    req = entry.get("request", "")
    return bool(re.search(r"\\x16\\x03", req))


def _check_rdp_brute(entry: dict) -> bool:
    req = entry.get("request", "")
    return bool(re.search(r"mstshash=", req, re.IGNORECASE))


def _check_path_traversal(entry: dict) -> bool:
    req = entry.get("request", "")
    patterns = [
        r"\.\.",
        r"\.%2[eE]",
        r"%2[eE]\.",
        r"%2[eE]%2[eE]",
        r"/etc/passwd",
        r"/proc/self",
        r"/bin/sh",
    ]
    return any(re.search(p, req) for p in patterns)


def _check_ssh_scan(entry: dict) -> bool:
    req = entry.get("request", "")
    return bool(re.search(r"SSH-2\.0-", req))


def _check_binary_garbage(entry: dict) -> bool:
    req = entry.get("request", "")
    if not req:
        return entry.get("status") == "400"
    if re.search(r"\\x[0-9a-fA-F]{2}", req):
        return True
    return False


def _check_generic_probe(entry: dict) -> bool:
    req = entry.get("request", "")
    host = entry.get("host", "")
    return host == "_" and req.startswith("GET / ")


# Ordered: most specific first. First match wins.
_PATTERNS = [
    (_check_rdp_brute, ThreatClassification(
        scenario="custom/rdp-bruteforce-on-http",
        label="RDP Brute Force",
        severity="critical",
        ban_duration="7d",
    )),
    (_check_path_traversal, ThreatClassification(
        scenario="custom/http-path-traversal",
        label="Path Traversal",
        severity="critical",
        ban_duration="24h",
    )),
    (_check_tls_probing, ThreatClassification(
        scenario="custom/tls-probing-on-http",
        label="TLS/SSL Probing",
        severity="high",
        ban_duration="24h",
    )),
    (_check_ssh_scan, ThreatClassification(
        scenario="custom/ssh-scan-on-http",
        label="SSH Scanning",
        severity="high",
        ban_duration="24h",
    )),
    (_check_binary_garbage, ThreatClassification(
        scenario="custom/non-http-data",
        label="Binary/Garbage Data",
        severity="medium",
        ban_duration="12h",
    )),
    (_check_generic_probe, ThreatClassification(
        scenario="custom/generic-ip-probe",
        label="Generic Probe",
        severity="low",
        ban_duration="4h",
    )),
]


def classify_entry(entry: dict) -> Optional[ThreatClassification]:
    """Classify a single log entry. Returns ThreatClassification or None."""
    for check_fn, classification in _PATTERNS:
        if check_fn(entry):
            return classification
    return None


def classify_entries(entries: list) -> list:
    """Enrich log entries with a 'threat' key (ThreatClassification or None)."""
    for entry in entries:
        entry["threat"] = classify_entry(entry)
    return entries
