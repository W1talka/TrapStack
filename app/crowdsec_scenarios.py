"""Pre-built CrowdSec scenario templates for NPMPlus attack patterns.

Each scenario is a dict that can be written as YAML to the CrowdSec
config directory. The GUI allows deploying/undeploying these.
"""

import os

import yaml

from app import config


SCENARIOS = [
    {
        "id": "npmplus-tls-probing",
        "filename": "npmplus-tls-probing.yaml",
        "severity": "high",
        "description": "Detects IPs sending raw TLS/SSL handshakes to HTTP ports. "
                       "This is a common scanning technique to fingerprint services.",
        "yaml_content": {
            "type": "leaky",
            "name": "crowdsec/npmplus-tls-probing",
            "description": "Ban IPs sending TLS handshakes to HTTP port",
            "filter": (
                'evt.Meta.service == "http" && '
                'evt.Meta.http_status == "400" && '
                'evt.Parsed.request contains "\\\\x16\\\\x03"'
            ),
            "capacity": 2,
            "leakspeed": "30m",
            "blackhole": "1h",
            "labels": {"remediation": True, "service": "http", "confidence": 10},
        },
    },
    {
        "id": "npmplus-rdp-bruteforce",
        "filename": "npmplus-rdp-bruteforce.yaml",
        "severity": "critical",
        "description": "Detects RDP brute force attempts sent to HTTP ports. "
                       "Attackers send mstshash cookies to probe for RDP services.",
        "yaml_content": {
            "type": "leaky",
            "name": "crowdsec/npmplus-rdp-bruteforce",
            "description": "Ban IPs attempting RDP brute force via HTTP",
            "filter": (
                'evt.Meta.service == "http" && '
                'evt.Meta.http_status == "400" && '
                'evt.Parsed.request contains "mstshash="'
            ),
            "capacity": 1,
            "leakspeed": "30m",
            "blackhole": "1h",
            "labels": {"remediation": True, "service": "http", "confidence": 10},
        },
    },
    {
        "id": "npmplus-path-traversal",
        "filename": "npmplus-path-traversal.yaml",
        "severity": "critical",
        "description": "Detects directory traversal attacks attempting to access "
                       "system files like /etc/passwd or execute /bin/sh.",
        "yaml_content": {
            "type": "leaky",
            "name": "crowdsec/npmplus-path-traversal",
            "description": "Ban IPs attempting path traversal attacks",
            "filter": (
                'evt.Meta.service == "http" && '
                '(evt.Parsed.request contains ".%2e" || '
                'evt.Parsed.request contains "%2e." || '
                'evt.Parsed.request contains "/etc/passwd" || '
                'evt.Parsed.request contains "/bin/sh")'
            ),
            "capacity": 1,
            "leakspeed": "30m",
            "blackhole": "1h",
            "labels": {"remediation": True, "service": "http", "confidence": 10},
        },
    },
    {
        "id": "npmplus-ssh-scan",
        "filename": "npmplus-ssh-scan.yaml",
        "severity": "high",
        "description": "Detects SSH protocol handshakes sent to HTTP ports. "
                       "Automated scanners probe for SSH on non-standard ports.",
        "yaml_content": {
            "type": "leaky",
            "name": "crowdsec/npmplus-ssh-scan",
            "description": "Ban IPs sending SSH protocol to HTTP port",
            "filter": (
                'evt.Meta.service == "http" && '
                'evt.Meta.http_status == "400" && '
                'evt.Parsed.request contains "SSH-2.0-"'
            ),
            "capacity": 1,
            "leakspeed": "30m",
            "blackhole": "1h",
            "labels": {"remediation": True, "service": "http", "confidence": 10},
        },
    },
    {
        "id": "npmplus-binary-garbage",
        "filename": "npmplus-binary-garbage.yaml",
        "severity": "medium",
        "description": "Detects non-HTTP binary data sent to HTTP ports. "
                       "Catches miscellaneous protocol probes and fuzzing attempts.",
        "yaml_content": {
            "type": "leaky",
            "name": "crowdsec/npmplus-binary-garbage",
            "description": "Ban IPs sending non-HTTP binary data",
            "filter": (
                'evt.Meta.service == "http" && '
                'evt.Meta.http_status == "400" && '
                'evt.Parsed.request contains "\\\\x"'
            ),
            "capacity": 3,
            "leakspeed": "30m",
            "blackhole": "1h",
            "labels": {"remediation": True, "service": "http", "confidence": 8},
        },
    },
    {
        "id": "npmplus-generic-probe",
        "filename": "npmplus-generic-probe.yaml",
        "severity": "low",
        "description": "Detects IPs probing the server directly by IP with no valid "
                       "hostname. Catches basic reconnaissance scans.",
        "yaml_content": {
            "type": "leaky",
            "name": "crowdsec/npmplus-generic-probe",
            "description": "Ban IPs probing server with no valid hostname",
            "filter": (
                'evt.Meta.service == "http" && '
                'evt.Meta.http_status == "400" && '
                'evt.Parsed.vhost == "_" && '
                'evt.Parsed.request startsWith "GET / "'
            ),
            "capacity": 2,
            "leakspeed": "30m",
            "blackhole": "1h",
            "labels": {"remediation": True, "service": "http", "confidence": 6},
        },
    },
]


def _scenarios_dir():
    return os.path.join(config.CROWDSEC_CONF_DIR, "scenarios")


def is_deployed(scenario):
    """Check if a scenario file exists in the CrowdSec config directory."""
    path = os.path.join(_scenarios_dir(), scenario["filename"])
    return os.path.isfile(path) and os.path.getsize(path) > 0


def deploy(scenario):
    """Write a scenario YAML file to the CrowdSec config directory."""
    path = os.path.join(_scenarios_dir(), scenario["filename"])
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        yaml.dump(scenario["yaml_content"], f, default_flow_style=False, sort_keys=False)


def undeploy(scenario):
    """Remove a scenario file from the CrowdSec config directory."""
    path = os.path.join(_scenarios_dir(), scenario["filename"])
    if os.path.isfile(path):
        os.remove(path)


def get_scenario_by_id(scenario_id):
    """Find a scenario template by its ID."""
    for s in SCENARIOS:
        if s["id"] == scenario_id:
            return s
    return None


def get_all_with_status():
    """Return all scenarios with their deployment status."""
    result = []
    for s in SCENARIOS:
        result.append({**s, "deployed": is_deployed(s)})
    return result
