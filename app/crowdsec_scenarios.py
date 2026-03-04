"""CrowdSec scenario library — loads scenario templates from YAML files.

Scenarios live in app/scenario_library/ as individual YAML files.
The GUI allows deploying/undeploying these to the CrowdSec config directory.
"""

import glob
import os

import yaml

from app import config

_REQUIRED_KEYS = {"id", "filename", "severity", "description", "yaml_content"}


def _library_dir():
    """Path to the scenario library folder shipped with the app."""
    return os.path.join(os.path.dirname(__file__), "scenario_library")


def _load_scenarios():
    """Read all .yaml files from the scenario library folder."""
    lib = _library_dir()
    scenarios = []
    for path in sorted(glob.glob(os.path.join(lib, "*.yaml"))):
        try:
            with open(path) as f:
                data = yaml.safe_load(f)
            if isinstance(data, dict) and _REQUIRED_KEYS.issubset(data):
                scenarios.append(data)
        except Exception:
            continue
    return scenarios


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
    for s in _load_scenarios():
        if s["id"] == scenario_id:
            return s
    return None


def get_all_with_status():
    """Return all scenarios with their deployment status."""
    return [{**s, "deployed": is_deployed(s)} for s in _load_scenarios()]
