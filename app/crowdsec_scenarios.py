"""CrowdSec scenario library — loads scenario templates from YAML files.

Scenarios are stored in a persistent directory inside the CrowdSec conf dir
(trapstack-library/) so they survive container rebuilds. Default scenarios
are seeded from the bundled app/scenario_library/ on first run.
"""

import glob
import os
import shutil

import yaml

from app import config

_REQUIRED_KEYS = {"id", "filename", "severity", "description", "yaml_content"}


def _library_dir():
    """Persistent library dir inside the already-mounted CrowdSec conf dir."""
    return os.path.join(config.CROWDSEC_CONF_DIR, "trapstack-library")


def _bundled_dir():
    """Built-in default scenarios shipped with the app image."""
    return os.path.join(os.path.dirname(__file__), "scenario_library")


def seed_defaults():
    """On first run, copy bundled defaults to persistent library dir if empty."""
    lib = _library_dir()
    os.makedirs(lib, exist_ok=True)
    if glob.glob(os.path.join(lib, "*.yaml")):
        return
    for src in glob.glob(os.path.join(_bundled_dir(), "*.yaml")):
        shutil.copy2(src, lib)


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


def get_deployed_scenarios():
    """Scan CrowdSec scenarios dir for deployed scenarios not in the library."""
    sdir = _scenarios_dir()
    if not os.path.isdir(sdir):
        return []

    library_filenames = {s["filename"] for s in _load_scenarios()}

    deployed = []
    for path in sorted(glob.glob(os.path.join(sdir, "*.yaml"))):
        basename = os.path.basename(path)
        if basename in library_filenames:
            continue
        try:
            with open(path) as f:
                data = yaml.safe_load(f)
            if not isinstance(data, dict):
                continue
            is_hub = os.path.islink(path)
            deployed.append({
                "filename": basename,
                "name": data.get("name", basename.replace(".yaml", "")),
                "description": data.get("description", ""),
                "type": data.get("type", ""),
                "filter": data.get("filter", ""),
                "source": "hub" if is_hub else "custom",
            })
        except Exception:
            continue
    return deployed
