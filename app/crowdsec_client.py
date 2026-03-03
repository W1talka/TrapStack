import time

import requests
from flask import current_app


class CrowdSecClient:
    """CrowdSec LAPI client.

    Uses bouncer API key for read operations (GET /v1/decisions).
    Uses machine auth (login + JWT) for write operations (add/delete decisions, alerts).
    """

    _jwt_token = None
    _jwt_expires = 0

    def __init__(self, base_url=None, api_key=None, machine_id=None, machine_password=None):
        self.base_url = (base_url or current_app.config["CROWDSEC_LAPI_URL"]).rstrip("/")
        self.api_key = api_key or current_app.config["CROWDSEC_API_KEY"]
        self.machine_id = machine_id or current_app.config.get("CROWDSEC_MACHINE_ID", "")
        self.machine_password = machine_password or current_app.config.get("CROWDSEC_MACHINE_PASSWORD", "")

    def _bouncer_headers(self):
        return {"X-Api-Key": self.api_key}

    def _machine_headers(self):
        token = self._get_jwt()
        return {"Authorization": f"Bearer {token}"}

    def _get_jwt(self):
        """Login with machine credentials to get a JWT token."""
        if CrowdSecClient._jwt_token and time.time() < CrowdSecClient._jwt_expires:
            return CrowdSecClient._jwt_token

        if not self.machine_id or not self.machine_password:
            raise RuntimeError(
                "Machine credentials not configured. "
                "Set CROWDSEC_MACHINE_ID and CROWDSEC_MACHINE_PASSWORD in .env. "
                "Create them with: cscli machines add <name> -p <password>"
            )

        resp = requests.post(
            f"{self.base_url}/v1/watchers/login",
            json={"machine_id": self.machine_id, "password": self.machine_password},
            timeout=5,
        )
        resp.raise_for_status()
        data = resp.json()
        CrowdSecClient._jwt_token = data["token"]
        # Refresh 5 min before expiry (tokens typically last 1h)
        CrowdSecClient._jwt_expires = time.time() + 3300
        return CrowdSecClient._jwt_token

    def _get(self, path, params=None, use_machine=False):
        headers = self._machine_headers() if use_machine else self._bouncer_headers()
        resp = requests.get(f"{self.base_url}{path}", params=params, headers=headers, timeout=5)
        resp.raise_for_status()
        return resp.json()

    def _post(self, path, json_data, use_machine=False):
        headers = self._machine_headers() if use_machine else self._bouncer_headers()
        resp = requests.post(f"{self.base_url}{path}", json=json_data, headers=headers, timeout=5)
        resp.raise_for_status()
        return resp.json() if resp.content else None

    def _delete(self, path, params=None, use_machine=False):
        headers = self._machine_headers() if use_machine else self._bouncer_headers()
        resp = requests.delete(f"{self.base_url}{path}", params=params, headers=headers, timeout=5)
        resp.raise_for_status()
        return resp.json() if resp.content else None

    # --- Read operations (bouncer key) ---

    def get_decisions(self):
        """Get all active decisions (bans/captchas)."""
        try:
            return self._get("/v1/decisions") or []
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                return []
            raise

    # --- Write operations (machine auth) ---

    def add_decision(self, ip, duration, reason, action="ban", scope="Ip"):
        """Add a manual decision via machine auth."""
        payload = [
            {
                "duration": duration,
                "origin": "crowdsec-gui",
                "reason": reason,
                "scope": scope,
                "type": action,
                "value": ip,
            }
        ]
        return self._post("/v1/decisions", payload, use_machine=True)

    def delete_decision(self, decision_id):
        """Delete a decision by ID via machine auth."""
        return self._delete(f"/v1/decisions/{decision_id}", use_machine=True)

    # --- Alerts (machine auth) ---

    def get_alerts(self, limit=50):
        """Get recent alerts via machine auth."""
        try:
            return self._get("/v1/alerts", params={"limit": limit}, use_machine=True) or []
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                return []
            raise

    def get_alert_detail(self, alert_id):
        """Get a single alert with full detail."""
        return self._get(f"/v1/alerts/{alert_id}", use_machine=True)


def get_client():
    """Get a CrowdSec client using Flask app config."""
    return CrowdSecClient()
