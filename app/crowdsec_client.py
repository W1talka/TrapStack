import requests
from flask import current_app


class CrowdSecClient:
    def __init__(self, base_url=None, api_key=None):
        self.base_url = (base_url or current_app.config["CROWDSEC_LAPI_URL"]).rstrip("/")
        self.api_key = api_key or current_app.config["CROWDSEC_API_KEY"]
        self.session = requests.Session()
        self.session.headers.update({"X-Api-Key": self.api_key})
        self.session.timeout = 5

    def _get(self, path, params=None):
        resp = self.session.get(f"{self.base_url}{path}", params=params)
        resp.raise_for_status()
        return resp.json()

    def _post(self, path, json_data):
        resp = self.session.post(f"{self.base_url}{path}", json=json_data)
        resp.raise_for_status()
        return resp.json() if resp.content else None

    def _delete(self, path, params=None):
        resp = self.session.delete(f"{self.base_url}{path}", params=params)
        resp.raise_for_status()
        return resp.json() if resp.content else None

    def get_decisions(self):
        """Get all active decisions (bans/captchas)."""
        try:
            return self._get("/v1/decisions") or []
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                return []
            raise

    def add_decision(self, ip, duration, reason, action="ban", scope="Ip"):
        """Add a manual decision."""
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
        return self._post("/v1/decisions", payload)

    def delete_decision(self, decision_id):
        """Delete a decision by ID."""
        return self._delete(f"/v1/decisions/{decision_id}")

    def get_alerts(self, limit=50):
        """Get recent alerts."""
        try:
            return self._get("/v1/alerts", params={"limit": limit}) or []
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                return []
            raise

    def get_alert_detail(self, alert_id):
        """Get a single alert with full detail."""
        return self._get(f"/v1/alerts/{alert_id}")


def get_client():
    """Get a CrowdSec client using Flask app config."""
    return CrowdSecClient()
