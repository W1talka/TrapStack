from collections import Counter

from flask import Blueprint, render_template, current_app

from app.crowdsec_client import get_client

bp = Blueprint("dashboard", __name__)


@bp.route("/")
def index():
    error = None
    decisions = []
    alerts = []
    stats = {"bans": 0, "alerts_total": 0, "top_scenario": "N/A", "top_country": "N/A"}

    try:
        client = get_client()
        decisions = client.get_decisions()
        alerts = client.get_alerts(limit=100)

        stats["bans"] = len(decisions)
        stats["alerts_total"] = len(alerts)

        # Top scenario from alerts
        scenarios = Counter()
        countries = Counter()
        for alert in alerts:
            scenario = alert.get("scenario", "unknown")
            scenarios[scenario] += 1
            source = alert.get("source", {})
            country = source.get("cn", "??")
            if country:
                countries[country] += 1

        if scenarios:
            stats["top_scenario"] = scenarios.most_common(1)[0][0]
        if countries:
            stats["top_country"] = countries.most_common(1)[0][0]

    except Exception as e:
        error = f"Failed to connect to CrowdSec LAPI: {e}"
        current_app.logger.error(error)

    return render_template(
        "dashboard.html",
        decisions=decisions[:10],
        alerts=alerts[:10],
        stats=stats,
        error=error,
    )


@bp.route("/partials/stats")
def partial_stats():
    """HTMX partial for auto-refreshing stats."""
    error = None
    decisions = []
    alerts = []
    stats = {"bans": 0, "alerts_total": 0, "top_scenario": "N/A", "top_country": "N/A"}

    try:
        client = get_client()
        decisions = client.get_decisions()
        alerts = client.get_alerts(limit=100)

        stats["bans"] = len(decisions)
        stats["alerts_total"] = len(alerts)

        scenarios = Counter()
        countries = Counter()
        for alert in alerts:
            scenarios[alert.get("scenario", "unknown")] += 1
            country = alert.get("source", {}).get("cn", "")
            if country:
                countries[country] += 1

        if scenarios:
            stats["top_scenario"] = scenarios.most_common(1)[0][0]
        if countries:
            stats["top_country"] = countries.most_common(1)[0][0]

    except Exception as e:
        error = str(e)

    return render_template(
        "partials/dashboard_stats.html",
        decisions=decisions[:10],
        stats=stats,
        error=error,
    )
