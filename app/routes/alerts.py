from flask import Blueprint, render_template, request, current_app

from app.crowdsec_client import get_client

bp = Blueprint("alerts", __name__, url_prefix="/alerts")


@bp.route("/")
def index():
    error = None
    alerts = []
    scenario_filter = request.args.get("scenario", "").strip()

    try:
        client = get_client()
        alerts = client.get_alerts(limit=200)

        # Extract unique scenarios for filter dropdown
        all_scenarios = sorted(set(a.get("scenario", "") for a in alerts if a.get("scenario")))

        if scenario_filter:
            alerts = [a for a in alerts if a.get("scenario") == scenario_filter]

    except Exception as e:
        error = f"Failed to fetch alerts: {e}"
        current_app.logger.error(error)
        all_scenarios = []

    return render_template(
        "alerts.html",
        alerts=alerts,
        all_scenarios=all_scenarios,
        scenario_filter=scenario_filter,
        error=error,
    )


@bp.route("/detail/<int:alert_id>")
def detail(alert_id):
    """HTMX partial: expanded alert detail row."""
    try:
        client = get_client()
        alert = client.get_alert_detail(alert_id)
    except Exception:
        alert = None

    return render_template("partials/alert_detail.html", alert=alert)
