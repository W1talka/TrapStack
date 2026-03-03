from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app

from app.crowdsec_client import get_client

bp = Blueprint("decisions", __name__, url_prefix="/decisions")


@bp.route("/")
def index():
    error = None
    decisions = []
    search = request.args.get("search", "").strip()

    try:
        client = get_client()
        decisions = client.get_decisions()

        if search:
            search_lower = search.lower()
            decisions = [
                d for d in decisions
                if search_lower in d.get("value", "").lower()
                or search_lower in d.get("scenario", "").lower()
                or search_lower in d.get("origin", "").lower()
            ]

    except Exception as e:
        error = f"Failed to fetch decisions: {e}"
        current_app.logger.error(error)

    return render_template("decisions.html", decisions=decisions, search=search, error=error)


@bp.route("/add", methods=["POST"])
def add():
    ip = request.form.get("ip", "").strip()
    duration = request.form.get("duration", "4h").strip()
    reason = request.form.get("reason", "Manual ban via GUI").strip()

    if not ip:
        flash("IP address is required", "error")
        return redirect(url_for("decisions.index"))

    try:
        client = get_client()
        client.add_decision(ip=ip, duration=duration, reason=reason)
        flash(f"Banned {ip} for {duration}", "success")
    except Exception as e:
        flash(f"Failed to add decision: {e}", "error")

    return redirect(url_for("decisions.index"))


@bp.route("/delete/<int:decision_id>", methods=["DELETE"])
def delete(decision_id):
    try:
        client = get_client()
        client.delete_decision(decision_id)
    except Exception:
        pass

    # Return updated table partial for HTMX
    decisions = []
    try:
        client = get_client()
        decisions = client.get_decisions()
    except Exception:
        pass

    return render_template("partials/decisions_table.html", decisions=decisions)


@bp.route("/partials/table")
def partial_table():
    """HTMX partial for the decisions table."""
    decisions = []
    search = request.args.get("search", "").strip()

    try:
        client = get_client()
        decisions = client.get_decisions()
        if search:
            search_lower = search.lower()
            decisions = [
                d for d in decisions
                if search_lower in d.get("value", "").lower()
                or search_lower in d.get("scenario", "").lower()
            ]
    except Exception:
        pass

    return render_template("partials/decisions_table.html", decisions=decisions)
