from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app

from app.crowdsec_client import get_client

bp = Blueprint("decisions", __name__, url_prefix="/decisions")


PER_PAGE = 100


@bp.route("/")
def index():
    error = None
    decisions = []
    search = request.args.get("search", "").strip()
    origin_filter = request.args.get("origin", "").strip()
    page = max(1, int(request.args.get("page", 1)))
    all_origins = []

    try:
        client = get_client()
        decisions = client.get_decisions()

        # Extract unique origins for filter chips
        all_origins = sorted(set(d.get("origin", "") for d in decisions if d.get("origin")))

        # Apply origin filter
        if origin_filter:
            decisions = [d for d in decisions if d.get("origin") == origin_filter]

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

    total = len(decisions)
    total_pages = max(1, (total + PER_PAGE - 1) // PER_PAGE)
    page = min(page, total_pages)
    start = (page - 1) * PER_PAGE
    paginated = decisions[start:start + PER_PAGE]

    return render_template(
        "decisions.html",
        decisions=paginated,
        total=total,
        search=search,
        error=error,
        page=page,
        total_pages=total_pages,
        origins=all_origins,
        selected_origin=origin_filter,
    )


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
