import logging
from collections import Counter

from fastapi import APIRouter, Request

from app.crowdsec_client import CrowdSecClient
from app.crowdsec_scenarios import get_all_with_status
from app.deps import templates, get_http_client

logger = logging.getLogger("trapstack")

router = APIRouter()


@router.get("/")
async def index(request: Request):
    error = None
    decisions = []
    alerts = []
    stats = {"bans": 0, "alerts_total": 0, "top_scenario": "N/A", "top_country": "N/A",
             "scenarios_deployed": 0, "scenarios_total": 0}

    client = CrowdSecClient(get_http_client())

    try:
        all_scenarios = get_all_with_status()
        stats["scenarios_total"] = len(all_scenarios)
        stats["scenarios_deployed"] = sum(1 for s in all_scenarios if s["deployed"])
    except Exception:
        pass

    try:
        decisions = await client.get_decisions()
        stats["bans"] = len(decisions)
    except Exception as e:
        error = f"Failed to connect to CrowdSec LAPI: {e}"
        logger.error(error)

    try:
        alerts = await client.get_alerts(limit=100)
        stats["alerts_total"] = len(alerts)

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
        logger.warning(f"Could not fetch alerts: {e}")

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "decisions": decisions[:10],
            "alerts": alerts[:10],
            "stats": stats,
            "error": error,
        },
    )


@router.get("/partials/stats")
async def partial_stats(request: Request):
    """HTMX partial for auto-refreshing stats."""
    error = None
    decisions = []
    alerts = []
    stats = {"bans": 0, "alerts_total": 0, "top_scenario": "N/A", "top_country": "N/A",
             "scenarios_deployed": 0, "scenarios_total": 0}

    client = CrowdSecClient(get_http_client())

    try:
        all_scenarios = get_all_with_status()
        stats["scenarios_total"] = len(all_scenarios)
        stats["scenarios_deployed"] = sum(1 for s in all_scenarios if s["deployed"])
    except Exception:
        pass

    try:
        decisions = await client.get_decisions()
        stats["bans"] = len(decisions)
    except Exception as e:
        error = str(e)

    try:
        alerts = await client.get_alerts(limit=100)
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
    except Exception:
        pass

    return templates.TemplateResponse(
        "partials/dashboard_stats.html",
        {
            "request": request,
            "decisions": decisions[:10],
            "stats": stats,
            "error": error,
        },
    )
