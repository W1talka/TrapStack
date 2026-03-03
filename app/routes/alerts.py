import logging

from fastapi import APIRouter, Request, Query

from app.crowdsec_client import CrowdSecClient
from app.deps import templates, get_http_client

logger = logging.getLogger("crowdsec-gui")

router = APIRouter(prefix="/alerts")

PER_PAGE = 100


@router.get("/")
async def index(
    request: Request,
    scenario: str = Query(default=""),
    page: int = Query(default=1, ge=1),
):
    error = None
    alerts = []
    all_scenarios = []
    scenario_filter = scenario.strip()

    client = CrowdSecClient(get_http_client())

    try:
        alerts = await client.get_alerts(limit=500)

        # Extract unique scenarios for filter dropdown
        all_scenarios = sorted(set(a.get("scenario", "") for a in alerts if a.get("scenario")))

        if scenario_filter:
            alerts = [a for a in alerts if a.get("scenario") == scenario_filter]

    except Exception as e:
        error = f"Failed to fetch alerts: {e}"
        logger.error(error)

    total = len(alerts)
    total_pages = max(1, (total + PER_PAGE - 1) // PER_PAGE)
    page = min(page, total_pages)
    start = (page - 1) * PER_PAGE
    paginated = alerts[start:start + PER_PAGE]

    return templates.TemplateResponse(
        "alerts.html",
        {
            "request": request,
            "alerts": paginated,
            "total": total,
            "all_scenarios": all_scenarios,
            "scenario_filter": scenario_filter,
            "error": error,
            "page": page,
            "total_pages": total_pages,
        },
    )


@router.get("/detail/{alert_id}")
async def detail(request: Request, alert_id: int):
    """HTMX partial: expanded alert detail row."""
    client = CrowdSecClient(get_http_client())

    try:
        alert = await client.get_alert_detail(alert_id)
    except Exception:
        alert = None

    return templates.TemplateResponse(
        "partials/alert_detail.html",
        {"request": request, "alert": alert},
    )
