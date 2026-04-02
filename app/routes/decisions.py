import logging

from fastapi import APIRouter, Request, Form, Query
from fastapi.responses import RedirectResponse, HTMLResponse

from app.crowdsec_client import CrowdSecClient
from app.deps import templates, get_http_client

logger = logging.getLogger("trapstack")

router = APIRouter(prefix="/decisions")

PER_PAGE = 100


@router.get("/")
async def index(
    request: Request,
    search: str = Query(default=""),
    origin: str = Query(default="crowdsec"),
    page: int = Query(default=1, ge=1),
):
    error = None
    decisions = []
    all_origins = []
    search = search.strip()
    origin_filter = origin.strip()

    client = CrowdSecClient(get_http_client())

    try:
        decisions = await client.get_decisions()

        # Extract unique origins for filter chips
        all_origins = sorted(set(d.get("origin", "") for d in decisions if d.get("origin")))

        # Apply origin filter ("all" shows everything)
        if origin_filter and origin_filter != "all":
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
        logger.error(error)

    total = len(decisions)
    total_pages = max(1, (total + PER_PAGE - 1) // PER_PAGE)
    page = min(page, total_pages)
    start = (page - 1) * PER_PAGE
    paginated = decisions[start:start + PER_PAGE]

    return templates.TemplateResponse(
        request,
        "decisions.html",
        {
            "decisions": paginated,
            "total": total,
            "search": search,
            "error": error,
            "page": page,
            "total_pages": total_pages,
            "origins": all_origins,
            "selected_origin": origin_filter,
        },
    )


@router.post("/add")
async def add(
    ip: str = Form(default=""),
    duration: str = Form(default="4h"),
    reason: str = Form(default="Manual ban via GUI"),
):
    ip = ip.strip()
    duration = duration.strip()
    reason = reason.strip()

    msg = ""
    msg_type = "success"

    if not ip:
        msg = "IP address is required"
        msg_type = "error"
    else:
        try:
            client = CrowdSecClient(get_http_client())
            await client.add_decision(ip=ip, duration=duration, reason=reason)
            msg = f"Banned {ip} for {duration}"
        except Exception as e:
            msg = f"Failed to add decision: {e}"
            msg_type = "error"

    response = RedirectResponse(url=f"/decisions/?msg={msg}&msg_type={msg_type}", status_code=303)
    return response


@router.delete("/delete/{decision_id}")
async def delete(request: Request, decision_id: int):
    client = CrowdSecClient(get_http_client())

    try:
        await client.delete_decision(decision_id)
    except Exception:
        pass

    # Return updated table partial for HTMX
    decisions = []
    try:
        decisions = await client.get_decisions()
    except Exception:
        pass

    return templates.TemplateResponse(
        request,
        "partials/decisions_table.html",
        {"decisions": decisions},
    )


@router.get("/partials/table")
async def partial_table(request: Request, search: str = Query(default="")):
    """HTMX partial for the decisions table."""
    decisions = []
    search = search.strip()

    client = CrowdSecClient(get_http_client())

    try:
        decisions = await client.get_decisions()
        if search:
            search_lower = search.lower()
            decisions = [
                d for d in decisions
                if search_lower in d.get("value", "").lower()
                or search_lower in d.get("scenario", "").lower()
            ]
    except Exception:
        pass

    return templates.TemplateResponse(
        request,
        "partials/decisions_table.html",
        {"decisions": decisions},
    )
