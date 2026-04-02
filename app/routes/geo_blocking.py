import logging

from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse

from app import config
from app.countries import COUNTRIES, NUMERIC_TO_ALPHA2
from app.crowdsec_client import CrowdSecClient
from app.deps import templates, get_http_client

logger = logging.getLogger("trapstack.geo")

router = APIRouter(prefix="/geo-blocking")


@router.get("/")
async def index(request: Request):
    blocked = {}
    error = None

    try:
        client = CrowdSecClient(get_http_client())
        decisions = await client.get_decisions()
        # Collect country-scoped decisions
        for d in decisions:
            if d.get("scope") == "Country":
                code = d.get("value", "").upper()
                if code in COUNTRIES:
                    blocked[code] = {
                        "id": d.get("id"),
                        "name": COUNTRIES[code],
                        "duration": d.get("duration", ""),
                        "origin": d.get("origin", ""),
                    }
    except Exception as e:
        error = f"Failed to fetch decisions: {e}"
        logger.error(error)

    return templates.TemplateResponse(
        request,
        "geo_blocking.html",
        {
            "countries": COUNTRIES,
            "blocked": blocked,
            "blocked_count": len(blocked),
            "numeric_map": NUMERIC_TO_ALPHA2,
            "error": error,
        },
    )


@router.post("/block")
async def block_countries(
    countries: str = Form(default=""),
    duration: str = Form(default="8760h"),
    mode: str = Form(default="blacklist"),
):
    """Block or whitelist countries. Returns updated page via redirect."""
    selected = {c.strip().upper() for c in countries.split(",") if c.strip()}

    if mode == "whitelist":
        # Block everything EXCEPT selected
        to_block = {code for code in COUNTRIES if code not in selected}
    else:
        to_block = selected

    if not to_block:
        return HTMLResponse(
            '<div class="alert alert-warning text-sm">No countries selected.</div>'
        )

    try:
        client = CrowdSecClient(get_http_client())

        # First remove existing country blocks to avoid duplicates
        decisions = await client.get_decisions()
        for d in decisions:
            if d.get("scope") == "Country" and d.get("value", "").upper() in to_block:
                try:
                    await client.delete_decision(d["id"])
                except Exception:
                    pass

        # Add new blocks
        bulk = [
            {
                "scope": "Country",
                "value": code,
                "duration": duration,
                "reason": f"Geo {'whitelist' if mode == 'whitelist' else 'blacklist'} via TrapStack",
            }
            for code in sorted(to_block)
        ]
        await client.add_decisions_bulk(bulk)

        action = "Whitelisted" if mode == "whitelist" else "Blocked"
        count = len(to_block)
        return HTMLResponse(
            f'<div class="alert alert-success text-sm">'
            f'{action} {count} countries for {duration}. Refresh to update map.</div>'
        )
    except Exception as e:
        logger.exception("Failed to block countries")
        return HTMLResponse(
            f'<div class="alert alert-error text-sm">Failed: {e}</div>'
        )


@router.post("/remove")
async def remove_country(country: str = Form(default="")):
    """Remove all blocks for a specific country."""
    country = country.strip().upper()
    if not country:
        return HTMLResponse('<span class="text-error text-xs">No country</span>')

    try:
        client = CrowdSecClient(get_http_client())
        decisions = await client.get_decisions()
        removed = 0
        for d in decisions:
            if d.get("scope") == "Country" and d.get("value", "").upper() == country:
                await client.delete_decision(d["id"])
                removed += 1

        name = COUNTRIES.get(country, country)
        return HTMLResponse(
            f'<span class="badge badge-success badge-sm">Removed {name}</span>'
        )
    except Exception as e:
        return HTMLResponse(f'<span class="badge badge-error badge-sm">Error: {e}</span>')


@router.post("/clear-all")
async def clear_all():
    """Remove all country-scoped decisions."""
    try:
        client = CrowdSecClient(get_http_client())
        decisions = await client.get_decisions()
        removed = 0
        for d in decisions:
            if d.get("scope") == "Country":
                try:
                    await client.delete_decision(d["id"])
                    removed += 1
                except Exception:
                    pass

        return HTMLResponse(
            f'<div class="alert alert-success text-sm">Removed {removed} country blocks. Refresh to update map.</div>'
        )
    except Exception as e:
        return HTMLResponse(
            f'<div class="alert alert-error text-sm">Failed: {e}</div>'
        )
