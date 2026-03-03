from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse

from app.crowdsec_scenarios import get_all_with_status, get_scenario_by_id, deploy, undeploy
from app.deps import templates

router = APIRouter(prefix="/scenarios")


@router.get("/")
async def index(request: Request):
    scenarios = get_all_with_status()
    deployed_count = sum(1 for s in scenarios if s["deployed"])
    return templates.TemplateResponse(
        "scenarios.html",
        {
            "request": request,
            "scenarios": scenarios,
            "deployed_count": deployed_count,
        },
    )


@router.post("/deploy")
async def deploy_scenario(id: str = Form(default="")):
    """HTMX endpoint: deploy a scenario."""
    scenario = get_scenario_by_id(id)
    if not scenario:
        return HTMLResponse('<span class="text-error text-xs">Scenario not found</span>', status_code=404)

    try:
        deploy(scenario)
        return HTMLResponse(f'''<div class="flex items-center gap-3">
            <span class="badge badge-success">Active</span>
            <button hx-post="/scenarios/undeploy"
                    hx-vals='{{"id": "{id}"}}'
                    hx-target="#scenario-status-{id}"
                    hx-swap="innerHTML"
                    class="btn btn-ghost btn-xs">
                Undeploy
            </button>
        </div>''')
    except Exception as e:
        return HTMLResponse(f'<span class="text-error text-xs">Error: {e}</span>', status_code=500)


@router.post("/undeploy")
async def undeploy_scenario(id: str = Form(default="")):
    """HTMX endpoint: undeploy a scenario."""
    scenario = get_scenario_by_id(id)
    if not scenario:
        return HTMLResponse('<span class="text-error text-xs">Scenario not found</span>', status_code=404)

    try:
        undeploy(scenario)
        return HTMLResponse(f'''<div class="flex items-center gap-3">
            <span class="badge badge-ghost">Not deployed</span>
            <button hx-post="/scenarios/deploy"
                    hx-vals='{{"id": "{id}"}}'
                    hx-target="#scenario-status-{id}"
                    hx-swap="innerHTML"
                    class="btn btn-primary btn-xs">
                Deploy
            </button>
        </div>''')
    except Exception as e:
        return HTMLResponse(f'<span class="text-error text-xs">Error: {e}</span>', status_code=500)


@router.post("/deploy-all")
async def deploy_all():
    """HTMX endpoint: deploy all scenarios at once."""
    scenarios = get_all_with_status()
    deployed = 0
    errors = 0
    for s in scenarios:
        if not s["deployed"]:
            try:
                deploy(s)
                deployed += 1
            except Exception:
                errors += 1

    error_text = f" {errors} failed." if errors else ""
    return HTMLResponse(f'''<div class="alert alert-success">
                 <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                   <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
                 </svg>
                 Deployed {deployed} scenarios.{error_text} Refresh page to see updated status.
               </div>''')
