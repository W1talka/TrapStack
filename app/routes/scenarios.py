import io
import logging
import zipfile

import httpx
import yaml
from fastapi import APIRouter, Request, Form, UploadFile, File
from fastapi.responses import HTMLResponse, StreamingResponse

from app import config
from app.crowdsec_scenarios import (
    get_all_with_status, get_deployed_scenarios, get_scenario_by_id,
    deploy, undeploy, _library_dir, _REQUIRED_KEYS,
)
from app.deps import templates

logger = logging.getLogger("trapstack.scenarios")

router = APIRouter(prefix="/scenarios")


@router.get("/")
async def index(request: Request):
    scenarios = get_all_with_status()
    deployed_count = sum(1 for s in scenarios if s["deployed"])
    deployed_external = get_deployed_scenarios()
    return templates.TemplateResponse(
        "scenarios.html",
        {
            "request": request,
            "scenarios": scenarios,
            "deployed_count": deployed_count,
            "deployed_external": deployed_external,
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


@router.get("/backup")
async def backup():
    """Download all scenario library YAML files as a ZIP."""
    import glob as _glob
    import os

    lib = _library_dir()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(_glob.glob(os.path.join(lib, "*.yaml"))):
            zf.write(path, os.path.basename(path))
    buf.seek(0)
    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={"Content-Disposition": "attachment; filename=scenarios-backup.zip"},
    )


@router.post("/upload")
async def upload(file: UploadFile = File(...)):
    """HTMX endpoint: upload a ZIP of scenario YAML files to the library."""
    import os

    if not file.filename or not file.filename.endswith(".zip"):
        return HTMLResponse(
            '<div class="alert alert-error text-sm">Please upload a .zip file.</div>',
            status_code=400,
        )

    try:
        content = await file.read()
        buf = io.BytesIO(content)
        added = 0
        skipped = 0

        with zipfile.ZipFile(buf) as zf:
            for name in zf.namelist():
                if not name.endswith(".yaml"):
                    skipped += 1
                    continue
                # Security: only use the basename, ignore directory structure
                basename = os.path.basename(name)
                if not basename:
                    skipped += 1
                    continue
                raw = zf.read(name)
                try:
                    data = yaml.safe_load(raw)
                except Exception:
                    skipped += 1
                    continue
                if not isinstance(data, dict) or not _REQUIRED_KEYS.issubset(data):
                    skipped += 1
                    continue
                dest = os.path.join(_library_dir(), basename)
                with open(dest, "wb") as f:
                    f.write(raw)
                added += 1

        skip_text = f" ({skipped} skipped)" if skipped else ""
        return HTMLResponse(f'''<div class="alert alert-success text-sm">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
            </svg>
            Imported {added} scenarios{skip_text}. Refresh page to see changes.
        </div>''')
    except zipfile.BadZipFile:
        return HTMLResponse(
            '<div class="alert alert-error text-sm">Invalid ZIP file.</div>',
            status_code=400,
        )


@router.post("/restart-crowdsec")
async def restart_crowdsec():
    """Restart the CrowdSec Docker container via Docker socket API."""
    container = config.CROWDSEC_CONTAINER_NAME
    try:
        transport = httpx.AsyncHTTPTransport(uds="/var/run/docker.sock")
        async with httpx.AsyncClient(transport=transport) as client:
            resp = await client.post(
                f"http://localhost/containers/{container}/restart",
                timeout=30.0,
            )
        if resp.status_code == 204:
            logger.info(f"CrowdSec container '{container}' restarted")
            return HTMLResponse(
                '<span class="badge badge-success gap-1">Restarted</span>'
            )
        logger.error(f"CrowdSec restart failed: {resp.status_code} {resp.text[:200]}")
        return HTMLResponse(
            f'<span class="badge badge-error">Failed: {resp.status_code}</span>'
        )
    except Exception as e:
        logger.exception("CrowdSec restart error")
        return HTMLResponse(
            f'<span class="badge badge-error">Error: {e}</span>'
        )
