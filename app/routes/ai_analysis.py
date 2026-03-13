"""AI-powered log analysis routes.

Analyzes recent nginx access logs with an LLM and generates
CrowdSec scenario recommendations.
"""

import html
import json
import logging
import os
import re

import yaml
from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse

from app import config
from app.ai_client import AIClient
from app.crowdsec_scenarios import deploy, _library_dir, _REQUIRED_KEYS
from app.deps import templates, get_http_client
from app.log_analyzer import analyze_logs, build_prompt

logger = logging.getLogger("trapstack.ai")

router = APIRouter(prefix="/ai-analysis")


def _get_ai_client():
    return AIClient(get_http_client())


async def _get_public_ip():
    """Fetch server's public IP for trusted IP auto-detection. Non-critical."""
    try:
        resp = await get_http_client().get("https://api.ipify.org", timeout=5.0)
        if resp.status_code == 200:
            ip = resp.text.strip()
            logger.info(f"Auto-detected public IP: {ip}")
            return ip
    except Exception:
        logger.debug("Could not auto-detect public IP")
    return None


def _sanitize_id(raw_id):
    """Sanitize a scenario ID to only allow safe characters."""
    return re.sub(r"[^a-z0-9-]", "", raw_id.lower().strip())


def _strip_code_fences(text):
    """Strip markdown code fences from AI response."""
    text = text.strip()
    m = re.search(r"```(?:json)?\s*\n?(.*?)```", text, re.DOTALL)
    if m:
        return m.group(1).strip()
    return text


def _validate_recommendation(rec):
    """Validate a single AI recommendation. Returns (cleaned_rec, error).

    Handles both flat format (from local models) and nested yaml_content format.
    Flat fields: scenario_name, scenario_description, filter, capacity, leakspeed, blackhole, confidence
    """
    # Reconstruct yaml_content from flat fields if not present
    if "yaml_content" not in rec and "filter" in rec:
        rec["yaml_content"] = {
            "type": "leaky",
            "name": rec.get("scenario_name", f"crowdsec/npmplus-{rec.get('id', 'unknown')}"),
            "description": rec.get("scenario_description", rec.get("description", "")),
            "filter": rec["filter"],
            "capacity": rec.get("capacity", 3),
            "leakspeed": rec.get("leakspeed", "30m"),
            "blackhole": rec.get("blackhole", "1h"),
            "labels": {
                "remediation": True,
                "service": "http",
                "confidence": rec.get("confidence", 5),
            },
        }
        # Use scenario_description for the card if present, fall back to description
        if "scenario_description" in rec and "description" not in rec:
            rec["description"] = rec["scenario_description"]
        elif "description" not in rec:
            rec["description"] = rec.get("scenario_description", "")

    required = {"id", "title", "severity", "evidence"}
    if not required.issubset(rec.keys()):
        return None, f"Missing fields: {required - rec.keys()}"

    if "yaml_content" not in rec:
        return None, "Missing yaml_content and no flat filter field"

    yc = rec["yaml_content"]
    yaml_required = {"type", "name", "filter", "capacity", "leakspeed", "blackhole"}
    if not yaml_required.issubset(yc.keys()):
        return None, f"Missing YAML fields: {yaml_required - yc.keys()}"

    # Validate YAML round-trip
    try:
        yaml.safe_load(yaml.dump(yc))
    except Exception as e:
        return None, f"Invalid YAML: {e}"

    # Sanitize ID
    rec["id"] = _sanitize_id(rec["id"])
    if not rec["id"]:
        return None, "Empty ID after sanitization"

    # Ensure severity is valid
    if rec["severity"] not in ("critical", "high", "medium", "low"):
        rec["severity"] = "medium"

    # Ensure description exists
    if "description" not in rec:
        rec["description"] = yc.get("description", "")

    return rec, None


@router.get("/")
async def index(request: Request):
    client = _get_ai_client()
    return templates.TemplateResponse(
        "ai_analysis.html",
        {
            "request": request,
            "ai_configured": client.is_configured(),
            "ai_provider": config.AI_PROVIDER,
            "ai_model": client.model if client.is_configured() else "",
        },
    )


@router.post("/run")
async def run_analysis(request: Request):
    """HTMX endpoint: run AI log analysis and return results."""
    client = _get_ai_client()
    if not client.is_configured():
        return HTMLResponse('<div class="alert alert-error">AI is not configured.</div>')

    # Build trusted IPs set (static config + auto-detected public IP)
    trusted_ips = set(config.TRUSTED_IPS)
    public_ip = await _get_public_ip()
    if public_ip:
        trusted_ips.add(public_ip)

    # Analyze logs
    try:
        analysis = analyze_logs(trusted_ips=trusted_ips)
    except Exception as e:
        logger.exception("Log analysis failed")
        return HTMLResponse(f'<div class="alert alert-error">Failed to read logs: {e}</div>')

    if not analysis:
        return HTMLResponse('<div class="alert alert-warning">No recent log entries found to analyze.</div>')

    # Build prompt and call AI
    user_prompt = build_prompt(analysis)

    try:
        raw_response = await client.analyze(user_prompt)
    except Exception as e:
        error_msg = str(e)
        if "401" in error_msg or "403" in error_msg:
            msg = "Invalid AI API key. Check your AI_API_KEY setting."
        elif "429" in error_msg:
            msg = "AI rate limit exceeded. Wait a moment and try again."
        elif "timeout" in error_msg.lower() or "timed out" in error_msg.lower():
            msg = "AI request timed out. Try again."
        else:
            msg = f"AI request failed: {error_msg}"
        logger.error(f"AI call failed: {e}")
        return HTMLResponse(f'<div class="alert alert-error">{msg}</div>')

    # Parse response
    try:
        cleaned = _strip_code_fences(raw_response)
        result = json.loads(cleaned)
    except json.JSONDecodeError:
        return HTMLResponse(
            f'<div class="alert alert-error">AI returned invalid JSON. Raw response:</div>'
            f'<details class="mt-2"><summary class="btn btn-ghost btn-xs">Show raw response</summary>'
            f'<pre class="mt-2 p-3 bg-base-300 rounded text-xs overflow-x-auto whitespace-pre-wrap">{raw_response[:3000]}</pre></details>'
        )

    recommendations = result.get("recommendations", [])
    summary = result.get("summary", "")

    # Validate each recommendation
    valid_recs = []
    for rec in recommendations:
        validated, error = _validate_recommendation(rec)
        if validated:
            # Add filename
            validated["filename"] = f"{validated['id']}.yaml"
            valid_recs.append(validated)
        else:
            logger.warning(f"Skipped invalid recommendation: {error}")

    return templates.TemplateResponse(
        "partials/ai_analysis_results.html",
        {
            "request": request,
            "recommendations": valid_recs,
            "summary": summary,
            "total_entries": analysis["total_entries"],
        },
    )


@router.post("/save")
async def save_scenario(
    scenario_id: str = Form(...),
    title: str = Form(...),
    severity: str = Form(...),
    description: str = Form(...),
    filename: str = Form(...),
    yaml_content: str = Form(...),
):
    """HTMX endpoint: save an AI recommendation to the scenario library."""
    try:
        yc = json.loads(html.unescape(yaml_content))
    except json.JSONDecodeError:
        logger.error(f"Failed to parse yaml_content: {yaml_content[:200]}")
        return HTMLResponse('<span class="badge badge-error">Invalid YAML data</span>')

    # Sanitize
    safe_id = _sanitize_id(scenario_id)
    safe_filename = re.sub(r"[^a-z0-9-.]", "", filename.lower())
    if not safe_filename.endswith(".yaml"):
        safe_filename = f"{safe_id}.yaml"

    # Build scenario dict
    scenario = {
        "id": safe_id,
        "filename": safe_filename,
        "severity": severity,
        "description": description,
        "yaml_content": yc,
    }

    # Validate required keys
    if not _REQUIRED_KEYS.issubset(scenario.keys()):
        return HTMLResponse('<span class="badge badge-error">Missing required fields</span>')

    # Path safety
    lib = _library_dir()
    dest = os.path.join(lib, safe_filename)
    if not os.path.abspath(dest).startswith(os.path.abspath(lib)):
        return HTMLResponse('<span class="badge badge-error">Invalid filename</span>')

    # Write to library
    try:
        os.makedirs(lib, exist_ok=True)
        with open(dest, "w") as f:
            yaml.dump(scenario, f, default_flow_style=False, sort_keys=False)
    except Exception as e:
        return HTMLResponse(f'<span class="badge badge-error">Save failed: {e}</span>')

    return HTMLResponse(f'''
        <div class="flex items-center gap-2">
            <span class="badge badge-success gap-1">
                <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
                </svg>
                Saved to Library
            </span>
            <span class="text-xs text-base-content/60">Deploy from Scenarios page</span>
        </div>
    ''')


@router.post("/deploy")
async def deploy_scenario(
    scenario_id: str = Form(...),
    title: str = Form(...),
    severity: str = Form(...),
    description: str = Form(...),
    filename: str = Form(...),
    yaml_content: str = Form(...),
):
    """HTMX endpoint: save and deploy an AI recommendation."""
    try:
        yc = json.loads(html.unescape(yaml_content))
    except json.JSONDecodeError:
        logger.error(f"Failed to parse yaml_content: {yaml_content[:200]}")
        return HTMLResponse('<span class="badge badge-error">Invalid YAML data</span>')

    safe_id = _sanitize_id(scenario_id)
    safe_filename = re.sub(r"[^a-z0-9-.]", "", filename.lower())
    if not safe_filename.endswith(".yaml"):
        safe_filename = f"{safe_id}.yaml"

    scenario = {
        "id": safe_id,
        "filename": safe_filename,
        "severity": severity,
        "description": description,
        "yaml_content": yc,
    }

    if not _REQUIRED_KEYS.issubset(scenario.keys()):
        return HTMLResponse('<span class="badge badge-error">Missing required fields</span>')

    lib = _library_dir()
    dest = os.path.join(lib, safe_filename)
    if not os.path.abspath(dest).startswith(os.path.abspath(lib)):
        return HTMLResponse('<span class="badge badge-error">Invalid filename</span>')

    # Save to library
    try:
        os.makedirs(lib, exist_ok=True)
        with open(dest, "w") as f:
            yaml.dump(scenario, f, default_flow_style=False, sort_keys=False)
    except Exception as e:
        return HTMLResponse(f'<span class="badge badge-error">Save failed: {e}</span>')

    # Deploy to CrowdSec
    try:
        deploy(scenario)
    except Exception as e:
        return HTMLResponse(f'''
            <div class="flex items-center gap-2">
                <span class="badge badge-success">Saved</span>
                <span class="badge badge-error">Deploy failed: {e}</span>
            </div>
        ''')

    return HTMLResponse(f'''
        <div class="flex items-center gap-2">
            <span class="badge badge-success gap-1">
                <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
                </svg>
                Deployed
            </span>
            <span class="text-xs text-base-content/60">Restart CrowdSec to activate</span>
        </div>
    ''')
