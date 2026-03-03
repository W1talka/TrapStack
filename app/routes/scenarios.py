from flask import Blueprint, render_template, request

from app.crowdsec_scenarios import get_all_with_status, get_scenario_by_id, deploy, undeploy

bp = Blueprint("scenarios", __name__, url_prefix="/scenarios")


@bp.route("/")
def index():
    scenarios = get_all_with_status()
    deployed_count = sum(1 for s in scenarios if s["deployed"])
    return render_template(
        "scenarios.html",
        scenarios=scenarios,
        deployed_count=deployed_count,
    )


@bp.route("/deploy", methods=["POST"])
def deploy_scenario():
    """HTMX endpoint: deploy a scenario."""
    scenario_id = request.form.get("id", "")
    scenario = get_scenario_by_id(scenario_id)
    if not scenario:
        return '<span class="text-red-400 text-xs">Scenario not found</span>', 404

    try:
        deploy(scenario)
        return f'''<div class="flex items-center gap-3">
            <span class="px-2.5 py-1 rounded-full text-xs font-semibold bg-cs-success/20 text-green-300 border border-cs-success/30">
                Active
            </span>
            <button hx-post="{ request.url_root.rstrip('/') }/scenarios/undeploy"
                    hx-vals='{{"id": "{scenario_id}"}}'
                    hx-target="#scenario-status-{scenario_id}"
                    hx-swap="innerHTML"
                    class="px-3 py-1.5 text-xs font-medium rounded-lg bg-cs-border hover:bg-cs-muted/30 text-white transition-colors">
                Undeploy
            </button>
        </div>'''
    except Exception as e:
        return f'<span class="text-red-400 text-xs">Error: {e}</span>', 500


@bp.route("/undeploy", methods=["POST"])
def undeploy_scenario():
    """HTMX endpoint: undeploy a scenario."""
    scenario_id = request.form.get("id", "")
    scenario = get_scenario_by_id(scenario_id)
    if not scenario:
        return '<span class="text-red-400 text-xs">Scenario not found</span>', 404

    try:
        undeploy(scenario)
        return f'''<div class="flex items-center gap-3">
            <span class="px-2.5 py-1 rounded-full text-xs font-semibold bg-cs-border text-cs-muted">
                Not deployed
            </span>
            <button hx-post="{ request.url_root.rstrip('/') }/scenarios/deploy"
                    hx-vals='{{"id": "{scenario_id}"}}'
                    hx-target="#scenario-status-{scenario_id}"
                    hx-swap="innerHTML"
                    class="px-3 py-1.5 text-xs font-medium rounded-lg bg-cs-accent hover:bg-blue-600 text-white transition-colors">
                Deploy
            </button>
        </div>'''
    except Exception as e:
        return f'<span class="text-red-400 text-xs">Error: {e}</span>', 500


@bp.route("/deploy-all", methods=["POST"])
def deploy_all():
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
    return f'''<span class="inline-flex items-center gap-2 px-4 py-2 rounded-lg
                     bg-cs-success/20 text-green-300 border border-cs-success/30 text-sm font-medium">
                 <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                   <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
                 </svg>
                 Deployed {deployed} scenarios.{error_text} Refresh page to see updated status.
               </span>'''
