import os

import yaml
from fastapi import APIRouter, Request, Form, Query
from fastapi.responses import RedirectResponse

from app import config
from app.deps import templates

router = APIRouter(prefix="/config")

# Editable directories relative to CROWDSEC_CONF_DIR
EDITABLE_DIRS = {
    "Custom Scenarios": "scenarios",
    "Acquisition": "acquis.d",
    "Whitelists (Postoverflows)": "postoverflows/s01-whitelist",
}


def _get_conf_dir():
    return config.CROWDSEC_CONF_DIR


def _list_files():
    """List all editable YAML files grouped by category."""
    conf_dir = _get_conf_dir()
    groups = {}

    for label, subdir in EDITABLE_DIRS.items():
        full_path = os.path.join(conf_dir, subdir)
        files = []
        if os.path.isdir(full_path):
            for f in sorted(os.listdir(full_path)):
                if f.endswith((".yaml", ".yml")):
                    files.append({
                        "name": f,
                        "path": os.path.join(subdir, f),
                    })
        if files:
            groups[label] = files

    return groups


@router.get("/")
async def index(
    request: Request,
    file: str = Query(default=""),
    msg: str = Query(default=""),
    msg_type: str = Query(default=""),
):
    selected = file
    content = ""
    error = None

    file_groups = _list_files()

    if selected:
        full_path = os.path.join(_get_conf_dir(), selected)
        # Prevent path traversal
        if not os.path.abspath(full_path).startswith(os.path.abspath(_get_conf_dir())):
            return RedirectResponse(url="/config/?msg=Invalid+file+path&msg_type=error", status_code=303)
        try:
            with open(full_path) as f:
                content = f.read()
        except FileNotFoundError:
            error = f"File not found: {selected}"
        except Exception as e:
            error = f"Error reading file: {e}"

    return templates.TemplateResponse(
        request,
        "config_editor.html",
        {
            "file_groups": file_groups,
            "selected": selected,
            "content": content,
            "error": error,
            "msg": msg,
            "msg_type": msg_type,
        },
    )


@router.post("/save")
async def save(
    file: str = Form(default=""),
    content: str = Form(default=""),
):
    file_path = file.strip()

    if not file_path:
        return RedirectResponse(url="/config/?msg=No+file+selected&msg_type=error", status_code=303)

    full_path = os.path.join(_get_conf_dir(), file_path)

    # Prevent path traversal
    if not os.path.abspath(full_path).startswith(os.path.abspath(_get_conf_dir())):
        return RedirectResponse(url="/config/?msg=Invalid+file+path&msg_type=error", status_code=303)

    # Validate YAML
    try:
        list(yaml.safe_load_all(content))
    except yaml.YAMLError as e:
        msg = f"Invalid YAML: {e}"
        return RedirectResponse(
            url=f"/config/?file={file_path}&msg={msg}&msg_type=error",
            status_code=303,
        )

    try:
        with open(full_path, "w") as f:
            f.write(content)
        msg = f"Saved {file_path}"
        msg_type = "success"
    except Exception as e:
        msg = f"Failed to save: {e}"
        msg_type = "error"

    return RedirectResponse(
        url=f"/config/?file={file_path}&msg={msg}&msg_type={msg_type}",
        status_code=303,
    )
