import os

import yaml
from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app

bp = Blueprint("config_editor", __name__, url_prefix="/config")

# Editable directories relative to CROWDSEC_CONF_DIR
EDITABLE_DIRS = {
    "Custom Scenarios": "scenarios",
    "Acquisition": "acquis.d",
    "Whitelists (Postoverflows)": "postoverflows/s01-whitelist",
}


def _get_conf_dir():
    return current_app.config["CROWDSEC_CONF_DIR"]


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


@bp.route("/")
def index():
    selected = request.args.get("file", "")
    content = ""
    error = None

    file_groups = _list_files()

    if selected:
        full_path = os.path.join(_get_conf_dir(), selected)
        # Prevent path traversal (use abspath to allow symlinks)
        if not os.path.abspath(full_path).startswith(os.path.abspath(_get_conf_dir())):
            flash("Invalid file path", "error")
            return redirect(url_for("config_editor.index"))
        try:
            with open(full_path) as f:
                content = f.read()
        except FileNotFoundError:
            error = f"File not found: {selected}"
        except Exception as e:
            error = f"Error reading file: {e}"

    return render_template(
        "config_editor.html",
        file_groups=file_groups,
        selected=selected,
        content=content,
        error=error,
    )


@bp.route("/save", methods=["POST"])
def save():
    file_path = request.form.get("file", "").strip()
    content = request.form.get("content", "")

    if not file_path:
        flash("No file selected", "error")
        return redirect(url_for("config_editor.index"))

    full_path = os.path.join(_get_conf_dir(), file_path)

    # Prevent path traversal (use abspath to allow symlinks)
    if not os.path.abspath(full_path).startswith(os.path.abspath(_get_conf_dir())):
        flash("Invalid file path", "error")
        return redirect(url_for("config_editor.index"))

    # Validate YAML
    try:
        list(yaml.safe_load_all(content))
    except yaml.YAMLError as e:
        flash(f"Invalid YAML: {e}", "error")
        return redirect(url_for("config_editor.index", file=file_path))

    try:
        with open(full_path, "w") as f:
            f.write(content)
        flash(f"Saved {file_path}", "success")
    except Exception as e:
        flash(f"Failed to save: {e}", "error")

    return redirect(url_for("config_editor.index", file=file_path))
