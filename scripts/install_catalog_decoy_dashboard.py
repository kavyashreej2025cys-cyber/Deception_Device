#!/usr/bin/env python3
"""Install catalog-aware decoy listing and guarded manual activation."""

import ast
import shutil
from pathlib import Path


SOURCE_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = Path.home() / "cyber-deception"


def replace_function(path, function_name, replacement):
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    target = next(
        (
            node
            for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == function_name
        ),
        None,
    )
    if target is None:
        raise RuntimeError(f"Could not find {function_name} in {path}")

    start_line = target.lineno
    if target.decorator_list:
        start_line = min(item.lineno for item in target.decorator_list)

    lines = source.splitlines(keepends=True)
    lines[start_line - 1 : target.end_lineno] = [replacement.rstrip() + "\n"]
    path.write_text("".join(lines), encoding="utf-8")


def install_manual_activator():
    source = SOURCE_ROOT / "adaptive" / "manual_activate_decoy.py"
    destination = PROJECT_ROOT / "adaptive" / "manual_activate_decoy.py"
    shutil.copy2(source, destination)

    installer_destination = (
        PROJECT_ROOT / "scripts" / "install_catalog_decoy_dashboard.py"
    )
    shutil.copy2(Path(__file__).resolve(), installer_destination)


def update_dashboard():
    path = PROJECT_ROOT / "dashboard" / "app.py"

    api_decoys = r'''
@app.get("/api/decoys")
def api_decoys():
    """Return registered decoys plus deployable catalog implementations."""
    connection = get_connection()
    try:
        rows = connection.execute(
            """
            SELECT decoy_id, name, type, container_name, status, activated_at
            FROM decoys
            ORDER BY decoy_id
            """
        ).fetchall()
    finally:
        connection.close()

    registered = {row["name"]: dict(row) for row in rows}
    catalog_path = PROJECT_ROOT / "adaptive" / "decoy_catalog.json"
    try:
        catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        catalog = {"decoys": {}}

    results = []
    catalog_decoys = catalog.get("decoys", {})
    for decoy_key, metadata in catalog_decoys.items():
        if metadata.get("implementation_status") != "deployed":
            continue
        item = registered.pop(decoy_key, None)
        if item is None:
            item = {
                "decoy_id": None,
                "name": decoy_key,
                "type": "adaptive_catalog",
                "container_name": metadata.get("container_name"),
                "status": "inactive",
                "activated_at": None,
            }
        item["display_name"] = metadata.get("name", decoy_key)
        item["description"] = metadata.get("description", "")
        item["port"] = metadata.get("port")
        item["catalog_managed"] = True
        results.append(item)

    for item in registered.values():
        item["display_name"] = item["name"].replace("_", " ").title()
        item["catalog_managed"] = False
        results.append(item)

    return jsonify(results)
'''

    activate_decoy = r'''
@app.post("/api/decoys/<decoy_key>/activate")
def activate_decoy(decoy_key):
    """Activate an allow-listed decoy through a guarded workflow."""
    rejected = require_confirmed_action()
    if rejected:
        return rejected
    payload = request.get_json(silent=True) or {}
    if payload.get("confirm") != decoy_key:
        return jsonify({"error": "decoy_confirmation_mismatch"}), 400

    catalog_path = PROJECT_ROOT / "adaptive" / "decoy_catalog.json"
    try:
        catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
        catalog_entry = catalog.get("decoys", {}).get(decoy_key)
    except (OSError, json.JSONDecodeError):
        catalog_entry = None
    if catalog_entry is None or catalog_entry.get("implementation_status") != "deployed":
        return jsonify({"error": "decoy_not_deployed"}), 404

    connection = get_connection()
    try:
        decoy = connection.execute(
            "SELECT name, status FROM decoys WHERE name = ?",
            (decoy_key,),
        ).fetchone()
        decision = connection.execute(
            """
            SELECT decision_id FROM deception_decisions
            WHERE decoy_key = ?
              AND recommended_action = 'ACTIVATE_DECOY'
              AND execution_status = 'recommended'
            ORDER BY decision_id DESC LIMIT 1
            """,
            (decoy_key,),
        ).fetchone()
    finally:
        connection.close()

    if decoy is not None and decoy["status"] == "active":
        return jsonify({"error": "decoy_already_active"}), 409

    if decision is not None:
        script = PROJECT_ROOT / "adaptive" / "orchestrator.py"
        command = [
            sys.executable, str(script), "--decision-id",
            str(decision["decision_id"]), "--approve",
        ]
    else:
        script = PROJECT_ROOT / "adaptive" / "manual_activate_decoy.py"
        command = [
            sys.executable, str(script), "--decoy-key", decoy_key,
            "--reason", "Manual dashboard activation", "--approve",
        ]

    if not script.exists():
        return jsonify({"error": "activation_service_unavailable"}), 503
    try:
        result = subprocess.run(
            command, cwd=PROJECT_ROOT, capture_output=True, text=True,
            timeout=120, check=False,
        )
    except subprocess.TimeoutExpired:
        return jsonify({"error": "activation_timed_out"}), 504
    if result.returncode != 0:
        app.logger.error("Decoy activation failed: %s", result.stderr)
        return jsonify(
            {"error": "activation_failed", "message": result.stderr[-500:]}
        ), 500
    try:
        output = json.loads(result.stdout)
    except json.JSONDecodeError:
        output = {"result": "activated", "message": result.stdout.strip()}
    return jsonify(output)
'''

    replace_function(path, "api_decoys", api_decoys)
    replace_function(path, "activate_decoy", activate_decoy)


def main():
    if not PROJECT_ROOT.is_dir():
        raise SystemExit(f"Project not found: {PROJECT_ROOT}")
    install_manual_activator()
    update_dashboard()
    print("Catalog-aware decoy dashboard installed.")


if __name__ == "__main__":
    main()
