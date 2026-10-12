#!/usr/bin/env python3
"""Install the coordinated layered-enterprise adaptive decoy."""

import ast
import json
import shutil
from pathlib import Path


SOURCE_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = Path.home() / "cyber-deception"
DECOY_KEY = "layered_enterprise"


def copy_files():
    source = SOURCE_ROOT / "adaptive" / "decoys" / DECOY_KEY
    destination = PROJECT_ROOT / "adaptive" / "decoys" / DECOY_KEY
    destination.mkdir(parents=True, exist_ok=True)
    for path in source.rglob("*"):
        relative = path.relative_to(source)
        target = destination / relative
        if path.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)

    (destination / "logs" / "web" / "discovery_events.json").touch(exist_ok=True)
    (destination / "logs" / "database" / "finance_events.json").touch(exist_ok=True)
    (destination / "logs" / "ssh" / "cowrie.json").touch(exist_ok=True)
    shutil.copy2(
        Path(__file__).resolve(),
        PROJECT_ROOT / "scripts" / "install_layered_enterprise_decoy.py",
    )


def make_app_key_configurable(relative_path, default_key):
    path = PROJECT_ROOT / relative_path
    source = path.read_text(encoding="utf-8")
    old = f'DECOY_KEY = "{default_key}"'
    new = f'DECOY_KEY = os.environ.get("DECOY_KEY", "{default_key}")'
    if new in source:
        return
    if old not in source:
        raise RuntimeError(f"Could not find DECOY_KEY in {path}")
    path.write_text(source.replace(old, new, 1), encoding="utf-8")


def insert_mapping_entry(path, variable_name, entry, marker):
    source = path.read_text(encoding="utf-8")
    if marker in source:
        return
    tree = ast.parse(source)
    assignment = next(
        (
            node for node in tree.body
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == variable_name
                for target in node.targets
            )
        ),
        None,
    )
    if assignment is None or not isinstance(assignment.value, (ast.Dict, ast.List)):
        raise RuntimeError(f"Could not locate {variable_name} in {path}")
    lines = source.splitlines(keepends=True)
    lines.insert(assignment.value.end_lineno - 1, entry)
    path.write_text("".join(lines), encoding="utf-8")


def update_orchestrator():
    entry = '''    "layered_enterprise": {
        "type": "adaptive_multi_service",
        "container_name": "adaptive-layered-enterprise-web",
        "compose_file": (
            PROJECT_ROOT
            / "adaptive"
            / "decoys"
            / "layered_enterprise"
            / "docker-compose.yml"
        ),
    },
'''
    insert_mapping_entry(
        PROJECT_ROOT / "adaptive" / "orchestrator.py",
        "DECOY_IMPLEMENTATIONS",
        entry,
        '"layered_enterprise":',
    )


def update_logger():
    path = PROJECT_ROOT / "logger" / "event_logger.py"
    source = path.read_text(encoding="utf-8")
    marker = "source_decoy_key = source.get(\"decoy_key\")"
    if marker in source:
        return
    old = '''            if fmt == "cowrie":
                norm = normalize_cowrie(raw)
            else:
                norm = normalize_custom(raw)

            conn.execute(
'''
    new = '''            if fmt == "cowrie":
                norm = normalize_cowrie(raw)
            else:
                norm = normalize_custom(raw)

            source_decoy_key = source.get("decoy_key")
            if source_decoy_key:
                details = json.loads(norm["details"] or "{}")
                if not isinstance(details, dict):
                    details = {"raw": details}
                details["decoy_key"] = source_decoy_key
                norm["details"] = json.dumps(details)

            conn.execute(
'''
    if old not in source:
        raise RuntimeError("Could not locate logger normalization block")
    path.write_text(source.replace(old, new, 1), encoding="utf-8")


def update_settings():
    entries = '''    {
        "service": "web",
        "cursor_key": "layered_enterprise_web",
        "decoy_key": "layered_enterprise",
        "log_path": os.path.join(
            BASE_DIR, "adaptive", "decoys", "layered_enterprise",
            "logs", "web", "discovery_events.json",
        ),
        "format": "custom",
    },
    {
        "service": "database",
        "cursor_key": "layered_enterprise_database",
        "decoy_key": "layered_enterprise",
        "log_path": os.path.join(
            BASE_DIR, "adaptive", "decoys", "layered_enterprise",
            "logs", "database", "finance_events.json",
        ),
        "format": "custom",
    },
    {
        "service": "ssh",
        "cursor_key": "layered_enterprise_ssh",
        "decoy_key": "layered_enterprise",
        "log_path": os.path.join(
            BASE_DIR, "adaptive", "decoys", "layered_enterprise",
            "logs", "ssh", "cowrie.json",
        ),
        "format": "cowrie",
    },
'''
    insert_mapping_entry(
        PROJECT_ROOT / "config" / "settings.py",
        "HONEYPOT_SOURCES",
        entries,
        '"cursor_key": "layered_enterprise_web"',
    )


def update_catalog():
    path = PROJECT_ROOT / "adaptive" / "decoy_catalog.json"
    catalog = json.loads(path.read_text(encoding="utf-8"))
    catalog["decoys"][DECOY_KEY].update(
        {
            "implementation_status": "deployed",
            "deployment_status": "deployed",
            "container_name": "adaptive-layered-enterprise-web",
            "port": 16000,
            "ports": {"web": 16000, "ssh": 2226, "database": 16432},
        }
    )
    catalog["version"] = "1.5.0"
    path.write_text(json.dumps(catalog, indent=2) + "\n", encoding="utf-8")


def main():
    if not PROJECT_ROOT.is_dir():
        raise SystemExit(f"Project not found: {PROJECT_ROOT}")
    copy_files()
    make_app_key_configurable(
        Path("adaptive/decoys/finance_database/app.py"), "finance_database"
    )
    make_app_key_configurable(
        Path("adaptive/decoys/service_discovery/app.py"), "service_discovery"
    )
    update_orchestrator()
    update_logger()
    update_settings()
    update_catalog()
    print("Layered enterprise decoy source installed.")
    print("Next: set log permissions, validate, build, and test the stack.")


if __name__ == "__main__":
    main()
