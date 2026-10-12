#!/usr/bin/env python3
"""Install the adaptive web service-discovery decoy."""

import ast
import json
import shutil
from pathlib import Path


SOURCE_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = Path.home() / "cyber-deception"
DECOY_KEY = "service_discovery"


def copy_decoy_files():
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

    (destination / "logs" / "discovery_events.json").touch(exist_ok=True)


def update_orchestrator():
    path = PROJECT_ROOT / "adaptive" / "orchestrator.py"
    source = path.read_text(encoding="utf-8")
    if f'"{DECOY_KEY}":' in source:
        return

    tree = ast.parse(source)
    assignment = None
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if any(
            isinstance(target, ast.Name)
            and target.id == "DECOY_IMPLEMENTATIONS"
            for target in node.targets
        ):
            assignment = node
            break

    if assignment is None or not isinstance(assignment.value, ast.Dict):
        raise RuntimeError("Could not locate DECOY_IMPLEMENTATIONS dictionary")

    lines = source.splitlines(keepends=True)
    entry = '''    "service_discovery": {
        "type": "adaptive_web",
        "container_name": "adaptive-service-discovery",
        "compose_file": (
            PROJECT_ROOT
            / "adaptive"
            / "decoys"
            / "service_discovery"
            / "docker-compose.yml"
        ),
    },
'''
    lines.insert(assignment.value.end_lineno - 1, entry)
    path.write_text("".join(lines), encoding="utf-8")


def update_settings():
    path = PROJECT_ROOT / "config" / "settings.py"
    source = path.read_text(encoding="utf-8")
    if '"cursor_key": "service_discovery"' in source:
        return

    tree = ast.parse(source)
    assignment = None
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if any(
            isinstance(target, ast.Name) and target.id == "HONEYPOT_SOURCES"
            for target in node.targets
        ):
            assignment = node
            break

    if assignment is None or not isinstance(assignment.value, ast.List):
        raise RuntimeError("Could not locate HONEYPOT_SOURCES list")

    lines = source.splitlines(keepends=True)
    entry = '''    {
        "service": "web",
        "cursor_key": "service_discovery",
        "log_path": os.path.join(
            BASE_DIR,
            "adaptive",
            "decoys",
            "service_discovery",
            "logs",
            "discovery_events.json",
        ),
        "format": "custom",
    },
'''
    lines.insert(assignment.value.end_lineno - 1, entry)
    path.write_text("".join(lines), encoding="utf-8")


def update_catalog():
    path = PROJECT_ROOT / "adaptive" / "decoy_catalog.json"
    catalog = json.loads(path.read_text(encoding="utf-8"))
    decoys = catalog["decoys"]

    decoys["service_discovery"].update(
        {
            "implementation_status": "deployed",
            "deployment_status": "deployed",
            "container_name": "adaptive-service-discovery",
            "port": 15000,
        }
    )

    if "ssh_admin_server" in decoys:
        decoys["ssh_admin_server"]["implementation_status"] = "deployed"

    catalog["version"] = "1.4.0"
    path.write_text(json.dumps(catalog, indent=2) + "\n", encoding="utf-8")


def main():
    if not PROJECT_ROOT.is_dir():
        raise SystemExit(f"Project not found: {PROJECT_ROOT}")

    copy_decoy_files()
    update_orchestrator()
    update_settings()
    update_catalog()

    print("Adaptive service-discovery decoy source installed.")
    print("Next: set log permissions, build, validate, and test it.")


if __name__ == "__main__":
    main()
