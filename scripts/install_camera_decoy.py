"""One-time idempotent integration helper for the camera decoy."""

import json
import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def backup(path):
    destination = path.with_suffix(path.suffix + ".before_camera_decoy")
    if not destination.exists():
        shutil.copy2(path, destination)


def update_orchestrator():
    path = ROOT / "adaptive" / "orchestrator.py"
    text = path.read_text(encoding="utf-8")
    if '"camera_management": {' in text:
        return
    marker = "}\n\nHEALTH_TIMEOUT_SECONDS"
    if marker not in text:
        raise RuntimeError("Could not locate DECOY_IMPLEMENTATIONS boundary.")
    entry = '''    "camera_management": {
        "type": "adaptive_iot",
        "container_name": "adaptive-camera-management",
        "compose_file": (
            PROJECT_ROOT
            / "adaptive"
            / "decoys"
            / "camera_management"
            / "docker-compose.yml"
        ),
    },
'''
    backup(path)
    text = text.replace(marker, entry + marker, 1)
    path.write_text(text, encoding="utf-8")


def update_settings():
    path = ROOT / "config" / "settings.py"
    text = path.read_text(encoding="utf-8")
    if '"cursor_key": "camera_management"' in text:
        return
    end = text.rfind("\n]")
    if end < 0:
        raise RuntimeError("Could not locate HONEYPOT_SOURCES boundary.")
    entry = '''
    {
        "service": "iot",
        "cursor_key": "camera_management",
        "log_path": os.path.join(
            BASE_DIR,
            "adaptive",
            "decoys",
            "camera_management",
            "logs",
            "camera_events.json",
        ),
        "format": "custom",
    },'''
    backup(path)
    text = text[:end] + entry + text[end:]
    path.write_text(text, encoding="utf-8")


def update_catalog():
    path = ROOT / "adaptive" / "decoy_catalog.json"
    backup(path)
    catalog = json.loads(path.read_text(encoding="utf-8"))
    catalog["catalog_version"] = "1.1.0"
    catalog["decoys"]["finance_database"]["implementation_status"] = "deployed"
    camera = catalog["decoys"]["camera_management"]
    camera["implementation_status"] = "deployed"
    camera["port"] = 18080
    camera["container_name"] = "adaptive-camera-management"
    path.write_text(json.dumps(catalog, indent=2) + "\n", encoding="utf-8")


def main():
    update_orchestrator()
    update_settings()
    update_catalog()
    log_path = (
        ROOT / "adaptive" / "decoys" / "camera_management"
        / "logs" / "camera_events.json"
    )
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.touch(exist_ok=True)
    print("Camera-management decoy integration complete.")


if __name__ == "__main__":
    main()
