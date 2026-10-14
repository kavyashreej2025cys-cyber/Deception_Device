"""Adaptive CCTV and camera-management deception service.

All devices, credentials, streams and firmware metadata are synthetic.
The service never proxies traffic to a real camera or executes input.
"""

import json
import os
from datetime import datetime, timezone

from flask import Flask, jsonify, request


app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024

DECOY_KEY = os.environ.get("DECOY_KEY", "camera_management")
DYNAMIC_STATE_DIR = os.environ.get("DYNAMIC_STATE_DIR", "/app/dynamic_content")
LOG_FILE = os.path.join(
    os.path.dirname(__file__),
    "logs",
    "camera_events.json",
)

CAMERAS = [
    {
        "id": "CAM-LOBBY-01",
        "name": "Main Lobby",
        "address": "10.42.8.21",
        "model": "NV-CAM-4K-PRO",
        "firmware": "4.8.12",
        "status": "online",
        "recording": True,
    },
    {
        "id": "CAM-WAREHOUSE-02",
        "name": "Warehouse Loading Bay",
        "address": "10.42.8.22",
        "model": "NV-CAM-PTZ-2",
        "firmware": "3.9.7",
        "status": "online",
        "recording": True,
    },
    {
        "id": "CAM-FINANCE-03",
        "name": "Finance Corridor",
        "address": "10.42.8.29",
        "model": "NV-CAM-DOME-5",
        "firmware": "4.6.2",
        "status": "maintenance",
        "recording": False,
    },
]


def utc_iso_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def safe_text(value, maximum_length=500):
    if value is None:
        return ""
    return str(value).replace("\x00", "")[:maximum_length]


def adaptive_context():
    path = os.path.join(DYNAMIC_STATE_DIR, f"{DECOY_KEY}.json")
    try:
        with open(path, "r", encoding="utf-8") as state_file:
            state = json.load(state_file)
        return state.get("sources", {}).get(request.remote_addr or "", {})
    except (OSError, ValueError, TypeError):
        return {}


def visible_cameras():
    cameras = list(CAMERAS)
    context = adaptive_context()
    if any("CAM-" in asset for asset in context.get("visible_assets", [])):
        cameras.append({
            "id": "CAM-ARCHIVE-04",
            "name": "Archive Entrance",
            "address": "10.42.8.34",
            "model": "NV-CAM-DOME-5",
            "firmware": "4.7.1",
            "status": "degraded",
            "recording": True,
            "classification": "synthetic_decoy",
        })
    return cameras


def log_event(event_type, details=None):
    event = {
        "timestamp": utc_iso_now(),
        "source_ip": request.remote_addr,
        "method": request.method,
        "path": safe_text(request.path, 256),
        "user_agent": safe_text(request.headers.get("User-Agent", ""), 256),
        "event_type": event_type,
        "details": {"decoy_key": DECOY_KEY},
    }
    if details:
        event["details"].update(details)
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, "a", encoding="utf-8") as log_file:
        log_file.write(json.dumps(event) + "\n")
        log_file.flush()


@app.get("/health")
def health():
    return jsonify({"status": "healthy", "service": DECOY_KEY})


@app.get("/")
def home():
    log_event("connection")
    return jsonify({
        "service": "NovaTech Vision Management Gateway",
        "product": "VisionControl Enterprise",
        "version": "6.4.1",
        "status": "authentication_required",
        "api": "/api/v1",
    })


@app.get("/api/v1/devices")
def list_devices():
    cameras = visible_cameras()
    log_event("device_discovery", {"device_count": len(cameras)})
    return jsonify({
        "devices": cameras,
        "count": len(cameras),
        "adaptive_context": adaptive_context(),
    })


@app.get("/api/v1/devices/<camera_id>")
def camera_detail(camera_id):
    camera_id = safe_text(camera_id, 80).upper()
    log_event("camera_access", {"camera_id": camera_id, "action": "metadata"})
    for camera in visible_cameras():
        if camera["id"] == camera_id:
            return jsonify(camera)
    return jsonify({"error": "device_not_found", "device_id": camera_id}), 404


@app.get("/api/v1/streams/<camera_id>")
def stream(camera_id):
    camera_id = safe_text(camera_id, 80).upper()
    log_event("camera_access", {"camera_id": camera_id, "action": "stream_request"})
    return jsonify({
        "camera_id": camera_id,
        "stream": f"rtsp://10.42.8.10/live/{camera_id.lower()}",
        "token_required": True,
        "error": "authorization_required",
    }), 401


@app.post("/api/v1/login")
def login():
    payload = request.get_json(silent=True) or {}
    username = safe_text(payload.get("username"), 128)
    password = safe_text(payload.get("password"), 128)
    log_event("login_attempt", {
        "username": username,
        "password": password,
        "interface": "camera_management",
    })
    return jsonify({"error": "invalid_credentials", "remaining_attempts": 2}), 401


@app.route("/api/v1/config", methods=["GET", "POST"])
def configuration():
    payload = request.get_json(silent=True) or {}
    log_event("configuration_access", {
        "requested_section": safe_text(request.args.get("section", "system"), 80),
        "submitted_keys": sorted(safe_text(key, 80) for key in payload)[:30],
    })
    return jsonify({
        "network": {"segment": "camera-vlan-42", "gateway": "10.42.8.1"},
        "storage": {"retention_days": 30, "archive_target": "nvr-primary"},
        "access": "read_only",
    })


@app.get("/api/v1/firmware")
def firmware():
    log_event("firmware_probe", {
        "requested_model": safe_text(request.args.get("model", "all"), 80),
    })
    return jsonify({
        "channel": "enterprise-stable",
        "latest": "6.4.3",
        "download": "/firmware/visioncontrol-6.4.3.bin",
        "signature_required": True,
    })


@app.get("/adaptive-context")
def current_adaptive_context():
    log_event("adaptive_context_access")
    return jsonify(adaptive_context())


@app.route("/onvif/device_service", methods=["GET", "POST"])
def onvif():
    body = safe_text(request.get_data(as_text=True), 1200)
    log_event("onvif_probe", {"payload": body})
    return (
        "<?xml version='1.0'?><Fault><Code>ter:NotAuthorized</Code></Fault>",
        401,
        {"Content-Type": "application/soap+xml"},
    )


@app.errorhandler(413)
def request_too_large(_error):
    log_event("request_rejected", {"reason": "payload_too_large"})
    return jsonify({"error": "request payload too large"}), 413


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=18080, debug=False)
