from flask import Flask, request, jsonify
import json
import os
from datetime import datetime

app = Flask(__name__)
LOG_FILE = os.path.join(os.path.dirname(__file__), "logs", "iot_events.json")

FAKE_CAMERAS = [
    {"id": "CAM-01", "location": "Main Entrance", "status": "online"},
    {"id": "CAM-02", "location": "Parking Lot", "status": "online"},
    {"id": "CAM-03", "location": "Server Room", "status": "offline"},
    {"id": "CAM-04", "location": "Reception", "status": "online"},
]

def log_event(event_type, extra=None):
    event = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "source_ip": request.remote_addr,
        "method": request.method,
        "path": request.path,
        "user_agent": request.headers.get("User-Agent", ""),
        "event_type": event_type,
    }
    if extra:
        event["details"] = extra
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(event) + "\n")

@app.route("/")
def home():
    log_event("connection")
    return jsonify({
        "device": "NovaTech CCTV Controller",
        "model": "NT-IPCAM-2000",
        "firmware": "v1.4.2",
        "status": "online"
    })

@app.route("/cameras")
def list_cameras():
    log_event("list_cameras")
    return jsonify({"cameras": FAKE_CAMERAS})

@app.route("/cameras/<cam_id>/view")
def view_camera(cam_id):
    log_event("view_camera_attempt", {"camera_id": cam_id})
    return jsonify({"error": "Stream unavailable. Authentication required."}), 401

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")
    log_event("login_attempt", {"username": username, "password": password})
    return jsonify({"error": "invalid credentials"}), 401

@app.route("/config")
def config():
    log_event("config_access_attempt")
    return jsonify({"error": "forbidden"}), 403

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
