import json
import os
from datetime import datetime, timezone

from flask import Flask, Response, jsonify, render_template, request


app = Flask(__name__)
LOG_FILE = os.path.join(os.path.dirname(__file__), "logs", "discovery_events.json")
DECOY_KEY = os.environ.get("DECOY_KEY", "service_discovery")


def utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def client_ip():
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",", 1)[0].strip()
    return request.remote_addr or ""


def log_event(event_type, details=None):
    event = {
        "timestamp": utc_now(),
        "source_ip": client_ip(),
        "method": request.method,
        "path": request.path,
        "query_string": request.query_string.decode("utf-8", errors="replace"),
        "user_agent": request.headers.get("User-Agent", ""),
        "event_type": event_type,
        "details": {
            "decoy_key": DECOY_KEY,
            **(details or {}),
        },
    }

    with open(LOG_FILE, "a", encoding="utf-8") as log_file:
        log_file.write(json.dumps(event, sort_keys=True) + "\n")


@app.get("/health")
def health():
    return jsonify({"status": "healthy", "service": DECOY_KEY})


@app.get("/")
def home():
    log_event("service_discovery", {"surface": "landing_page"})
    return render_template("index.html")


@app.route("/admin", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
def admin():
    details = {"surface": "administration_portal"}
    if request.method == "POST":
        details.update(
            {
                "username": request.form.get("username", ""),
                "password": request.form.get("password", ""),
            }
        )
    log_event("admin_probe", details)
    return render_template("index.html", login_error="Authentication failed")


@app.get("/api")
@app.get("/api/v1")
@app.get("/api/v1/status")
def api_surface():
    log_event("api_probe", {"surface": "internal_api"})
    return jsonify(
        {
            "service": "NovaTech Service Registry",
            "environment": "production",
            "version": "2.8.4",
            "services": [
                {"name": "identity-api", "status": "online"},
                {"name": "finance-api", "status": "online"},
                {"name": "camera-gateway", "status": "degraded"},
            ],
        }
    )


@app.get("/server-status")
@app.get("/actuator")
@app.get("/actuator/health")
def status_surface():
    log_event("status_probe", {"surface": "service_status"})
    return jsonify(
        {
            "status": "UP",
            "node": "edge-gateway-02",
            "region": "sme-primary",
            "management": "/admin",
        }
    )


@app.get("/.env")
@app.get("/config")
@app.get("/config.json")
def configuration_surface():
    log_event("sensitive_file_probe", {"surface": "configuration"})
    body = (
        "APP_ENV=production\n"
        "SERVICE_REGISTRY=http://registry.internal\n"
        "BACKUP_PATH=/srv/backups\n"
        "API_TOKEN=redacted-decoy-token\n"
    )
    return Response(body, mimetype="text/plain")


@app.get("/backup")
@app.get("/backups")
@app.get("/backup.zip")
def backup_surface():
    log_event("backup_probe", {"surface": "backup_archive"})
    return jsonify(
        {
            "archive": "novatech-services-2026-10-11.zip",
            "size": "184 MB",
            "status": "access denied",
        }
    ), 403


@app.get("/robots.txt")
def robots():
    log_event("service_discovery", {"surface": "robots"})
    return Response(
        "User-agent: *\nDisallow: /admin\nDisallow: /backup\nDisallow: /config\n",
        mimetype="text/plain",
    )


@app.errorhandler(404)
def not_found(_error):
    log_event("path_probe", {"requested_path": request.path})
    return jsonify({"error": "resource not found", "path": request.path}), 404


if __name__ == "__main__":
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    app.run(host="0.0.0.0", port=15000)
