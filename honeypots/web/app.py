from flask import Flask, request, render_template, redirect
import json
import os
from datetime import datetime

app = Flask(__name__)
LOG_FILE = os.path.join(os.path.dirname(__file__), "logs", "web_events.json")

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
    log_event("page_view")
    return render_template("login.html")

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    log_event("login_attempt", {"username": username, "password": password})
    return render_template("login.html", error="Invalid credentials")

@app.route("/portal")
def portal():
    log_event("page_view")
    return render_template("portal.html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
