from flask import Flask, request, jsonify
import json
import os
from datetime import datetime

app = Flask(__name__)
LOG_FILE = os.path.join(os.path.dirname(__file__), "logs", "db_events.json")

FAKE_TABLES = {
    "employees": [
        {"id": 1, "name": "A. Sharma", "dept": "Finance", "salary": 82000},
        {"id": 2, "name": "R. Iyer", "dept": "Engineering", "salary": 95000},
        {"id": 3, "name": "M. Khan", "dept": "HR", "salary": 70000},
    ],
    "invoices": [
        {"id": 101, "client": "Acme Corp", "amount": 15200, "status": "paid"},
        {"id": 102, "client": "Globex Inc", "amount": 8400, "status": "pending"},
    ],
    "departments": [
        {"id": 1, "name": "Finance"},
        {"id": 2, "name": "Engineering"},
        {"id": 3, "name": "HR"},
    ],
}

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
        "service": "NovaTech FinanceDB",
        "version": "PostgreSQL-like Admin Interface v3.2",
        "status": "connected"
    })

@app.route("/tables")
def list_tables():
    log_event("list_tables")
    return jsonify({"tables": list(FAKE_TABLES.keys())})

@app.route("/tables/<table_name>")
def get_table(table_name):
    log_event("table_access", {"table": table_name})
    if table_name in FAKE_TABLES:
        return jsonify({"table": table_name, "rows": FAKE_TABLES[table_name]})
    return jsonify({"error": "table not found"}), 404

@app.route("/query", methods=["POST"])
def query():
    data = request.get_json(silent=True) or {}
    query_str = data.get("query", "")
    log_event("query_attempt", {"query": query_str})
    return jsonify({"error": "syntax error or access denied", "query_received": query_str}), 400

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")
    log_event("login_attempt", {"username": username, "password": password})
    return jsonify({"error": "authentication failed"}), 401

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5432)
