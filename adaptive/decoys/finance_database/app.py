"""
Adaptive finance-database honeypot.

This service never connects to a real database and never executes
attacker-supplied queries. All returned records are synthetic.
"""

import json
import os
from datetime import datetime, timezone

from flask import Flask, jsonify, request


app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024

DECOY_KEY = os.environ.get("DECOY_KEY", "finance_database")

LOG_FILE = os.path.join(
    os.path.dirname(__file__),
    "logs",
    "finance_events.json",
)

FAKE_TABLES = {
    "accounts_payable": [
        {
            "invoice_id": "INV-2026-1042",
            "vendor": "Northstar Office Supply",
            "amount": 18450.75,
            "currency": "USD",
            "status": "pending_approval",
        },
        {
            "invoice_id": "INV-2026-1058",
            "vendor": "Blue Harbor Logistics",
            "amount": 6275.00,
            "currency": "USD",
            "status": "scheduled",
        },
    ],
    "payroll_summary": [
        {
            "department": "Finance",
            "employee_count": 14,
            "monthly_total": 118400.00,
        },
        {
            "department": "Engineering",
            "employee_count": 31,
            "monthly_total": 294750.00,
        },
    ],
    "vendor_payments": [
        {
            "payment_id": "PAY-88201",
            "vendor": "Northstar Office Supply",
            "amount": 18450.75,
            "payment_state": "review",
        },
        {
            "payment_id": "PAY-88217",
            "vendor": "Metro Data Services",
            "amount": 9200.00,
            "payment_state": "released",
        },
    ],
    "quarterly_forecast": [
        {
            "quarter": "2026-Q3",
            "projected_revenue": 2850000,
            "projected_expenses": 2190000,
        }
    ],
    "audit_log": [
        {
            "audit_id": 9001,
            "actor": "finance.service",
            "action": "EXPORT_REQUESTED",
            "result": "DENIED",
        },
        {
            "audit_id": 9002,
            "actor": "reporting.service",
            "action": "REPORT_GENERATED",
            "result": "SUCCESS",
        },
    ],
}


def utc_iso_now():
    """Return the current UTC timestamp."""
    return (
        datetime.now(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def safe_text(value, maximum_length=500):
    """Convert untrusted input into bounded log-safe text."""
    if value is None:
        return ""

    text = str(value)
    text = text.replace("\x00", "")
    return text[:maximum_length]


def log_event(event_type, details=None):
    """Write one structured JSON event."""
    event = {
        "timestamp": utc_iso_now(),
        "source_ip": request.remote_addr,
        "method": request.method,
        "path": safe_text(request.path, 256),
        "user_agent": safe_text(
            request.headers.get("User-Agent", ""),
            256,
        ),
        "event_type": event_type,
        "details": {
            "decoy_key": DECOY_KEY,
        },
    }

    if details:
        event["details"].update(details)

    with open(
        LOG_FILE,
        "a",
        encoding="utf-8",
    ) as log_file:
        log_file.write(json.dumps(event) + "\n")
        log_file.flush()


@app.get("/health")
def health():
    """Container health endpoint; deliberately not logged."""
    return jsonify(
        {
            "status": "healthy",
            "service": DECOY_KEY,
        }
    )


@app.get("/")
def home():
    log_event("connection")

    return jsonify(
        {
            "service": "NovaTech Financial Reporting Gateway",
            "engine": "PostgreSQL 14.8",
            "cluster": "corp-finance-prod",
            "status": "authentication_required",
            "api_version": "v2",
        }
    )


@app.get("/schemas")
def list_schemas():
    log_event("list_schemas")

    return jsonify(
        {
            "schemas": [
                "public",
                "finance",
                "reporting",
                "audit",
            ]
        }
    )


@app.get("/tables")
def list_tables():
    log_event("list_tables")

    return jsonify(
        {
            "schema": "finance",
            "tables": sorted(FAKE_TABLES),
        }
    )


@app.get("/tables/<table_name>")
def get_table(table_name):
    normalized_name = safe_text(
        table_name.lower(),
        100,
    )

    log_event(
        "table_access",
        {
            "table": normalized_name,
        },
    )

    if normalized_name not in FAKE_TABLES:
        return (
            jsonify(
                {
                    "error": "relation does not exist",
                    "relation": normalized_name,
                }
            ),
            404,
        )

    return jsonify(
        {
            "schema": "finance",
            "table": normalized_name,
            "row_count": len(
                FAKE_TABLES[normalized_name]
            ),
            "rows": FAKE_TABLES[normalized_name],
        }
    )


@app.post("/query")
def query():
    payload = request.get_json(silent=True)

    if not isinstance(payload, dict):
        payload = {}

    query_text = safe_text(
        payload.get("query", ""),
        1000,
    )

    log_event(
        "query_attempt",
        {
            "query": query_text,
        },
    )

    normalized_query = query_text.lower()

    for table_name, rows in FAKE_TABLES.items():
        if table_name in normalized_query:
            return jsonify(
                {
                    "columns": (
                        sorted(rows[0])
                        if rows
                        else []
                    ),
                    "rows": rows,
                    "row_count": len(rows),
                    "notice": "read-only reporting replica",
                }
            )

    return (
        jsonify(
            {
                "error": "permission denied for relation",
                "sqlstate": "42501",
            }
        ),
        403,
    )


@app.post("/login")
def login():
    payload = request.get_json(silent=True)

    if not isinstance(payload, dict):
        payload = {}

    username = safe_text(
        payload.get("username", ""),
        128,
    )
    password = safe_text(
        payload.get("password", ""),
        128,
    )

    log_event(
        "login_attempt",
        {
            "username": username,
            "password": password,
        },
    )

    return (
        jsonify(
            {
                "error": "authentication failed",
                "sqlstate": "28P01",
            }
        ),
        401,
    )


@app.errorhandler(413)
def request_too_large(_error):
    log_event(
        "request_rejected",
        {
            "reason": "payload_too_large",
        },
    )

    return (
        jsonify(
            {
                "error": "request payload too large",
            }
        ),
        413,
    )


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=15432,
        debug=False,
    )
