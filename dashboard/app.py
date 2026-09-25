"""
Read-only dashboard API for the Cyber Deception System.

The dashboard exposes operational data but cannot approve decisions,
start containers, stop containers, or modify security state.
"""

import json
import os
import sqlite3
import sys
from pathlib import Path

from flask import Flask, jsonify, render_template, request


PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from logger.database import get_connection


app = Flask(__name__)

DEFAULT_LIMIT = 50
MAXIMUM_LIMIT = 200


def bounded_limit():
    """Return a safe API row limit."""
    raw_limit = request.args.get(
        "limit",
        DEFAULT_LIMIT,
    )

    try:
        value = int(raw_limit)
    except (TypeError, ValueError):
        value = DEFAULT_LIMIT

    return max(1, min(value, MAXIMUM_LIMIT))


def rows_as_dicts(rows):
    """Convert SQLite rows into ordinary dictionaries."""
    return [
        dict(row)
        for row in rows
    ]


def parse_json_value(value):
    """Parse stored JSON while preserving malformed text."""
    if value in (None, ""):
        return {}

    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return {
            "raw": str(value),
        }


@app.after_request
def add_security_headers(response):
    """Add browser security and no-cache headers."""
    response.headers["Cache-Control"] = (
        "no-store, max-age=0"
    )
    response.headers["X-Content-Type-Options"] = (
        "nosniff"
    )
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = (
        "no-referrer"
    )
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "base-uri 'none'; "
        "frame-ancestors 'none'"
    )
    return response


@app.errorhandler(sqlite3.Error)
def handle_database_error(error):
    """Return a controlled response for database errors."""
    app.logger.exception("Dashboard database error")

    return (
        jsonify(
            {
                "error": "database_error",
                "message": "Dashboard data is temporarily unavailable.",
            }
        ),
        500,
    )


@app.get("/")
def index():
    """Render the dashboard shell."""
    return render_template("index.html")


@app.get("/health")
def health():
    """Return application and database health."""
    connection = get_connection()

    try:
        connection.execute("SELECT 1").fetchone()
    finally:
        connection.close()

    return jsonify(
        {
            "status": "healthy",
            "service": "cyber-deception-dashboard",
            "read_only": True,
        }
    )


@app.get("/api/summary")
def api_summary():
    """Return top-level operational counters."""
    connection = get_connection()

    try:
        total_events = connection.execute(
            "SELECT COUNT(*) FROM events"
        ).fetchone()[0]

        attacker_count = connection.execute(
            "SELECT COUNT(*) FROM attackers"
        ).fetchone()[0]

        active_decoys = connection.execute(
            """
            SELECT COUNT(*)
            FROM decoys
            WHERE status = 'active'
            """
        ).fetchone()[0]

        pending_approvals = connection.execute(
            """
            SELECT COUNT(*)
            FROM deception_decisions
            WHERE recommended_action = 'ACTIVATE_DECOY'
              AND execution_status = 'recommended'
            """
        ).fetchone()[0]
        open_alerts = connection.execute(
            """
            SELECT COUNT(*)
            FROM alerts
            WHERE status = 'open'
            """
        ).fetchone()[0]
        prediction_count = connection.execute(
            """
            SELECT COUNT(*)
            FROM predictions
            WHERE source_ip IS NOT NULL
            """
        ).fetchone()[0]

        latest_event = connection.execute(
            """
            SELECT MAX(timestamp)
            FROM events
            """
        ).fetchone()[0]
    finally:
        connection.close()

    return jsonify(
        {
            "total_events": total_events,
            "attackers": attacker_count,
            "active_decoys": active_decoys,
            "pending_approvals": pending_approvals,
	    "open_alerts": open_alerts,
            "predictions": prediction_count,
            "latest_event": latest_event,
        }
    )


@app.get("/api/attackers")
def api_attackers():
    """Return risk-ranked attacker profiles."""
    connection = get_connection()

    try:
        rows = connection.execute(
            """
            SELECT
                attacker_id,
                source_ip,
                first_seen,
                last_seen,
                risk_score,
                primary_attack_type,
                status
            FROM attackers
            ORDER BY risk_score DESC, last_seen DESC
            LIMIT ?
            """,
            (bounded_limit(),),
        ).fetchall()
    finally:
        connection.close()

    return jsonify(rows_as_dicts(rows))


@app.get("/api/events")
def api_events():
    """Return recent normalized events."""
    connection = get_connection()

    try:
        rows = connection.execute(
            """
            SELECT
                event_id,
                timestamp,
                source_ip,
                destination_ip,
                service,
                event_type,
                protocol,
                details,
                risk_score
            FROM events
            ORDER BY event_id DESC
            LIMIT ?
            """,
            (bounded_limit(),),
        ).fetchall()
    finally:
        connection.close()

    results = []

    for row in rows:
        event = dict(row)
        event["details"] = parse_json_value(
            event.get("details")
        )
        results.append(event)

    return jsonify(results)


@app.get("/api/predictions")
def api_predictions():
    """Return recent contextual AI predictions."""
    connection = get_connection()

    try:
        rows = connection.execute(
            """
            SELECT
                prediction_id,
                source_ip,
                predicted_class,
                confidence,
                model_version,
                window_start,
                window_end,
                first_event_id,
                last_event_id,
                event_count,
                features_json,
                created_at
            FROM predictions
            WHERE source_ip IS NOT NULL
            ORDER BY prediction_id DESC
            LIMIT ?
            """,
            (bounded_limit(),),
        ).fetchall()
    finally:
        connection.close()

    results = []

    for row in rows:
        prediction = dict(row)
        prediction["features"] = parse_json_value(
            prediction.pop("features_json", None)
        )
        results.append(prediction)

    return jsonify(results)


@app.get("/api/decisions")
def api_decisions():
    """Return recent adaptive policy decisions."""
    connection = get_connection()

    try:
        rows = connection.execute(
            """
            SELECT
                decision_id,
                prediction_id,
                source_ip,
                attack_class,
                confidence,
                risk_score,
                risk_bucket,
                recommended_action,
                decoy_key,
                reason,
                policy_version,
                execution_mode,
                execution_status,
                created_at
            FROM deception_decisions
            ORDER BY decision_id DESC
            LIMIT ?
            """,
            (bounded_limit(),),
        ).fetchall()
    finally:
        connection.close()

    return jsonify(rows_as_dicts(rows))

@app.get("/api/alerts")
def api_alerts():
    """Return recent security alerts ordered by severity."""
    connection = get_connection()

    try:
        rows = connection.execute(
            """
            SELECT
                alert_id,
                fingerprint,
                source_ip,
                alert_type,
                severity,
                title,
                message,
                related_prediction_id,
                related_decision_id,
                status,
                created_at,
                updated_at,
                acknowledged_at,
                resolved_at
            FROM alerts
            ORDER BY
                CASE severity
                    WHEN 'CRITICAL' THEN 1
                    WHEN 'HIGH' THEN 2
                    WHEN 'MEDIUM' THEN 3
                    WHEN 'LOW' THEN 4
                    ELSE 5
                END,
                alert_id DESC
            LIMIT ?
            """,
            (bounded_limit(),),
        ).fetchall()
    finally:
        connection.close()

    return jsonify(rows_as_dicts(rows))


@app.get("/api/decoys")
def api_decoys():
    """Return registered adaptive decoys."""
    connection = get_connection()

    try:
        rows = connection.execute(
            """
            SELECT
                decoy_id,
                name,
                type,
                container_name,
                status,
                activated_at
            FROM decoys
            ORDER BY decoy_id
            """
        ).fetchall()
    finally:
        connection.close()

    return jsonify(rows_as_dicts(rows))


@app.get("/api/lifecycle")
def api_lifecycle():
    """Return immutable decoy lifecycle records."""
    connection = get_connection()

    try:
        rows = connection.execute(
            """
            SELECT
                lifecycle_event_id,
                decoy_id,
                decision_id,
                decoy_key,
                action,
                execution_mode,
                status,
                details,
                created_at
            FROM decoy_lifecycle_events
            ORDER BY lifecycle_event_id DESC
            LIMIT ?
            """,
            (bounded_limit(),),
        ).fetchall()
    finally:
        connection.close()

    results = []

    for row in rows:
        lifecycle = dict(row)
        lifecycle["details"] = parse_json_value(
            lifecycle.get("details")
        )
        results.append(lifecycle)

    return jsonify(results)


@app.get("/api/event-series")
def api_event_series():
    """Return per-minute event counts grouped by service."""
    connection = get_connection()

    try:
        rows = connection.execute(
            """
            SELECT
                substr(timestamp, 1, 16) AS minute,
                service,
                COUNT(*) AS event_count
            FROM events
            WHERE timestamp IS NOT NULL
              AND timestamp != ''
            GROUP BY
                substr(timestamp, 1, 16),
                service
            ORDER BY minute DESC
            LIMIT 240
            """
        ).fetchall()
    finally:
        connection.close()

    results = rows_as_dicts(rows)
    results.reverse()

    return jsonify(results)


if __name__ == "__main__":
    host = os.environ.get(
        "DASHBOARD_HOST",
        "0.0.0.0",
    )
    port = int(
        os.environ.get(
            "DASHBOARD_PORT",
            "7000",
        )
    )

    app.run(
        host=host,
        port=port,
        debug=False,
    )
