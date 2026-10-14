"""Security operations dashboard for the Cyber Deception System."""

import json
import os
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, Response, jsonify, render_template, request


PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from logger.database import get_connection


app = Flask(__name__)

DEFAULT_LIMIT = 50
MAXIMUM_LIMIT = 200
ALERT_STATUSES = {"open", "acknowledged", "resolved"}


def utc_iso_now():
    """Return a database-compatible UTC timestamp."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def require_confirmed_action():
    """Reject browser state changes that are not deliberate same-site JSON calls."""
    if request.headers.get("X-Dashboard-Action") != "confirmed":
        return jsonify({"error": "confirmation_required"}), 403
    if not request.is_json:
        return jsonify({"error": "json_required"}), 415
    fetch_site = request.headers.get("Sec-Fetch-Site", "same-origin")
    if fetch_site not in {"same-origin", "same-site", "none"}:
        return jsonify({"error": "cross_site_action_blocked"}), 403
    return None


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
            "read_only": False,
            "guarded_actions": True,
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


def attacker_evidence(source_ip, event_limit=200):
    """Build a complete analyst-oriented view of one observed source."""
    connection = get_connection()
    try:
        attacker = connection.execute(
            "SELECT * FROM attackers WHERE source_ip = ?",
            (source_ip,),
        ).fetchone()
        if attacker is None:
            return None
        events = connection.execute(
            """
            SELECT event_id, timestamp, source_ip, destination_ip,
                   service, event_type, protocol, details, risk_score
            FROM events WHERE source_ip = ?
            ORDER BY event_id DESC LIMIT ?
            """,
            (source_ip, event_limit),
        ).fetchall()
        predictions = connection.execute(
            """SELECT * FROM predictions WHERE source_ip = ?
               ORDER BY prediction_id DESC LIMIT 30""",
            (source_ip,),
        ).fetchall()
        decisions = connection.execute(
            """SELECT * FROM deception_decisions WHERE source_ip = ?
               ORDER BY decision_id DESC LIMIT 30""",
            (source_ip,),
        ).fetchall()
        alerts = connection.execute(
            """SELECT * FROM alerts WHERE source_ip = ?
               ORDER BY alert_id DESC LIMIT 50""",
            (source_ip,),
        ).fetchall()
    finally:
        connection.close()

    parsed_events = []
    services = {}
    event_types = {}
    decoy_events = []
    for row in events:
        item = dict(row)
        item["details"] = parse_json_value(item.get("details"))
        parsed_events.append(item)
        services[item["service"]] = services.get(item["service"], 0) + 1
        event_types[item["event_type"]] = event_types.get(item["event_type"], 0) + 1
        if isinstance(item["details"], dict) and item["details"].get("decoy_key"):
            decoy_events.append(item)

    return {
        "attacker": dict(attacker),
        "summary": {
            "event_count": len(parsed_events),
            "services": services,
            "event_types": event_types,
            "decoy_interactions": len(decoy_events),
        },
        "events": parsed_events,
        "decoy_events": decoy_events,
        "predictions": rows_as_dicts(predictions),
        "decisions": rows_as_dicts(decisions),
        "alerts": rows_as_dicts(alerts),
        "generated_at": utc_iso_now(),
    }


@app.get("/api/attackers/<int:attacker_id>")
def api_attacker_detail(attacker_id):
    """Return detailed behavior and evidence for one attacker."""
    connection = get_connection()
    try:
        row = connection.execute(
            "SELECT source_ip FROM attackers WHERE attacker_id = ?",
            (attacker_id,),
        ).fetchone()
    finally:
        connection.close()
    if row is None:
        return jsonify({"error": "attacker_not_found"}), 404
    return jsonify(attacker_evidence(row["source_ip"]))


@app.get("/reports/attacker/<int:attacker_id>")
def attacker_report(attacker_id):
    """Render a printable SOC investigation report."""
    connection = get_connection()
    try:
        row = connection.execute(
            "SELECT source_ip FROM attackers WHERE attacker_id = ?",
            (attacker_id,),
        ).fetchone()
    finally:
        connection.close()
    if row is None:
        return "Attacker profile not found", 404
    return render_template("attacker_report.html", report=attacker_evidence(row["source_ip"]))


@app.get("/api/attackers/<int:attacker_id>/report.json")
def download_attacker_report(attacker_id):
    """Download a portable JSON evidence report."""
    connection = get_connection()
    try:
        row = connection.execute(
            "SELECT source_ip FROM attackers WHERE attacker_id = ?",
            (attacker_id,),
        ).fetchone()
    finally:
        connection.close()
    if row is None:
        return jsonify({"error": "attacker_not_found"}), 404
    payload = json.dumps(attacker_evidence(row["source_ip"]), indent=2)
    filename = f"attacker-{row['source_ip']}-report.json"
    return Response(payload, mimetype="application/json", headers={
        "Content-Disposition": f'attachment; filename="{filename}"'
    })


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


@app.post("/api/alerts/<int:alert_id>/status")
def update_alert_status(alert_id):
    """Acknowledge, reopen, or resolve an alert with audit timestamps."""
    rejected = require_confirmed_action()
    if rejected:
        return rejected
    status = str((request.get_json(silent=True) or {}).get("status", "")).lower()
    if status not in ALERT_STATUSES:
        return jsonify({"error": "invalid_status", "allowed": sorted(ALERT_STATUSES)}), 400
    now = utc_iso_now()
    acknowledged_at = now if status == "acknowledged" else None
    resolved_at = now if status == "resolved" else None
    connection = get_connection()
    try:
        cursor = connection.execute(
            """
            UPDATE alerts SET status = ?, updated_at = ?,
                acknowledged_at = CASE WHEN ? = 'acknowledged' THEN ? ELSE acknowledged_at END,
                resolved_at = CASE WHEN ? = 'resolved' THEN ? ELSE NULL END
            WHERE alert_id = ?
            """,
            (status, now, status, acknowledged_at, status, resolved_at, alert_id),
        )
        if cursor.rowcount == 0:
            connection.rollback()
            return jsonify({"error": "alert_not_found"}), 404
        connection.commit()
    finally:
        connection.close()
    return jsonify({"alert_id": alert_id, "status": status, "updated_at": now})



@app.get("/api/decoys")
def api_decoys():
    """Return registered decoys plus deployable catalog implementations."""
    connection = get_connection()
    try:
        rows = connection.execute(
            """
            SELECT decoy_id, name, type, container_name, status, activated_at
            FROM decoys
            ORDER BY decoy_id
            """
        ).fetchall()
    finally:
        connection.close()

    registered = {row["name"]: dict(row) for row in rows}
    catalog_path = PROJECT_ROOT / "adaptive" / "decoy_catalog.json"
    try:
        catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        catalog = {"decoys": {}}

    results = []
    catalog_decoys = catalog.get("decoys", {})
    for decoy_key, metadata in catalog_decoys.items():
        if metadata.get("implementation_status") != "deployed":
            continue
        item = registered.pop(decoy_key, None)
        if item is None:
            item = {
                "decoy_id": None,
                "name": decoy_key,
                "type": "adaptive_catalog",
                "container_name": metadata.get("container_name"),
                "status": "inactive",
                "activated_at": None,
            }
        item["display_name"] = metadata.get("name", decoy_key)
        item["description"] = metadata.get("description", "")
        item["port"] = metadata.get("port")
        item["catalog_managed"] = True
        results.append(item)

    for item in registered.values():
        item["display_name"] = item["name"].replace("_", " ").title()
        item["catalog_managed"] = False
        results.append(item)

    return jsonify(results)


@app.get("/api/decoys/<decoy_key>/events")
def api_decoy_events(decoy_key):
    """Return detailed attacker interactions recorded by a decoy."""
    connection = get_connection()
    try:
        rows = connection.execute(
            """
            SELECT event_id, timestamp, source_ip, destination_ip,
                   service, event_type, protocol, details, risk_score
            FROM events
            WHERE details LIKE ?
            ORDER BY event_id DESC LIMIT ?
            """,
            (f'%"decoy_key": "{decoy_key}"%', bounded_limit()),
        ).fetchall()
    finally:
        connection.close()
    results = []
    for row in rows:
        item = dict(row)
        item["details"] = parse_json_value(item.get("details"))
        results.append(item)
    return jsonify(results)


@app.get("/api/decoys/<decoy_key>/adaptive-content")
def api_decoy_adaptive_content(decoy_key):
    """Return the safe per-source content narrative built from interactions."""
    connection = get_connection()
    try:
        rows = connection.execute(
            """
            SELECT decoy_key, source_ip, interaction_count, behavior_stage,
                   last_event_type, last_command, interests_json,
                   content_json, first_seen, updated_at
            FROM decoy_content_states
            WHERE decoy_key = ?
            ORDER BY updated_at DESC
            LIMIT ?
            """,
            (decoy_key, bounded_limit()),
        ).fetchall()
    finally:
        connection.close()

    results = []
    for row in rows:
        item = dict(row)
        item["interests"] = parse_json_value(item.pop("interests_json"))
        item["content"] = parse_json_value(item.pop("content_json"))
        results.append(item)
    return jsonify(results)


@app.post("/api/decoys/<decoy_key>/deactivate")
def deactivate_decoy(decoy_key):
    """Run the existing guarded deactivation workflow after confirmation."""
    rejected = require_confirmed_action()
    if rejected:
        return rejected
    payload = request.get_json(silent=True) or {}
    if payload.get("confirm") != decoy_key:
        return jsonify({"error": "decoy_confirmation_mismatch"}), 400
    reason = str(payload.get("reason", "Manual dashboard deactivation")).strip()[:300]
    connection = get_connection()
    try:
        decoy = connection.execute(
            "SELECT name, status FROM decoys WHERE name = ?",
            (decoy_key,),
        ).fetchone()
    finally:
        connection.close()
    if decoy is None:
        return jsonify({"error": "decoy_not_found"}), 404
    if decoy["status"] != "active":
        return jsonify({"error": "decoy_not_active", "status": decoy["status"]}), 409
    script = PROJECT_ROOT / "adaptive" / "deactivate_decoy.py"
    if not script.exists():
        return jsonify({"error": "deactivation_service_unavailable"}), 503
    try:
        result = subprocess.run(
            [sys.executable, str(script), "--decoy-key", decoy_key,
             "--reason", reason, "--approve"],
            cwd=PROJECT_ROOT, capture_output=True, text=True,
            timeout=90, check=False,
        )
    except subprocess.TimeoutExpired:
        return jsonify({"error": "deactivation_timed_out"}), 504
    if result.returncode != 0:
        app.logger.error("Decoy deactivation failed: %s", result.stderr)
        return jsonify({"error": "deactivation_failed", "message": result.stderr[-500:]}), 500
    try:
        output = json.loads(result.stdout)
    except json.JSONDecodeError:
        output = {"result": "deactivated", "message": result.stdout.strip()}
    return jsonify(output)



@app.post("/api/decoys/<decoy_key>/activate")
def activate_decoy(decoy_key):
    """Activate an allow-listed decoy through a guarded workflow."""
    rejected = require_confirmed_action()
    if rejected:
        return rejected
    payload = request.get_json(silent=True) or {}
    if payload.get("confirm") != decoy_key:
        return jsonify({"error": "decoy_confirmation_mismatch"}), 400

    catalog_path = PROJECT_ROOT / "adaptive" / "decoy_catalog.json"
    try:
        catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
        catalog_entry = catalog.get("decoys", {}).get(decoy_key)
    except (OSError, json.JSONDecodeError):
        catalog_entry = None
    if catalog_entry is None or catalog_entry.get("implementation_status") != "deployed":
        return jsonify({"error": "decoy_not_deployed"}), 404

    connection = get_connection()
    try:
        decoy = connection.execute(
            "SELECT name, status FROM decoys WHERE name = ?",
            (decoy_key,),
        ).fetchone()
        decision = connection.execute(
            """
            SELECT decision_id FROM deception_decisions
            WHERE decoy_key = ?
              AND recommended_action = 'ACTIVATE_DECOY'
              AND execution_status = 'recommended'
            ORDER BY decision_id DESC LIMIT 1
            """,
            (decoy_key,),
        ).fetchone()
    finally:
        connection.close()

    if decoy is not None and decoy["status"] == "active":
        return jsonify({"error": "decoy_already_active"}), 409

    if decision is not None:
        script = PROJECT_ROOT / "adaptive" / "orchestrator.py"
        command = [
            sys.executable, str(script), "--decision-id",
            str(decision["decision_id"]), "--approve",
        ]
    else:
        script = PROJECT_ROOT / "adaptive" / "manual_activate_decoy.py"
        command = [
            sys.executable, str(script), "--decoy-key", decoy_key,
            "--reason", "Manual dashboard activation", "--approve",
        ]

    if not script.exists():
        return jsonify({"error": "activation_service_unavailable"}), 503
    try:
        result = subprocess.run(
            command, cwd=PROJECT_ROOT, capture_output=True, text=True,
            timeout=120, check=False,
        )
    except subprocess.TimeoutExpired:
        return jsonify({"error": "activation_timed_out"}), 504
    if result.returncode != 0:
        app.logger.error("Decoy activation failed: %s", result.stderr)
        return jsonify(
            {"error": "activation_failed", "message": result.stderr[-500:]}
        ), 500
    try:
        output = json.loads(result.stdout)
    except json.JSONDecodeError:
        output = {"result": "activated", "message": result.stdout.strip()}
    return jsonify(output)


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
