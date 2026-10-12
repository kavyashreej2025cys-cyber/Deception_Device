"""
Persistent alert generation for the cyber-deception system.

Alerts are created from adaptive decisions, not directly from raw
events. A deterministic fingerprint prevents duplicate alerts.
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from logger.database import get_connection


def utc_iso_now():
    """Return the current UTC timestamp."""
    return (
        datetime.now(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def fetch_alertable_decisions():
    """Return pending or failed decisions requiring attention."""
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
                execution_status,
                created_at
            FROM deception_decisions
            WHERE execution_status IN (
                  'recommended',
                  'activation_failed'
              )
            ORDER BY decision_id
            """
        ).fetchall()
    finally:
        connection.close()

    return [
        dict(row)
        for row in rows
    ]


def alert_specification(decision):
    """Convert an adaptive decision into an alert definition."""
    action = decision["recommended_action"]
    risk_score = int(decision["risk_score"] or 0)
    confidence = float(decision["confidence"] or 0)
    source_ip = decision["source_ip"]
    attack_class = decision["attack_class"]
    decoy_key = decision.get("decoy_key")
    execution_status = decision.get("execution_status")

    if execution_status == "activation_failed":
        return {
            "alert_type": "DECOY_ACTIVATION_FAILED",
            "severity": "CRITICAL",
            "title": "Adaptive decoy activation failed",
            "message": (
                f"Activation of {decoy_key} failed for source "
                f"{source_ip}. The detected class was {attack_class} "
                f"with {confidence:.1%} confidence and risk score "
                f"{risk_score}. Review the container and lifecycle logs."
            ),
        }

    if action == "ACTIVATE_DECOY":
        return {
            "alert_type": "DECOY_ACTIVATION_RECOMMENDED",
            "severity": "CRITICAL",
            "title": "Adaptive decoy activation recommended",
            "message": (
                f"Source {source_ip} was classified as "
                f"{attack_class} with {confidence:.1%} confidence "
                f"and risk score {risk_score}. Review activation "
                f"of {decoy_key}."
            ),
        }

    if action == "PREPARE_DECOY":
        return {
            "alert_type": "DECOY_PREPARATION_RECOMMENDED",
            "severity": "HIGH",
            "title": "Prepare an adaptive decoy",
            "message": (
                f"Source {source_ip} shows {attack_class} behavior "
                f"with {confidence:.1%} confidence and risk score "
                f"{risk_score}. Prepare {decoy_key} for possible "
                "activation."
            ),
        }

    if action == "COLLECT_MORE_DATA":
        severity = (
            "HIGH"
            if risk_score >= 81
            else "MEDIUM"
        )

        return {
            "alert_type": "LOW_CONFIDENCE_HIGH_RISK",
            "severity": severity,
            "title": "More evidence required",
            "message": (
                f"Source {source_ip} has risk score {risk_score}, "
                f"but the {attack_class} classification confidence "
                f"is only {confidence:.1%}. Continue monitoring "
                "before taking automated action."
            ),
        }

    if action == "INCREASE_MONITORING":
        return {
            "alert_type": "INCREASE_MONITORING",
            "severity": "MEDIUM",
            "title": "Increased monitoring recommended",
            "message": (
                f"Source {source_ip} shows {attack_class} behavior. "
                f"Risk score is {risk_score} and confidence is "
                f"{confidence:.1%}."
            ),
        }

    return None


def build_fingerprint(
    decision,
    specification,
):
    """Create a stable per-decision and outcome alert identifier."""
    suffix = decision["recommended_action"]

    if specification["alert_type"] == "DECOY_ACTIVATION_FAILED":
        suffix = "ACTIVATION_FAILED"

    return (
        f"decision:"
        f"{decision['decision_id']}:"
        f"{suffix}"
    )


def insert_alert(decision, specification):
    """Insert an alert once and return whether it was new."""
    timestamp = utc_iso_now()
    fingerprint = build_fingerprint(
        decision,
        specification,
    )

    connection = get_connection()

    try:
        cursor = connection.execute(
            """
            INSERT OR IGNORE INTO alerts (
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
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?)
            """,
            (
                fingerprint,
                decision["source_ip"],
                specification["alert_type"],
                specification["severity"],
                specification["title"],
                specification["message"],
                decision["prediction_id"],
                decision["decision_id"],
                timestamp,
                timestamp,
            ),
        )

        connection.commit()
        inserted = cursor.rowcount == 1
    finally:
        connection.close()

    return {
        "inserted": inserted,
        "fingerprint": fingerprint,
        "decision_id": decision["decision_id"],
        "source_ip": decision["source_ip"],
        "severity": specification["severity"],
        "alert_type": specification["alert_type"],
        "title": specification["title"],
    }


def run_alert_cycle():
    """Generate alerts for every eligible pending decision."""
    decisions = fetch_alertable_decisions()
    results = []

    for decision in decisions:
        specification = alert_specification(decision)

        if specification is None:
            continue

        result = insert_alert(
            decision=decision,
            specification=specification,
        )

        if result["inserted"]:
            results.append(result)

    return results


def main():
    """Run one alert-generation cycle."""
    try:
        results = run_alert_cycle()
    except Exception as error:
        print(
            json.dumps(
                {
                    "error_type": type(error).__name__,
                    "error": str(error),
                }
            ),
            file=sys.stderr,
        )
        raise SystemExit(1)

    if not results:
        print("No new alerts were created.")
        return

    for result in results:
        print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
