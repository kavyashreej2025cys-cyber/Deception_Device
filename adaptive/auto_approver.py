"""
Guarded lab-only automatic approval for adaptive decoy activation.

Automatic activation is disabled unless DECEPTION_AUTO_APPROVE=true.
Only high-confidence, critical-risk attack decisions originating from the
isolated lab subnet are eligible.
"""

import ipaddress
import json
import os
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from adaptive.orchestrator import (
    DECOY_IMPLEMENTATIONS,
    build_plan,
    get_connection,
    record_activation,
    record_failure,
    run_compose_activation,
    utc_iso_now,
    validate_decision,
    wait_for_healthy,
)


AUTO_APPROVE_ENVIRONMENT_VARIABLE = "DECEPTION_AUTO_APPROVE"
MINIMUM_AUTO_CONFIDENCE = 0.80
MINIMUM_AUTO_RISK_SCORE = int(
    os.getenv("DECEPTION_ACTIVATE_RISK_SCORE", "60")
)
ALLOWED_SOURCE_NETWORK = ipaddress.ip_network(
    "192.168.56.0/24"
)


def auto_approval_enabled():
    """Return whether guarded lab auto-approval is explicitly enabled."""
    value = os.environ.get(
        AUTO_APPROVE_ENVIRONMENT_VARIABLE,
        "false",
    )

    return value.strip().lower() == "true"


def fetch_eligible_decisions():
    """Return pending high-confidence attack activation decisions."""
    connection = get_connection()

    try:
        rows = connection.execute(
            """
            SELECT *
            FROM deception_decisions
            WHERE recommended_action = 'ACTIVATE_DECOY'
              AND execution_status = 'recommended'
              AND attack_class != 'NORMAL'
              AND confidence >= ?
              AND risk_score >= ?
            ORDER BY decision_id
            """,
            (
                MINIMUM_AUTO_CONFIDENCE,
                MINIMUM_AUTO_RISK_SCORE,
            ),
        ).fetchall()
    finally:
        connection.close()

    return [
        dict(row)
        for row in rows
	if row["decoy_key"] in DECOY_IMPLEMENTATIONS
    ]


def source_is_allowed(source_ip):
    """Restrict automatic actions to the isolated laboratory subnet."""
    try:
        address = ipaddress.ip_address(source_ip)
    except ValueError:
        return False

    return address in ALLOWED_SOURCE_NETWORK


def record_already_active(
    decision,
    implementation,
    recorded_at,
):
    """Mark a recommendation satisfied by an already healthy decoy."""
    connection = get_connection()

    try:
        decoy = connection.execute(
            """
            SELECT decoy_id
            FROM decoys
            WHERE name = ?
            ORDER BY decoy_id
            LIMIT 1
            """,
            (decision["decoy_key"],),
        ).fetchone()

        if decoy is None:
            cursor = connection.execute(
                """
                INSERT INTO decoys (
                    name,
                    type,
                    container_name,
                    status,
                    activated_at
                )
                VALUES (?, ?, ?, 'active', ?)
                """,
                (
                    decision["decoy_key"],
                    implementation["type"],
                    implementation["container_name"],
                    recorded_at,
                ),
            )
            decoy_id = cursor.lastrowid
        else:
            decoy_id = decoy["decoy_id"]

            connection.execute(
                """
                UPDATE decoys
                SET type = ?,
                    container_name = ?,
                    status = 'active'
                WHERE decoy_id = ?
                """,
                (
                    implementation["type"],
                    implementation["container_name"],
                    decoy_id,
                ),
            )

        connection.execute(
            """
            UPDATE deception_decisions
            SET execution_mode = 'auto',
                execution_status = 'activated'
            WHERE decision_id = ?
            """,
            (decision["decision_id"],),
        )

        connection.execute(
            """
            INSERT INTO decoy_lifecycle_events (
                decoy_id,
                decision_id,
                decoy_key,
                action,
                execution_mode,
                status,
                details,
                created_at
            )
            VALUES (
                ?,
                ?,
                ?,
                'ACTIVATE',
                'auto',
                'already_active',
                ?,
                ?
            )
            """,
            (
                decoy_id,
                decision["decision_id"],
                decision["decoy_key"],
                json.dumps(
                    {
                        "attack_class": decision["attack_class"],
                        "confidence": decision["confidence"],
                        "container_name": implementation[
                            "container_name"
                        ],
                        "reason": (
                            "Eligible attack decision was automatically "
                            "satisfied because the approved decoy was "
                            "already running and healthy."
                        ),
                        "risk_score": decision["risk_score"],
                        "source_ip": decision["source_ip"],
                    },
                    sort_keys=True,
                ),
                recorded_at,
            ),
        )

        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def execute_automatic_approval(decision):
    """Validate and execute one eligible automatic approval."""
    implementation = validate_decision(decision)
    plan = build_plan(decision, implementation)
    current_state = plan["current_container_state"]
    recorded_at = utc_iso_now()

    if (
        current_state["running"]
        and current_state["health"] == "healthy"
    ):
        record_already_active(
            decision=decision,
            implementation=implementation,
            recorded_at=recorded_at,
        )

        return {
            "decision_id": decision["decision_id"],
            "source_ip": decision["source_ip"],
            "attack_class": decision["attack_class"],
            "confidence": decision["confidence"],
            "risk_score": decision["risk_score"],
            "decoy_key": decision["decoy_key"],
            "execution_mode": "auto",
            "result": "already_active",
            "docker_action_executed": False,
        }

    compose_result = run_compose_activation(
        implementation["compose_file"]
    )

    final_state = wait_for_healthy(
        implementation["container_name"]
    )

    activated_at = utc_iso_now()

    record_activation(
        decision=decision,
        implementation=implementation,
        activated_at=activated_at,
        execution_mode="auto",
    )

    return {
        "decision_id": decision["decision_id"],
        "source_ip": decision["source_ip"],
        "attack_class": decision["attack_class"],
        "confidence": decision["confidence"],
        "risk_score": decision["risk_score"],
        "decoy_key": decision["decoy_key"],
        "execution_mode": "auto",
        "result": "activated",
        "activated_at": activated_at,
        "final_container_state": final_state,
        "compose": compose_result,
        "docker_action_executed": True,
    }


def run_auto_approval_cycle():
    """Automatically execute only strictly eligible attack decisions."""
    if not auto_approval_enabled():
        return []

    results = []

    for decision in fetch_eligible_decisions():
        if not source_is_allowed(decision.get("source_ip")):
            continue

        try:
            result = execute_automatic_approval(decision)
        except Exception as error:
            record_failure(
                decision["decision_id"],
                execution_mode="auto",
            )

            result = {
                "decision_id": decision["decision_id"],
                "source_ip": decision.get("source_ip"),
                "attack_class": decision.get("attack_class"),
                "decoy_key": decision.get("decoy_key"),
                "execution_mode": "auto",
                "result": "activation_failed",
                "error": str(error),
                "docker_action_executed": False,
            }

        results.append(result)

    return results


def main():
    """Run one guarded auto-approval cycle."""
    if not auto_approval_enabled():
        print(
            "Automatic approval is disabled. Set "
            "DECEPTION_AUTO_APPROVE=true only in the isolated lab."
        )
        return

    results = run_auto_approval_cycle()

    if not results:
        print("No eligible attack decisions require automatic approval.")
        return

    for result in results:
        print(
            json.dumps(
                result,
                indent=2,
                sort_keys=True,
            )
        )


if __name__ == "__main__":
    main()
