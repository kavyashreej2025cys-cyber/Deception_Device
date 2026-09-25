"""
Guarded Docker orchestrator for adaptive deception decoys.

Without --approve, this module performs a dry run.
With --approve, it executes only a validated decision already stored
by the observe-only decision engine.
"""

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from logger.database import get_connection


DECOY_IMPLEMENTATIONS = {
    "finance_database": {
        "type": "adaptive_database",
        "container_name": "adaptive-finance-database",
        "compose_file": (
            PROJECT_ROOT
            / "adaptive"
            / "decoys"
            / "finance_database"
            / "docker-compose.yml"
        ),
    },
}

HEALTH_TIMEOUT_SECONDS = 30
HEALTH_POLL_SECONDS = 2


def utc_iso_now():
    """Return the current UTC time."""
    return (
        datetime.now(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def fetch_decision(decision_id):
    """Load one stored adaptive decision."""
    connection = get_connection()

    try:
        row = connection.execute(
            """
            SELECT *
            FROM deception_decisions
            WHERE decision_id = ?
            """,
            (decision_id,),
        ).fetchone()
    finally:
        connection.close()

    if row is None:
        raise ValueError(
            f"Decision {decision_id} does not exist."
        )

    return dict(row)


def validate_decision(decision):
    """Ensure the decision is eligible for activation."""
    if decision["recommended_action"] != "ACTIVATE_DECOY":
        raise ValueError(
            "Decision does not recommend ACTIVATE_DECOY."
        )

    decoy_key = decision.get("decoy_key")

    if not decoy_key:
        raise ValueError(
            "Decision does not specify a decoy key."
        )

    if decoy_key not in DECOY_IMPLEMENTATIONS:
        raise ValueError(
            f"No deployed implementation exists for "
            f"{decoy_key!r}."
        )

    allowed_statuses = {
        "recommended",
        "activation_failed",
        "activated",
    }

    if decision["execution_status"] not in allowed_statuses:
        raise ValueError(
            "Decision has unsupported execution status: "
            f"{decision['execution_status']!r}."
        )

    implementation = DECOY_IMPLEMENTATIONS[decoy_key]
    compose_file = implementation["compose_file"]

    if not compose_file.exists():
        raise FileNotFoundError(
            f"Compose file not found: {compose_file}"
        )

    return implementation


def inspect_container(container_name):
    """Return a normalized container state."""
    completed = subprocess.run(
        [
            "docker",
            "inspect",
            container_name,
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    if completed.returncode != 0:
        return {
            "exists": False,
            "running": False,
            "health": None,
        }

    try:
        inspection = json.loads(completed.stdout)[0]
    except (json.JSONDecodeError, IndexError) as error:
        raise RuntimeError(
            "Docker returned invalid inspection data."
        ) from error

    state = inspection.get("State", {})
    health_data = state.get("Health") or {}

    return {
        "exists": True,
        "running": bool(state.get("Running")),
        "health": health_data.get("Status"),
    }


def run_compose_activation(compose_file):
    """Start the selected decoy without rebuilding it."""
    completed = subprocess.run(
        [
            "docker",
            "compose",
            "-f",
            str(compose_file),
            "up",
            "-d",
            "--no-build",
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    if completed.returncode != 0:
        message = (
            completed.stderr.strip()
            or completed.stdout.strip()
            or "Unknown Docker Compose failure."
        )

        raise RuntimeError(message)

    return {
        "stdout": completed.stdout.strip(),
        "stderr": completed.stderr.strip(),
    }


def wait_for_healthy(container_name):
    """Wait until the container is running and healthy."""
    deadline = time.monotonic() + HEALTH_TIMEOUT_SECONDS
    latest_state = None

    while time.monotonic() < deadline:
        latest_state = inspect_container(container_name)

        if (
            latest_state["running"]
            and latest_state["health"] == "healthy"
        ):
            return latest_state

        time.sleep(HEALTH_POLL_SECONDS)

    raise RuntimeError(
        f"Container {container_name} did not become healthy "
        f"within {HEALTH_TIMEOUT_SECONDS} seconds. "
        f"Last state: {latest_state}"
    )


def record_activation(
    decision,
    implementation,
    activated_at,
):
    """Register the active decoy and update decision status."""
    decoy_key = decision["decoy_key"]
    container_name = implementation["container_name"]

    connection = get_connection()

    try:
        existing = connection.execute(
            """
            SELECT decoy_id
            FROM decoys
            WHERE name = ?
            ORDER BY decoy_id
            LIMIT 1
            """,
            (decoy_key,),
        ).fetchone()

        if existing is None:
            connection.execute(
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
                    decoy_key,
                    implementation["type"],
                    container_name,
                    activated_at,
                ),
            )
        else:
            connection.execute(
                """
                UPDATE decoys
                SET type = ?,
                    container_name = ?,
                    status = 'active',
                    activated_at = ?
                WHERE decoy_id = ?
                """,
                (
                    implementation["type"],
                    container_name,
                    activated_at,
                    existing["decoy_id"],
                ),
            )

        connection.execute(
            """
            UPDATE deception_decisions
            SET execution_mode = 'manual',
                execution_status = 'activated'
            WHERE decision_id = ?
            """,
            (decision["decision_id"],),
        )

        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def record_failure(decision_id):
    """Record a failed explicitly approved activation."""
    connection = get_connection()

    try:
        connection.execute(
            """
            UPDATE deception_decisions
            SET execution_mode = 'manual',
                execution_status = 'activation_failed'
            WHERE decision_id = ?
            """,
            (decision_id,),
        )
        connection.commit()
    finally:
        connection.close()


def build_plan(decision, implementation):
    """Create a human-readable activation plan."""
    state = inspect_container(
        implementation["container_name"]
    )

    return {
        "decision_id": decision["decision_id"],
        "source_ip": decision["source_ip"],
        "attack_class": decision["attack_class"],
        "confidence": decision["confidence"],
        "risk_score": decision["risk_score"],
        "recommended_action": decision[
            "recommended_action"
        ],
        "decoy_key": decision["decoy_key"],
        "container_name": implementation[
            "container_name"
        ],
        "compose_file": str(
            implementation["compose_file"]
        ),
        "current_container_state": state,
    }


def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description=(
            "Validate and optionally execute a stored adaptive "
            "deception decision."
        )
    )

    parser.add_argument(
        "--decision-id",
        type=int,
        required=True,
    )

    parser.add_argument(
        "--approve",
        action="store_true",
        help=(
            "Explicitly approve Docker activation. Without this "
            "flag, only a dry-run plan is printed."
        ),
    )

    return parser.parse_args()


def main():
    """Validate, preview, and optionally activate one decoy."""
    args = parse_arguments()

    try:
        decision = fetch_decision(args.decision_id)
        implementation = validate_decision(decision)
        plan = build_plan(decision, implementation)

        if not args.approve:
            print(
                json.dumps(
                    {
                        "mode": "dry-run",
                        "message": (
                            "No Docker or database state was changed. "
                            "Add --approve to execute this plan."
                        ),
                        "plan": plan,
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return
        current_state = plan["current_container_state"]

        if (
            decision["execution_status"] == "activated"
            and current_state["running"]
            and current_state["health"] == "healthy"
        ):
            print(
                json.dumps(
                    {
                        "mode": "manual-approved",
                        "result": "already_active",
                        "message": (
                            "The decision is already activated and "
                            "the container is healthy. No state was "
                            "changed."
                        ),
                        "plan": plan,
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return

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
        )

        print(
            json.dumps(
                {
                    "mode": "manual-approved",
                    "result": "activated",
                    "activated_at": activated_at,
                    "plan": plan,
                    "final_container_state": final_state,
                    "compose": compose_result,
                },
                indent=2,
                sort_keys=True,
            )
        )

    except (
        FileNotFoundError,
        ValueError,
        RuntimeError,
        KeyError,
        TypeError,
    ) as error:
        if args.approve:
            try:
                record_failure(args.decision_id)
            except Exception:
                pass

        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
