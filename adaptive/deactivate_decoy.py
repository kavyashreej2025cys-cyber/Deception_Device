"""
Guarded manual deactivation for adaptive decoys.

Without --approve, only a dry-run plan is printed.
Approved deactivation stops the container but preserves:
- the container definition;
- collected logs;
- activation history;
- lifecycle audit records.
"""

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from adaptive.orchestrator import (
    DECOY_IMPLEMENTATIONS,
    inspect_container,
)
from logger.database import get_connection


def utc_iso_now():
    """Return the current UTC time."""
    return (
        datetime.now(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def fetch_decoy(decoy_key):
    """Fetch one registered adaptive decoy."""
    connection = get_connection()

    try:
        row = connection.execute(
            """
            SELECT *
            FROM decoys
            WHERE name = ?
            ORDER BY decoy_id
            LIMIT 1
            """,
            (decoy_key,),
        ).fetchone()
    finally:
        connection.close()

    if row is None:
        raise ValueError(
            f"Decoy {decoy_key!r} is not registered."
        )

    return dict(row)


def fetch_latest_decision_id(decoy_key):
    """Find the latest decision associated with the decoy."""
    connection = get_connection()

    try:
        row = connection.execute(
            """
            SELECT decision_id
            FROM deception_decisions
            WHERE decoy_key = ?
            ORDER BY decision_id DESC
            LIMIT 1
            """,
            (decoy_key,),
        ).fetchone()
    finally:
        connection.close()

    if row is None:
        return None

    return int(row["decision_id"])


def run_compose_stop(compose_file):
    """Stop the decoy without deleting it or its logs."""
    completed = subprocess.run(
        [
            "docker",
            "compose",
            "-f",
            str(compose_file),
            "stop",
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
            or "Unknown Docker Compose stop failure."
        )
        raise RuntimeError(message)

    return {
        "stdout": completed.stdout.strip(),
        "stderr": completed.stderr.strip(),
    }


def record_lifecycle_event(
    decoy,
    decision_id,
    action,
    status,
    details,
):
    """Write an immutable lifecycle audit record."""
    connection = get_connection()

    try:
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
            VALUES (?, ?, ?, ?, 'manual', ?, ?, ?)
            """,
            (
                decoy["decoy_id"],
                decision_id,
                decoy["name"],
                action,
                status,
                json.dumps(details, sort_keys=True),
                utc_iso_now(),
            ),
        )
        connection.commit()
    finally:
        connection.close()


def mark_inactive(decoy_id):
    """Update the current decoy state without erasing history."""
    connection = get_connection()

    try:
        connection.execute(
            """
            UPDATE decoys
            SET status = 'inactive'
            WHERE decoy_id = ?
            """,
            (decoy_id,),
        )
        connection.commit()
    finally:
        connection.close()


def build_plan(decoy, implementation):
    """Build the dry-run deactivation plan."""
    container_state = inspect_container(
        implementation["container_name"]
    )

    return {
        "decoy_id": decoy["decoy_id"],
        "decoy_key": decoy["name"],
        "database_status": decoy["status"],
        "container_name": implementation[
            "container_name"
        ],
        "compose_file": str(
            implementation["compose_file"]
        ),
        "current_container_state": container_state,
        "preserves_logs": True,
        "removes_container": False,
    }


def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description=(
            "Preview or approve adaptive-decoy deactivation."
        )
    )

    parser.add_argument(
        "--decoy-key",
        required=True,
        choices=sorted(DECOY_IMPLEMENTATIONS),
    )

    parser.add_argument(
        "--reason",
        default="manual operator request",
        help="Human-readable reason stored in the audit record.",
    )

    parser.add_argument(
        "--approve",
        action="store_true",
        help=(
            "Explicitly approve container shutdown. Without "
            "this flag, no state is changed."
        ),
    )

    return parser.parse_args()


def main():
    """Preview or execute one guarded deactivation."""
    args = parse_arguments()

    try:
        decoy = fetch_decoy(args.decoy_key)
        implementation = DECOY_IMPLEMENTATIONS[
            args.decoy_key
        ]
        plan = build_plan(decoy, implementation)
        state = plan["current_container_state"]

        if not args.approve:
            print(
                json.dumps(
                    {
                        "mode": "dry-run",
                        "message": (
                            "No Docker or database state was changed. "
                            "Add --approve to stop this decoy."
                        ),
                        "reason": args.reason,
                        "plan": plan,
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return

        if (
            decoy["status"] == "inactive"
            and not state["running"]
        ):
            print(
                json.dumps(
                    {
                        "mode": "manual-approved",
                        "result": "already_inactive",
                        "message": (
                            "The decoy is already inactive. "
                            "No state was changed."
                        ),
                        "plan": plan,
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return

        compose_result = run_compose_stop(
            implementation["compose_file"]
        )

        final_state = inspect_container(
            implementation["container_name"]
        )

        if final_state["running"]:
            raise RuntimeError(
                "Docker reported success, but the container "
                "is still running."
            )

        mark_inactive(decoy["decoy_id"])

        decision_id = fetch_latest_decision_id(
            args.decoy_key
        )

        record_lifecycle_event(
            decoy=decoy,
            decision_id=decision_id,
            action="DEACTIVATE",
            status="completed",
            details={
                "reason": args.reason,
                "container_state_before": state,
                "container_state_after": final_state,
                "logs_preserved": True,
            },
        )

        print(
            json.dumps(
                {
                    "mode": "manual-approved",
                    "result": "deactivated",
                    "reason": args.reason,
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
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
