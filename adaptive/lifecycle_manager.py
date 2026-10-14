"""Automatic replacement, retirement and cleanup of adaptive decoys.

Safety properties:
- replacement is make-before-break: the new decoy must be healthy first;
- recent interaction is treated as an active session and blocks retirement;
- Docker volumes/log directories and database evidence are never deleted;
- lifecycle changes are fully audited and can be disabled with one flag.
"""

import json
import os
import subprocess
from datetime import datetime, timezone

from adaptive.orchestrator import DECOY_IMPLEMENTATIONS, inspect_container
from logger.database import get_connection


def utc_now():
    return datetime.now(timezone.utc)


def utc_iso_now():
    return utc_now().isoformat().replace("+00:00", "Z")


def parse_timestamp(value):
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def env_seconds(name, default, minimum=10):
    return max(minimum, int(os.environ.get(name, str(default))))


def enabled():
    return os.environ.get("DECEPTION_AUTO_LIFECYCLE", "false").lower() == "true"


def run_compose(compose_file, action):
    command = ["docker", "compose", "-f", str(compose_file)]
    if action == "stop":
        command.append("stop")
    elif action == "remove":
        command.extend(["down", "--remove-orphans"])
    else:
        raise ValueError(f"Unsupported lifecycle action: {action}")
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or completed.stdout.strip())
    return {
        "stdout": completed.stdout.strip(),
        "stderr": completed.stderr.strip(),
    }


def latest_event_time(connection, decoy_key):
    row = connection.execute(
        """
        SELECT MAX(timestamp) AS last_activity
        FROM events
        WHERE json_valid(details)
          AND json_extract(details, '$.decoy_key') = ?
        """,
        (decoy_key,),
    ).fetchone()
    return parse_timestamp(row["last_activity"] if row else None)


def latest_lifecycle_time(connection, decoy_key, action=None):
    parameters = [decoy_key]
    action_filter = ""
    if action:
        action_filter = "AND action = ?"
        parameters.append(action)
    row = connection.execute(
        f"""
        SELECT MAX(created_at) AS occurred_at
        FROM decoy_lifecycle_events
        WHERE decoy_key = ? {action_filter}
        """,
        parameters,
    ).fetchone()
    return parse_timestamp(row["occurred_at"] if row else None)


def replacement_targets(connection, activation_results):
    """Return only decoys superseded by a fresh activation this cycle."""
    targets = set()
    for result in activation_results or []:
        if (
            result.get("result") != "activated"
            or not result.get("docker_action_executed")
        ):
            continue
        row = connection.execute(
            """
            SELECT decoy_key
            FROM deception_decisions
            WHERE source_ip = ?
              AND execution_status = 'activated'
              AND decision_id < ?
              AND decoy_key IS NOT NULL
              AND decoy_key != ?
            ORDER BY decision_id DESC
            LIMIT 1
            """,
            (
                result.get("source_ip"),
                result.get("decision_id"),
                result.get("decoy_key"),
            ),
        ).fetchone()
        if row and row["decoy_key"]:
            targets.add(row["decoy_key"])
    return targets


def record_event(connection, decoy, action, reason, before, after, compose):
    connection.execute(
        """
        INSERT INTO decoy_lifecycle_events (
            decoy_id, decision_id, decoy_key, action, execution_mode,
            status, details, created_at
        ) VALUES (?, NULL, ?, ?, 'auto', 'completed', ?, ?)
        """,
        (
            decoy["decoy_id"], decoy["name"], action,
            json.dumps({
                "reason": reason,
                "container_state_before": before,
                "container_state_after": after,
                "logs_preserved": True,
                "database_evidence_preserved": True,
                "compose": compose,
            }, sort_keys=True),
            utc_iso_now(),
        ),
    )


def age_seconds(timestamp):
    if timestamp is None:
        return float("inf")
    return max(0.0, (utc_now() - timestamp).total_seconds())


def run_lifecycle_cycle(activation_results=None):
    if not enabled():
        return []

    idle_timeout = env_seconds("DECEPTION_DECOY_IDLE_TIMEOUT_SECONDS", 900, 60)
    remove_timeout = env_seconds("DECEPTION_DECOY_REMOVE_TIMEOUT_SECONDS", 1800, 60)
    session_grace = env_seconds("DECEPTION_ACTIVE_SESSION_GRACE_SECONDS", 90, 30)
    results = []
    connection = get_connection()
    try:
        replacements = replacement_targets(
            connection,
            activation_results,
        )
        decoys = connection.execute(
            "SELECT * FROM decoys WHERE name IS NOT NULL ORDER BY decoy_id"
        ).fetchall()

        for row in decoys:
            decoy = dict(row)
            decoy_key = decoy["name"]
            implementation = DECOY_IMPLEMENTATIONS.get(decoy_key)
            if not implementation:
                continue
            before = inspect_container(implementation["container_name"])
            last_activity = latest_event_time(connection, decoy_key)
            activated_at = parse_timestamp(decoy.get("activated_at"))
            lifecycle_activation = latest_lifecycle_time(
                connection, decoy_key, "ACTIVATE"
            )
            activity_reference = max(
                (
                    value for value in (
                        last_activity,
                        activated_at,
                        lifecycle_activation,
                    ) if value is not None
                ),
                default=None,
            )
            activity_age = age_seconds(activity_reference)

            if decoy["status"] == "active":
                replacement_ready = decoy_key in replacements
                idle = activity_age >= idle_timeout
                recent_session = activity_age < session_grace
                if not (replacement_ready or idle) or recent_session:
                    continue
                reason = "superseded_by_healthy_replacement" if replacement_ready else "idle_timeout"
                compose = run_compose(implementation["compose_file"], "stop")
                after = inspect_container(implementation["container_name"])
                if after["running"]:
                    raise RuntimeError(f"{decoy_key} remained running after stop")
                connection.execute(
                    "UPDATE decoys SET status = 'inactive' WHERE decoy_id = ?",
                    (decoy["decoy_id"],),
                )
                record_event(connection, decoy, "DEACTIVATE", reason, before, after, compose)
                results.append({
                    "decoy_key": decoy_key,
                    "result": "deactivated",
                    "reason": reason,
                    "docker_action_executed": True,
                })
                connection.commit()
                continue

            if decoy["status"] == "inactive":
                deactivated_at = latest_lifecycle_time(connection, decoy_key, "DEACTIVATE")
                if age_seconds(deactivated_at) < remove_timeout:
                    continue
                compose = run_compose(implementation["compose_file"], "remove")
                after = inspect_container(implementation["container_name"])
                connection.execute(
                    "UPDATE decoys SET status = 'removed' WHERE decoy_id = ?",
                    (decoy["decoy_id"],),
                )
                record_event(
                    connection, decoy, "REMOVE", "inactive_timeout",
                    before, after, compose,
                )
                results.append({
                    "decoy_key": decoy_key,
                    "result": "removed",
                    "reason": "inactive_timeout",
                    "docker_action_executed": True,
                    "evidence_preserved": True,
                })
                connection.commit()
    finally:
        connection.close()
    return results
