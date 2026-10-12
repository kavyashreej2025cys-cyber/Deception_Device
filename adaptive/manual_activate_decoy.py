#!/usr/bin/env python3
"""Guarded operator activation for a deployed catalog decoy."""

import argparse
import json
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from adaptive.orchestrator import (
    DECOY_IMPLEMENTATIONS,
    inspect_container,
    run_compose_activation,
    utc_iso_now,
    wait_for_healthy,
)
from logger.database import get_connection


CATALOG_PATH = PROJECT_ROOT / "adaptive" / "decoy_catalog.json"


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Preview or manually activate a deployed catalog decoy."
    )
    parser.add_argument("--decoy-key", required=True)
    parser.add_argument("--reason", default="Manual dashboard activation")
    parser.add_argument("--approve", action="store_true")
    return parser.parse_args()


def load_catalog_entry(decoy_key):
    catalog = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    entry = catalog.get("decoys", {}).get(decoy_key)
    if entry is None:
        raise ValueError(f"Unknown decoy: {decoy_key}")
    if entry.get("implementation_status") != "deployed":
        raise ValueError(f"Decoy is not deployed: {decoy_key}")
    return entry


def validate_implementation(decoy_key):
    implementation = DECOY_IMPLEMENTATIONS.get(decoy_key)
    if implementation is None:
        raise ValueError(f"No deployed implementation exists for {decoy_key}")

    compose_file = Path(implementation["compose_file"]).resolve()
    allowed_root = (PROJECT_ROOT / "adaptive" / "decoys").resolve()
    if allowed_root not in compose_file.parents:
        raise ValueError("Compose file is outside the adaptive decoy directory")
    if not compose_file.is_file():
        raise FileNotFoundError(f"Compose file not found: {compose_file}")
    return implementation, compose_file


def record_activation(decoy_key, catalog_entry, implementation, activated_at, reason):
    connection = get_connection()
    try:
        existing = connection.execute(
            "SELECT decoy_id FROM decoys WHERE name = ? ORDER BY decoy_id LIMIT 1",
            (decoy_key,),
        ).fetchone()

        if existing is None:
            cursor = connection.execute(
                """
                INSERT INTO decoys (
                    name, type, container_name, status, activated_at
                ) VALUES (?, ?, ?, 'active', ?)
                """,
                (
                    decoy_key,
                    implementation["type"],
                    implementation["container_name"],
                    activated_at,
                ),
            )
            decoy_id = cursor.lastrowid
        else:
            decoy_id = existing["decoy_id"]
            connection.execute(
                """
                UPDATE decoys
                SET type = ?, container_name = ?, status = 'active',
                    activated_at = ?
                WHERE decoy_id = ?
                """,
                (
                    implementation["type"],
                    implementation["container_name"],
                    activated_at,
                    decoy_id,
                ),
            )

        details = json.dumps(
            {
                "activation_source": "dashboard_operator",
                "container_name": implementation["container_name"],
                "display_name": catalog_entry.get("name", decoy_key),
                "reason": reason,
            },
            sort_keys=True,
        )
        connection.execute(
            """
            INSERT INTO decoy_lifecycle_events (
                decoy_id, decision_id, decoy_key, action,
                execution_mode, status, details, created_at
            ) VALUES (?, NULL, ?, 'ACTIVATE', 'manual', 'completed', ?, ?)
            """,
            (decoy_id, decoy_key, details, activated_at),
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def main():
    args = parse_arguments()
    decoy_key = args.decoy_key.strip()
    reason = args.reason.strip()[:300] or "Manual dashboard activation"

    try:
        catalog_entry = load_catalog_entry(decoy_key)
        implementation, compose_file = validate_implementation(decoy_key)
        current_state = inspect_container(implementation["container_name"])
        plan = {
            "decoy_key": decoy_key,
            "display_name": catalog_entry.get("name", decoy_key),
            "container_name": implementation["container_name"],
            "compose_file": str(compose_file),
            "current_container_state": current_state,
            "reason": reason,
        }

        if not args.approve:
            print(json.dumps({"mode": "dry-run", "plan": plan}, indent=2, sort_keys=True))
            return

        compose_result = run_compose_activation(compose_file)
        final_state = wait_for_healthy(implementation["container_name"])
        activated_at = utc_iso_now()
        record_activation(
            decoy_key,
            catalog_entry,
            implementation,
            activated_at,
            reason,
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
    except (FileNotFoundError, RuntimeError, ValueError, KeyError, TypeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
