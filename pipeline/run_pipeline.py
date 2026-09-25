"""
Supervised cyber-deception pipeline.

Automates:
1. Log ingestion
2. Rule-based attacker profiling
3. Random Forest classification
4. Adaptive decision generation

It deliberately does not activate or deactivate Docker decoys.
Those actions remain behind explicit approval commands.
"""

import argparse
import fcntl
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOCK_PATH = PROJECT_ROOT / "data" / "pipeline.lock"

sys.path.insert(0, str(PROJECT_ROOT))

from adaptive.decision_engine import run_decision_cycle
from ai.classifier_service import (
    load_model_bundle,
    run_cycle as run_classifier_cycle,
)
from config.settings import IGNORE_IP_PREFIXES
from logger.database import get_connection, init_db
from logger.event_logger import run_once as run_logger_once
from profiler.profile_manager import run_profiling


DEFAULT_INTERVAL_SECONDS = 5
DEFAULT_CLASSIFICATION_WINDOW_SECONDS = 300
DEFAULT_MINIMUM_EVENTS = 1


def utc_iso_now():
    """Return the current UTC timestamp."""
    return (
        datetime.now(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def acquire_process_lock():
    """Prevent two supervised pipelines from running together."""
    LOCK_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    lock_file = LOCK_PATH.open("w")

    try:
        fcntl.flock(
            lock_file.fileno(),
            fcntl.LOCK_EX | fcntl.LOCK_NB,
        )
    except BlockingIOError as error:
        lock_file.close()
        raise RuntimeError(
            "Another supervised pipeline process is already running."
        ) from error

    lock_file.write(str(os.getpid()))
    lock_file.flush()

    return lock_file


def profiles_need_refresh():
    """Check whether any external source has newer events."""
    connection = get_connection()

    try:
        rows = connection.execute(
            """
            SELECT
                events.source_ip,
                MAX(events.timestamp) AS newest_event,
                attackers.last_seen
            FROM events
            LEFT JOIN attackers
              ON attackers.source_ip = events.source_ip
            WHERE events.source_ip IS NOT NULL
              AND events.source_ip != ''
            GROUP BY
                events.source_ip,
                attackers.last_seen
            """
        ).fetchall()
    finally:
        connection.close()

    for row in rows:
        source_ip = row["source_ip"]

        if source_ip.startswith(IGNORE_IP_PREFIXES):
            continue

        if row["last_seen"] is None:
            return True

        if row["newest_event"] > row["last_seen"]:
            return True

    return False


def summarize_classifier_results(results):
    """Keep operational output concise."""
    return [
        {
            "source_ip": result.get("source_ip"),
            "predicted_class": result.get(
                "predicted_class"
            ),
            "confidence": result.get("confidence"),
            "event_count": result.get("event_count"),
            "last_event_id": result.get(
                "last_event_id"
            ),
            "inserted": result.get("inserted"),
            "skipped": result.get("skipped", False),
            "reason": result.get("reason"),
        }
        for result in results
    ]


def summarize_decisions(results):
    """Return the important observe-only decision fields."""
    return [
        {
            "prediction_id": result.get(
                "prediction_id"
            ),
            "source_ip": result.get("source_ip"),
            "attack_class": result.get(
                "attack_class"
            ),
            "confidence": result.get("confidence"),
            "risk_score": result.get("risk_score"),
            "recommended_action": result.get(
                "recommended_action"
            ),
            "decoy_key": result.get("decoy_key"),
            "execution_mode": result.get(
                "execution_mode"
            ),
            "inserted": result.get("inserted"),
        }
        for result in results
    ]


def run_supervised_cycle(
    model_bundle,
    classification_window_seconds,
    minimum_events,
):
    """Run one complete supervised analysis cycle."""
    cycle_started = utc_iso_now()

    ingested_events = run_logger_once()

    profile_refreshed = profiles_need_refresh()

    if profile_refreshed:
        run_profiling()

    classifier_results = run_classifier_cycle(
        bundle=model_bundle,
        window_seconds=classification_window_seconds,
        minimum_events=minimum_events,
    )

    decision_results = run_decision_cycle()

    return {
        "cycle_started_at": cycle_started,
        "ingested_events": ingested_events,
        "profile_refreshed": profile_refreshed,
        "classifier_results": summarize_classifier_results(
            classifier_results
        ),
        "decision_results": summarize_decisions(
            decision_results
        ),
        "docker_actions_executed": 0,
                "approval_required": any(
            result.get("recommended_action")
            == "ACTIVATE_DECOY"
            for result in decision_results
        ),
    }


def cycle_has_activity(summary):
    """Return whether a cycle produced meaningful work."""
    return bool(
        summary["ingested_events"]
        or summary["profile_refreshed"]
        or summary["classifier_results"]
        or summary["decision_results"]
    )


def parse_arguments():
    """Parse service arguments."""
    parser = argparse.ArgumentParser(
        description=(
            "Run the supervised cyber-deception pipeline."
        )
    )

    parser.add_argument(
        "--once",
        action="store_true",
        help="Run one complete cycle and exit.",
    )

    parser.add_argument(
        "--interval-seconds",
        type=int,
        default=DEFAULT_INTERVAL_SECONDS,
    )

    parser.add_argument(
        "--classification-window-seconds",
        type=int,
        default=DEFAULT_CLASSIFICATION_WINDOW_SECONDS,
    )

    parser.add_argument(
        "--minimum-events",
        type=int,
        default=DEFAULT_MINIMUM_EVENTS,
    )

    parser.add_argument(
        "--show-idle",
        action="store_true",
        help="Print summaries even when no work occurred.",
    )

    return parser.parse_args()


def validate_arguments(args):
    """Validate positive timing and event limits."""
    if args.interval_seconds <= 0:
        raise ValueError(
            "--interval-seconds must be greater than zero."
        )

    if args.classification_window_seconds <= 0:
        raise ValueError(
            "--classification-window-seconds must be greater "
            "than zero."
        )

    if args.minimum_events <= 0:
        raise ValueError(
            "--minimum-events must be greater than zero."
        )


def main():
    """Run the supervised loop."""
    args = parse_arguments()

    try:
        validate_arguments(args)
        process_lock = acquire_process_lock()
        init_db()
        model_bundle = load_model_bundle()
    except (
        FileNotFoundError,
        RuntimeError,
        ValueError,
        TypeError,
        KeyError,
    ) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)

    print(
        "Supervised pipeline started. "
        "Docker actions require separate explicit approval."
    )

    try:
        while True:
            try:
                summary = run_supervised_cycle(
                    model_bundle=model_bundle,
                    classification_window_seconds=(
                        args.classification_window_seconds
                    ),
                    minimum_events=args.minimum_events,
                )

                if (
                    args.show_idle
                    or cycle_has_activity(summary)
                ):
                    print(
                        json.dumps(
                            summary,
                            indent=2,
                            sort_keys=True,
                        )
                    )

            except Exception as error:
                print(
                    json.dumps(
                        {
                            "cycle_failed_at": utc_iso_now(),
                            "error_type": type(error).__name__,
                            "error": str(error),
                        },
                        sort_keys=True,
                    ),
                    file=sys.stderr,
                )

                if args.once:
                    raise SystemExit(1)

            if args.once:
                break

            time.sleep(args.interval_seconds)

    except KeyboardInterrupt:
        print("\nSupervised pipeline stopped.")
    finally:
        process_lock.close()


if __name__ == "__main__":
    main()
