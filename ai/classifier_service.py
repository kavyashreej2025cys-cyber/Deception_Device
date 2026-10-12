"""
Continuously classify new attacker activity stored in SQLite.

The service:
- checks each external source IP for new events;
- builds a rolling feature window;
- runs the trained Random Forest;
- stores one contextual prediction;
- avoids duplicates using a deterministic event-group ID.
"""

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from ai.feature_extraction import prepare_event
from ai.predict import load_model_bundle, predict_event_group
from config.settings import IGNORE_IP_PREFIXES
from logger.database import get_connection


DEFAULT_POLL_SECONDS = 5
DEFAULT_WINDOW_SECONDS = 300
DEFAULT_MINIMUM_EVENTS = 1

DUPLICATE_PREDICTION_COOLDOWN_SECONDS = 30
SIGNIFICANT_CONFIDENCE_CHANGE = 0.05
DECISION_CONFIDENCE_BOUNDARIES = (0.55, 0.60, 0.70)


def utc_iso_now():
    """Return the current UTC time as ISO-8601."""
    return (
        datetime.now(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def epoch_to_iso(epoch_value):
    """Convert epoch seconds to UTC ISO-8601."""
    return (
        datetime.fromtimestamp(
            epoch_value,
            timezone.utc,
        )
        .isoformat()
        .replace("+00:00", "Z")
    )


def model_version_from_metadata(metadata):
    """Build a readable model version identifier."""
    dataset_hash = metadata.get(
        "dataset_sha256",
        "unknown",
    )

    sklearn_version = metadata.get(
        "scikit_learn_version",
        "unknown",
    )

    return (
        f"random-forest:"
        f"{dataset_hash[:12]}:"
        f"sklearn-{sklearn_version}"
    )


def fetch_source_states():
    """Return the newest stored event for each external source."""
    connection = get_connection()

    try:
        rows = connection.execute(
            """
            SELECT
                source_ip,
                MAX(event_id) AS latest_event_id
            FROM events
            WHERE source_ip IS NOT NULL
              AND source_ip != ''
            GROUP BY source_ip
            ORDER BY source_ip
            """
        ).fetchall()
    finally:
        connection.close()

    states = []

    for row in rows:
        source_ip = row["source_ip"]

        if source_ip.startswith(IGNORE_IP_PREFIXES):
            continue

        states.append(
            {
                "source_ip": source_ip,
                "latest_event_id": row["latest_event_id"],
            }
        )

    return states


def fetch_last_processed_event_id(source_ip):
    """Return the last event included in a live prediction."""
    connection = get_connection()

    try:
        row = connection.execute(
            """
            SELECT MAX(last_event_id) AS last_event_id
            FROM predictions
            WHERE source_ip = ?
              AND last_event_id IS NOT NULL
            """,
            (source_ip,),
        ).fetchone()
    finally:
        connection.close()

    if row is None or row["last_event_id"] is None:
        return 0

    return int(row["last_event_id"])


def fetch_latest_event(source_ip):
    """Return the newest event for a source IP."""
    connection = get_connection()

    try:
        row = connection.execute(
            """
            SELECT *
            FROM events
            WHERE source_ip = ?
            ORDER BY event_id DESC
            LIMIT 1
            """,
            (source_ip,),
        ).fetchone()
    finally:
        connection.close()

    if row is None:
        return None

    return prepare_event(row)


def fetch_window_events(
    source_ip,
    start_epoch,
    end_epoch,
):
    """Fetch events from one source inside a rolling window."""
    connection = get_connection()

    try:
        rows = connection.execute(
            """
            SELECT *
            FROM events
            WHERE source_ip = ?
            ORDER BY event_id ASC
            """,
            (source_ip,),
        ).fetchall()
    finally:
        connection.close()

    matching_events = []

    for row in rows:
        event = prepare_event(row)
        event_epoch = event.get("_ts_epoch")

        if event_epoch is None:
            continue

        if start_epoch <= event_epoch <= end_epoch:
            matching_events.append(event)

    return matching_events



def fetch_latest_prediction(source_ip):
    """Return the newest stored live prediction for a source."""
    connection = get_connection()

    try:
        row = connection.execute(
            """
            SELECT *
            FROM predictions
            WHERE source_ip = ?
              AND last_event_id IS NOT NULL
            ORDER BY prediction_id DESC
            LIMIT 1
            """,
            (source_ip,),
        ).fetchone()
    finally:
        connection.close()

    return dict(row) if row is not None else None


def confidence_band(confidence):
    """Return the adaptive-policy confidence interval."""
    value = float(confidence)

    for index, boundary in enumerate(
        DECISION_CONFIDENCE_BOUNDARIES
    ):
        if value < boundary:
            return index

    return len(DECISION_CONFIDENCE_BOUNDARIES)


def parse_utc_timestamp(value):
    """Parse a stored UTC ISO-8601 timestamp."""
    if not value:
        return None

    try:
        parsed = datetime.fromisoformat(
            str(value).replace("Z", "+00:00")
        )
    except ValueError:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def duplicate_prediction_reason(
    previous,
    prediction_result,
    model_version,
    current_time=None,
):
    """Explain why an equivalent prediction should be delayed."""
    if previous is None:
        return None

    if previous.get("model_version") != model_version:
        return None

    if (
        previous.get("predicted_class")
        != prediction_result["predicted_class"]
    ):
        return None

    previous_confidence = float(previous["confidence"])
    current_confidence = float(prediction_result["confidence"])

    if confidence_band(previous_confidence) != confidence_band(
        current_confidence
    ):
        return None

    if (
        abs(current_confidence - previous_confidence)
        >= SIGNIFICANT_CONFIDENCE_CHANGE
    ):
        return None

    created_at = parse_utc_timestamp(previous.get("created_at"))

    if created_at is None:
        return None

    now = current_time or datetime.now(timezone.utc)
    age_seconds = (now - created_at).total_seconds()

    if age_seconds < 0:
        return None

    if age_seconds >= DUPLICATE_PREDICTION_COOLDOWN_SECONDS:
        return None

    return (
        "Equivalent prediction is inside the "
        f"{DUPLICATE_PREDICTION_COOLDOWN_SECONDS}-second cooldown."
    )

def save_live_prediction(
    source_ip,
    events,
    start_epoch,
    end_epoch,
    prediction_result,
    model_metadata,
):
    """Persist a contextual prediction and prevent duplicates."""
    first_event_id = min(
        int(event["event_id"])
        for event in events
    )
    last_event_id = max(
        int(event["event_id"])
        for event in events
    )

    model_version = model_version_from_metadata(
        model_metadata
    )

    event_group_id = (
        f"{source_ip}:"
        f"{first_event_id}:"
        f"{last_event_id}:"
        f"{model_metadata.get('dataset_sha256', 'unknown')[:12]}"
    )

    connection = get_connection()

    try:
        cursor = connection.execute(
            """
            INSERT OR IGNORE INTO predictions (
                event_group_id,
                predicted_class,
                confidence,
                model_version,
                created_at,
                source_ip,
                window_start,
                window_end,
                first_event_id,
                last_event_id,
                event_count,
                features_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_group_id,
                prediction_result["predicted_class"],
                prediction_result["confidence"],
                model_version,
                utc_iso_now(),
                source_ip,
                epoch_to_iso(start_epoch),
                epoch_to_iso(end_epoch),
                first_event_id,
                last_event_id,
                len(events),
                json.dumps(
                    prediction_result["features"],
                    sort_keys=True,
                ),
            ),
        )

        connection.commit()
        inserted = cursor.rowcount == 1
    finally:
        connection.close()

    return {
        "inserted": inserted,
        "event_group_id": event_group_id,
        "first_event_id": first_event_id,
        "last_event_id": last_event_id,
        "model_version": model_version,
    }


def classify_source(
    bundle,
    source_ip,
    window_seconds,
    minimum_events,
):
    """Classify the latest rolling window for one source."""
    latest_event = fetch_latest_event(source_ip)

    if latest_event is None:
        return None

    end_epoch = latest_event.get("_ts_epoch")

    if end_epoch is None:
        raise ValueError(
            f"Latest event for {source_ip} has an invalid timestamp."
        )

    start_epoch = end_epoch - window_seconds

    events = fetch_window_events(
        source_ip=source_ip,
        start_epoch=start_epoch,
        end_epoch=end_epoch,
    )

    if len(events) < minimum_events:
        return {
            "source_ip": source_ip,
            "skipped": True,
            "reason": (
                f"Only {len(events)} events; "
                f"minimum is {minimum_events}."
            ),
        }

    prediction_result = predict_event_group(
        bundle=bundle,
        events=events,
    )

    model_version = model_version_from_metadata(
        bundle["metadata"]
    )
    previous_prediction = fetch_latest_prediction(source_ip)
    cooldown_reason = duplicate_prediction_reason(
        previous=previous_prediction,
        prediction_result=prediction_result,
        model_version=model_version,
    )

    if cooldown_reason is not None:
        return {
            "source_ip": source_ip,
            "event_count": len(events),
            "last_event_id": max(
                int(event["event_id"])
                for event in events
            ),
            "predicted_class": prediction_result[
                "predicted_class"
            ],
            "confidence": prediction_result["confidence"],
            "inserted": False,
            "skipped": True,
            "reason": cooldown_reason,
        }

    database_result = save_live_prediction(
        source_ip=source_ip,
        events=events,
        start_epoch=start_epoch,
        end_epoch=end_epoch,
        prediction_result=prediction_result,
        model_metadata=bundle["metadata"],
    )

    return {
        "source_ip": source_ip,
        "event_count": len(events),
        "predicted_class": prediction_result[
            "predicted_class"
        ],
        "confidence": prediction_result["confidence"],
        "features": prediction_result["features"],
        **database_result,
    }


def run_cycle(
    bundle,
    window_seconds,
    minimum_events,
):
    """Process every source that has unclassified new events."""
    source_states = fetch_source_states()
    results = []

    for state in source_states:
        source_ip = state["source_ip"]
        latest_event_id = int(state["latest_event_id"])
        processed_event_id = fetch_last_processed_event_id(
            source_ip
        )

        if latest_event_id <= processed_event_id:
            continue

        result = classify_source(
            bundle=bundle,
            source_ip=source_ip,
            window_seconds=window_seconds,
            minimum_events=minimum_events,
        )

        if result is not None:
            results.append(result)

    return results


def parse_arguments():
    """Parse service configuration."""
    parser = argparse.ArgumentParser(
        description=(
            "Continuously classify new cyber-deception events."
        )
    )

    parser.add_argument(
        "--once",
        action="store_true",
        help="Run one classification cycle and exit.",
    )

    parser.add_argument(
        "--poll-seconds",
        type=int,
        default=DEFAULT_POLL_SECONDS,
    )

    parser.add_argument(
        "--window-seconds",
        type=int,
        default=DEFAULT_WINDOW_SECONDS,
    )

    parser.add_argument(
        "--minimum-events",
        type=int,
        default=DEFAULT_MINIMUM_EVENTS,
    )

    return parser.parse_args()


def validate_arguments(args):
    """Reject invalid service settings."""
    if args.poll_seconds <= 0:
        raise ValueError(
            "--poll-seconds must be greater than zero."
        )

    if args.window_seconds <= 0:
        raise ValueError(
            "--window-seconds must be greater than zero."
        )

    if args.minimum_events <= 0:
        raise ValueError(
            "--minimum-events must be greater than zero."
        )


def print_cycle_results(results):
    """Print concise JSON results for operational logs."""
    if not results:
        print("No new external events to classify.")
        return

    for result in results:
        print(json.dumps(result, sort_keys=True))


def main():
    """Start the classifier loop."""
    args = parse_arguments()

    try:
        validate_arguments(args)
        bundle = load_model_bundle()
    except (
        FileNotFoundError,
        ValueError,
        TypeError,
        KeyError,
    ) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)

    print(
        "Classifier service started "
        f"(window={args.window_seconds}s, "
        f"poll={args.poll_seconds}s, "
        f"minimum_events={args.minimum_events})."
    )

    try:
        while True:
            results = run_cycle(
                bundle=bundle,
                window_seconds=args.window_seconds,
                minimum_events=args.minimum_events,
            )
            print_cycle_results(results)

            if args.once:
                break

            time.sleep(args.poll_seconds)
    except KeyboardInterrupt:
        print("\nClassifier service stopped.")


if __name__ == "__main__":
    main()
