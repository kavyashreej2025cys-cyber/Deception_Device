"""
Run Random Forest predictions against events stored in SQLite.

Examples:

    venv/bin/python ai/predict.py \
        --source-ip 192.168.56.103 \
        --lookback-seconds 300

    venv/bin/python ai/predict.py \
        --source-ip 192.168.56.103 \
        --start-time 2026-09-25T17:09:00Z \
        --end-time 2026-09-25T17:15:10Z
"""

import argparse
import ipaddress
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import joblib


PROJECT_ROOT = Path(__file__).resolve().parent.parent
AI_DIR = PROJECT_ROOT / "ai"
MODEL_PATH = AI_DIR / "models" / "random_forest.joblib"

sys.path.insert(0, str(PROJECT_ROOT))

from ai.feature_extraction import (  # noqa: E402
    compute_features,
    feature_vector,
    prepare_event,
)
from logger.database import get_connection  # noqa: E402


def utc_now():
    """Return the current UTC time."""
    return datetime.now(timezone.utc)


def iso_to_epoch(value):
    """Convert an ISO-8601 timestamp into epoch seconds."""
    try:
        parsed = datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )
    except ValueError as error:
        raise ValueError(
            f"Invalid ISO timestamp: {value!r}"
        ) from error

    if parsed.tzinfo is None:
        raise ValueError(
            "Timestamps must include a timezone, such as Z or +00:00."
        )

    return parsed.timestamp()


def epoch_to_iso(value):
    """Convert epoch seconds into a UTC ISO-8601 timestamp."""
    return (
        datetime.fromtimestamp(value, timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def validate_source_ip(value):
    """Validate and normalize an IPv4 or IPv6 address."""
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as error:
        raise ValueError(
            f"Invalid source IP address: {value!r}"
        ) from error


def determine_window(args):
    """Build either an explicit or lookback-based time window."""
    explicit_start = args.start_time is not None
    explicit_end = args.end_time is not None

    if explicit_start != explicit_end:
        raise ValueError(
            "--start-time and --end-time must be provided together."
        )

    if explicit_start:
        start_epoch = iso_to_epoch(args.start_time)
        end_epoch = iso_to_epoch(args.end_time)
    else:
        if args.lookback_seconds <= 0:
            raise ValueError(
                "--lookback-seconds must be greater than zero."
            )

        end_epoch = utc_now().timestamp()
        start_epoch = end_epoch - args.lookback_seconds

    if end_epoch <= start_epoch:
        raise ValueError(
            "The end of the window must be later than the start."
        )

    return start_epoch, end_epoch


def load_model_bundle():
    """Load and validate the locally trained model artifact."""
    if not MODEL_PATH.exists():
        raise FileNotFoundError(
            f"Model artifact not found: {MODEL_PATH}"
        )

    bundle = joblib.load(MODEL_PATH)

    required_keys = {
        "model",
        "feature_columns",
        "class_names",
        "metadata",
    }

    if not isinstance(bundle, dict):
        raise ValueError("The model artifact is not a model bundle.")

    missing_keys = required_keys - set(bundle)

    if missing_keys:
        raise ValueError(
            "Model bundle is missing: "
            + ", ".join(sorted(missing_keys))
        )

    model = bundle["model"]

    if not hasattr(model, "predict_proba"):
        raise ValueError(
            "The loaded model does not support probability prediction."
        )

    return bundle


def fetch_events(source_ip, start_epoch, end_epoch):
    """Fetch one source IP's events inside the requested time window."""
    connection = get_connection()

    try:
        rows = connection.execute(
            """
            SELECT *
            FROM events
            WHERE source_ip = ?
            ORDER BY timestamp ASC
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


def predict_event_group(bundle, events):
    """Extract features and return the prediction result."""
    features = compute_features(events)
    ordered_features = feature_vector(
        features,
        bundle["feature_columns"],
    )

    model = bundle["model"]
    probabilities = model.predict_proba([ordered_features])[0]
    class_names = [str(value) for value in model.classes_]

    probability_map = {
        class_name: round(float(probability), 6)
        for class_name, probability in zip(
            class_names,
            probabilities,
        )
    }

    predicted_class = str(
        model.predict([ordered_features])[0]
    )
    confidence = float(
        probability_map[predicted_class]
    )

    return {
        "predicted_class": predicted_class,
        "confidence": confidence,
        "probabilities": probability_map,
        "features": features,
    }


def save_prediction(
    source_ip,
    start_epoch,
    end_epoch,
    result,
    metadata,
):
    """Store the model result in the predictions table."""
    event_group_id = (
        f"{source_ip}:"
        f"{int(start_epoch)}:"
        f"{int(end_epoch)}:"
        f"{uuid.uuid4().hex[:8]}"
    )

    dataset_hash = metadata.get(
        "dataset_sha256",
        "unknown",
    )

    model_version = (
        f"random-forest:"
        f"{dataset_hash[:12]}:"
        f"sklearn-{metadata.get('scikit_learn_version', 'unknown')}"
    )

    created_at = (
        utc_now()
        .isoformat()
        .replace("+00:00", "Z")
    )

    connection = get_connection()

    try:
        connection.execute(
            """
            INSERT INTO predictions (
                event_group_id,
                predicted_class,
                confidence,
                model_version,
                created_at
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                event_group_id,
                result["predicted_class"],
                result["confidence"],
                model_version,
                created_at,
            ),
        )
        connection.commit()
    finally:
        connection.close()

    return {
        "event_group_id": event_group_id,
        "model_version": model_version,
        "created_at": created_at,
    }


def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description=(
            "Classify a source IP's event activity using the "
            "trained Random Forest."
        )
    )

    parser.add_argument(
        "--source-ip",
        required=True,
        help="Attacker/source IP address to classify.",
    )

    parser.add_argument(
        "--lookback-seconds",
        type=int,
        default=300,
        help=(
            "Live window ending now. Default: 300. Ignored when "
            "--start-time and --end-time are supplied."
        ),
    )

    parser.add_argument(
        "--start-time",
        help=(
            "Explicit ISO-8601 window start, for example "
            "2026-09-25T17:09:00Z."
        ),
    )

    parser.add_argument(
        "--end-time",
        help=(
            "Explicit ISO-8601 window end, for example "
            "2026-09-25T17:15:10Z."
        ),
    )

    parser.add_argument(
        "--no-save",
        action="store_true",
        help="Print the result without inserting it into SQLite.",
    )

    return parser.parse_args()


def main():
    """Run one prediction."""
    args = parse_arguments()

    try:
        source_ip = validate_source_ip(args.source_ip)
        start_epoch, end_epoch = determine_window(args)
        bundle = load_model_bundle()

        events = fetch_events(
            source_ip=source_ip,
            start_epoch=start_epoch,
            end_epoch=end_epoch,
        )

        if not events:
            raise ValueError(
                "No matching events were found for this source IP "
                "and time window."
            )

        result = predict_event_group(
            bundle=bundle,
            events=events,
        )

        output = {
            "source_ip": source_ip,
            "window": {
                "start": epoch_to_iso(start_epoch),
                "end": epoch_to_iso(end_epoch),
            },
            "event_count": len(events),
            **result,
        }

        if not args.no_save:
            output["database_record"] = save_prediction(
                source_ip=source_ip,
                start_epoch=start_epoch,
                end_epoch=end_epoch,
                result=result,
                metadata=bundle["metadata"],
            )

        print(json.dumps(output, indent=2, sort_keys=True))

    except (
        FileNotFoundError,
        ValueError,
        TypeError,
        KeyError,
    ) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
