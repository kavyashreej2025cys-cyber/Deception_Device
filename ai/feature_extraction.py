"""
Shared feature extraction for training and live prediction.

Both build_dataset.py and predict.py must use this module so that
the model receives features defined exactly as they were during training.
"""

from datetime import datetime


FEATURE_COLUMNS = [
    "event_count",
    "unique_services",
    "ssh_events",
    "web_events",
    "database_events",
    "iot_events",
    "login_attempts",
    "query_attempts",
    "camera_attempts",
    "session_duration",
]

LOGIN_EVENT_TYPES = {
    "login_attempt",
    "cowrie.login.failed",
    "cowrie.login.success",
}


def timestamp_to_epoch(timestamp):
    """Convert an ISO-8601 timestamp string to Unix epoch seconds."""
    if not timestamp:
        return None

    try:
        parsed = datetime.fromisoformat(
            str(timestamp).replace("Z", "+00:00")
        )
        return parsed.timestamp()
    except (TypeError, ValueError):
        return None


def prepare_event(event):
    """
    Return a normal dictionary with a parsed `_ts_epoch` field.

    SQLite rows and ordinary dictionaries are both accepted.
    """
    prepared = dict(event)

    if prepared.get("_ts_epoch") is None:
        prepared["_ts_epoch"] = timestamp_to_epoch(
            prepared.get("timestamp")
        )

    return prepared


def compute_features(events):
    """Compute the ten numerical features expected by the model."""
    prepared_events = [prepare_event(event) for event in events]

    services = {
        event.get("service")
        for event in prepared_events
        if event.get("service")
    }

    ssh_events = [
        event
        for event in prepared_events
        if event.get("service") == "ssh"
    ]

    web_events = [
        event
        for event in prepared_events
        if event.get("service") == "web"
    ]

    database_events = [
        event
        for event in prepared_events
        if event.get("service") == "database"
    ]

    iot_events = [
        event
        for event in prepared_events
        if event.get("service") == "iot"
    ]

    login_attempts = sum(
        event.get("event_type") in LOGIN_EVENT_TYPES
        for event in prepared_events
    )

    query_attempts = sum(
        event.get("event_type") == "query_attempt"
        for event in database_events
    )

    camera_attempts = sum(
        event.get("event_type") == "view_camera_attempt"
        for event in iot_events
    )

    timestamps = [
        event["_ts_epoch"]
        for event in prepared_events
        if event.get("_ts_epoch") is not None
    ]

    if len(timestamps) >= 2:
        session_duration = max(timestamps) - min(timestamps)
    else:
        session_duration = 0

    return {
        "event_count": len(prepared_events),
        "unique_services": len(services),
        "ssh_events": len(ssh_events),
        "web_events": len(web_events),
        "database_events": len(database_events),
        "iot_events": len(iot_events),
        "login_attempts": login_attempts,
        "query_attempts": query_attempts,
        "camera_attempts": camera_attempts,
        "session_duration": round(session_duration, 2),
    }


def feature_vector(feature_values, feature_order=None):
    """Convert a feature dictionary into the ordered model input vector."""
    order = feature_order or FEATURE_COLUMNS

    missing = [
        feature_name
        for feature_name in order
        if feature_name not in feature_values
    ]

    if missing:
        raise ValueError(
            "Missing model features: " + ", ".join(missing)
        )

    return [
        float(feature_values[feature_name])
        for feature_name in order
    ]
