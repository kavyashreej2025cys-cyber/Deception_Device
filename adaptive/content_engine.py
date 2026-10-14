"""Safe, per-attacker adaptation of synthetic decoy content.

Attacker input is classified only as text. It is never evaluated, passed to a
shell, used as a filesystem path, or applied to real infrastructure.
"""

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from logger.database import get_connection


PROJECT_ROOT = Path(__file__).resolve().parent.parent
STATE_DIR = PROJECT_ROOT / "data" / "dynamic_content"
MAX_COMMAND_LENGTH = 500
MAX_INTERESTS = 12

INTEREST_PATTERNS = {
    "credentials": re.compile(r"password|passwd|credential|secret|token|login", re.I),
    "finance": re.compile(r"invoice|payroll|payment|account|finance|bank", re.I),
    "camera": re.compile(r"camera|stream|onvif|firmware|nvr|rtsp", re.I),
    "configuration": re.compile(r"config|\.env|environment|setting", re.I),
    "backup": re.compile(r"backup|archive|zip|dump", re.I),
    "services": re.compile(r"service|port|status|api|host|network", re.I),
    "privilege": re.compile(r"sudo|root|admin|chmod|chown|su\b", re.I),
}


def utc_iso_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def enabled():
    return os.environ.get("DECEPTION_DYNAMIC_CONTENT", "false").lower() == "true"


def bounded_text(value):
    if value is None:
        return ""
    return str(value).replace("\x00", "")[:MAX_COMMAND_LENGTH]


def event_text(raw, normalized):
    candidates = [
        raw.get("input"), raw.get("command"), raw.get("query"),
        raw.get("path"), raw.get("username"), normalized.get("event_type"),
    ]
    details = raw.get("details")
    if isinstance(details, dict):
        candidates.extend(
            details.get(key)
            for key in ("query", "payload", "requested_path", "table", "camera_id", "username")
        )
    return " ".join(bounded_text(value) for value in candidates if value)


def behavior_stage(interaction_count, interests):
    if interaction_count >= 20 or "privilege" in interests:
        return "exploitation"
    if interaction_count >= 8 or len(interests) >= 3:
        return "enumeration"
    return "discovery"


def synthetic_content(decoy_key, stage, interests, interaction_count):
    # These are deliberately fake breadcrumbs selected from a fixed allow-list.
    assets = []
    if "credentials" in interests:
        assets.append("service-accounts.example")
    if "finance" in interests:
        assets.extend(["quarterly_forecast", "vendor_payments"])
    if "camera" in interests:
        assets.extend(["CAM-ARCHIVE-04", "nvr-secondary"])
    if "configuration" in interests:
        assets.append("config.snapshot.example")
    if "backup" in interests:
        assets.append("backup-2026-10.example.zip")
    if "services" in interests:
        assets.extend(["identity-api", "reporting-api"])
    if not assets:
        assets = ["status-page", "service-catalog"]

    return {
        "decoy_key": decoy_key,
        "behavior_stage": stage,
        "interaction_count": interaction_count,
        "interests": interests,
        "visible_assets": list(dict.fromkeys(assets))[:10],
        "banner_profile": f"adaptive-{stage}",
        "safety": "synthetic-read-only",
    }


def write_public_state(decoy_key, connection=None):
    owns_connection = connection is None
    connection = connection or get_connection()
    try:
        rows = connection.execute(
            """
            SELECT source_ip, content_json, updated_at
            FROM decoy_content_states
            WHERE decoy_key = ?
            ORDER BY updated_at DESC
            LIMIT 50
            """,
            (decoy_key,),
        ).fetchall()
    finally:
        if owns_connection:
            connection.close()

    payload = {
        "decoy_key": decoy_key,
        "generated_at": utc_iso_now(),
        "sources": {
            row["source_ip"]: {
                **json.loads(row["content_json"]),
                "updated_at": row["updated_at"],
            }
            for row in rows
        },
    }
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    destination = STATE_DIR / f"{decoy_key}.json"
    temporary = destination.with_suffix(".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    temporary.replace(destination)


def observe_event(decoy_key, raw, normalized, connection=None):
    """Update safe adaptive state from one captured decoy interaction."""
    if not enabled() or not decoy_key:
        return None
    source_ip = bounded_text(normalized.get("source_ip"))
    if not source_ip:
        return None

    text = event_text(raw, normalized)
    now = utc_iso_now()
    owns_connection = connection is None
    connection = connection or get_connection()
    try:
        existing = connection.execute(
            "SELECT * FROM decoy_content_states WHERE decoy_key = ? AND source_ip = ?",
            (decoy_key, source_ip),
        ).fetchone()
        count = (existing["interaction_count"] if existing else 0) + 1
        interests = json.loads(existing["interests_json"]) if existing else []
        for name, pattern in INTEREST_PATTERNS.items():
            if pattern.search(text) and name not in interests:
                interests.append(name)
        interests = interests[-MAX_INTERESTS:]
        stage = behavior_stage(count, interests)
        content = synthetic_content(decoy_key, stage, interests, count)
        connection.execute(
            """
            INSERT INTO decoy_content_states (
                decoy_key, source_ip, interaction_count, behavior_stage,
                last_event_type, last_command, interests_json, content_json,
                first_seen, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(decoy_key, source_ip) DO UPDATE SET
                interaction_count = excluded.interaction_count,
                behavior_stage = excluded.behavior_stage,
                last_event_type = excluded.last_event_type,
                last_command = excluded.last_command,
                interests_json = excluded.interests_json,
                content_json = excluded.content_json,
                updated_at = excluded.updated_at
            """,
            (
                decoy_key, source_ip, count, stage,
                bounded_text(normalized.get("event_type")), bounded_text(text),
                json.dumps(interests), json.dumps(content, sort_keys=True), now, now,
            ),
        )
        if owns_connection:
            connection.commit()
    finally:
        if owns_connection:
            connection.close()
    write_public_state(decoy_key, None if owns_connection else connection)
    return content
