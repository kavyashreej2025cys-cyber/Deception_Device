"""Time-windowed risk scoring for attacker profiles."""

from datetime import datetime, timezone


ATTACK_BASE_SCORES = {
    "NORMAL": 5,
    "RECONNAISSANCE": 35,
    "IOT_PROBING": 48,
    "DATABASE_PROBING": 52,
    "WEB_ATTACK": 52,
    "BRUTE_FORCE": 65,
    "MULTI_SERVICE_PROBE": 75,
}

SEVERITY_BONUSES = {
    "LOW": 0,
    "MEDIUM": 4,
    "HIGH": 8,
    "CRITICAL": 12,
}

BUCKETS = (
    (29, "LOW"),
    (59, "MEDIUM"),
    (79, "HIGH"),
    (100, "CRITICAL"),
)


def risk_bucket(score):
    """Return the display bucket for a 0-100 risk score."""
    for maximum, bucket in BUCKETS:
        if score <= maximum:
            return bucket
    return "CRITICAL"


def _parse_timestamp(value):
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _recency_factor(events, now, window_minutes):
    """Fade risk as the newest event approaches the window boundary."""
    timestamps = [
        parsed
        for parsed in (
            _parse_timestamp(event.get("timestamp"))
            for event in events
        )
        if parsed is not None
    ]
    if not timestamps:
        return 1.0

    age_seconds = max(0.0, (now - max(timestamps)).total_seconds())
    window_seconds = max(60.0, float(window_minutes) * 60.0)
    grace_seconds = window_seconds / 3.0
    if age_seconds <= grace_seconds:
        return 1.0
    return max(
        0.0,
        1.0 - (
            (age_seconds - grace_seconds)
            / (window_seconds - grace_seconds)
        ),
    )


def compute_risk_score(
    findings,
    event_count,
    unique_services=0,
    events=None,
    now=None,
    window_minutes=15,
):
    """Calculate current risk from recent behaviour only.

    The strongest detected pattern supplies the base score. Repetition,
    service breadth and additional patterns add bounded escalation. Old
    events fade as they approach the end of the configured window.
    """
    events = events or []
    now = now or datetime.now(timezone.utc)

    if not findings:
        score = 5 if event_count else 0
    else:
        strongest = max(
            findings,
            key=lambda item: ATTACK_BASE_SCORES.get(
                item.get("attack_type"), 25
            ),
        )
        score = ATTACK_BASE_SCORES.get(
            strongest.get("attack_type"), 25
        )
        score += SEVERITY_BONUSES.get(
            strongest.get("severity"), 0
        )
        score += min(9, max(0, len(findings) - 1) * 3)

    if event_count >= 50:
        score += 15
    elif event_count >= 20:
        score += 10
    elif event_count >= 10:
        score += 6
    elif event_count >= 5:
        score += 3

    if unique_services >= 4:
        score += 12
    elif unique_services == 3:
        score += 8
    elif unique_services == 2:
        score += 4

    score = round(
        min(100, score)
        * _recency_factor(events, now, window_minutes)
    )
    score = max(0, min(int(score), 100))
    return score, risk_bucket(score)
