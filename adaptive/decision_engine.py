"""
Observe-only adaptive deception decision engine.

This module combines:
- the latest AI classification for a source;
- the source's rule-based risk score;
- a versioned decoy catalog.

It records recommendations but does not control Docker.
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
ADAPTIVE_DIR = PROJECT_ROOT / "adaptive"
CATALOG_PATH = ADAPTIVE_DIR / "decoy_catalog.json"

sys.path.insert(0, str(PROJECT_ROOT))

from logger.database import get_connection


POLICY_VERSION = "1.0.1"

MINIMUM_DECISION_CONFIDENCE = 0.55
PREPARE_CONFIDENCE = 0.60
ACTIVATE_CONFIDENCE = 0.70


def utc_iso_now():
    """Return the current time in UTC ISO-8601 format."""
    return (
        datetime.now(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def load_catalog():
    """Load and validate the decoy catalog."""
    if not CATALOG_PATH.exists():
        raise FileNotFoundError(
            f"Decoy catalog not found: {CATALOG_PATH}"
        )

    with CATALOG_PATH.open(
        "r",
        encoding="utf-8",
    ) as catalog_file:
        catalog = json.load(catalog_file)

    required_keys = {
        "catalog_version",
        "decoys",
        "class_to_decoy",
    }

    missing = required_keys - set(catalog)

    if missing:
        raise ValueError(
            "Catalog is missing: "
            + ", ".join(sorted(missing))
        )

    for attack_class, decoy_key in catalog[
        "class_to_decoy"
    ].items():
        if decoy_key not in catalog["decoys"]:
            raise ValueError(
                f"{attack_class} references unknown decoy "
                f"{decoy_key!r}."
            )

    return catalog


def risk_bucket(risk_score):
    """Convert a numerical risk score into its policy bucket."""
    if risk_score <= 30:
        return "LOW"

    if risk_score <= 60:
        return "MEDIUM"

    if risk_score <= 80:
        return "HIGH"

    return "CRITICAL"


def fetch_latest_pending_predictions():
    """
    Return only the newest unprocessed prediction for each source.

    Older predictions are intentionally ignored because activating a
    decoy for stale behavior could contradict the attacker's latest
    observed interest.
    """
    connection = get_connection()

    try:
        rows = connection.execute(
            """
            SELECT p.*
            FROM predictions AS p
            LEFT JOIN deception_decisions AS d
              ON d.prediction_id = p.prediction_id
            WHERE p.source_ip IS NOT NULL
              AND p.last_event_id IS NOT NULL
              AND d.decision_id IS NULL
              AND p.last_event_id = (
                  SELECT MAX(newest.last_event_id)
                  FROM predictions AS newest
                  WHERE newest.source_ip = p.source_ip
                    AND newest.source_ip IS NOT NULL
                    AND newest.last_event_id IS NOT NULL
              )
            ORDER BY p.source_ip
            """
        ).fetchall()
    finally:
        connection.close()

    return [
        dict(row)
        for row in rows
    ]


def fetch_attacker_profile(source_ip):
    """Fetch the current rule-based profile for one source."""
    connection = get_connection()

    try:
        row = connection.execute(
            """
            SELECT *
            FROM attackers
            WHERE source_ip = ?
            """,
            (source_ip,),
        ).fetchone()
    finally:
        connection.close()

    if row is None:
        return None

    return dict(row)


def choose_action(
    attack_class,
    confidence,
    risk_score,
    catalog,
):
    """Apply the first version of the adaptive policy."""
    decoy_key = catalog["class_to_decoy"].get(
        attack_class
    )
    if confidence < MINIMUM_DECISION_CONFIDENCE:
        return {
            "recommended_action": "COLLECT_MORE_DATA",
            "decoy_key": None,
            "reason": (
                f"Model confidence {confidence:.3f} is below "
                f"the decision threshold "
                f"{MINIMUM_DECISION_CONFIDENCE:.2f}; the class "
                f"{attack_class} is not trusted."
            ),
        }

    if attack_class == "NORMAL":
        return {
            "recommended_action": "MONITOR",
            "decoy_key": None,
            "reason": (
                "The model classified the activity as NORMAL; "
                "no targeted decoy is recommended."
            ),
        }

    if decoy_key is None:
        return {
            "recommended_action": "COLLECT_MORE_DATA",
            "decoy_key": None,
            "reason": (
                f"No decoy mapping exists for class "
                f"{attack_class}."
            ),
        }

    if confidence < MINIMUM_DECISION_CONFIDENCE:
        return {
            "recommended_action": "COLLECT_MORE_DATA",
            "decoy_key": None,
            "reason": (
                f"Model confidence {confidence:.3f} is below "
                f"the decision threshold "
                f"{MINIMUM_DECISION_CONFIDENCE:.2f}."
            ),
        }

    if (
        risk_score >= 81
        and confidence >= ACTIVATE_CONFIDENCE
    ):
        return {
            "recommended_action": "ACTIVATE_DECOY",
            "decoy_key": decoy_key,
            "reason": (
                f"Critical risk score {risk_score} and "
                f"confidence {confidence:.3f} support targeted "
                f"activation of {decoy_key}."
            ),
        }

    if (
        risk_score >= 61
        and confidence >= PREPARE_CONFIDENCE
    ):
        return {
            "recommended_action": "PREPARE_DECOY",
            "decoy_key": decoy_key,
            "reason": (
                f"High risk score {risk_score} and confidence "
                f"{confidence:.3f} support preparing "
                f"{decoy_key}, but not automatic activation."
            ),
        }

    return {
        "recommended_action": "INCREASE_MONITORING",
        "decoy_key": None,
        "reason": (
            f"Class {attack_class} was detected, but risk "
            f"{risk_score} and confidence {confidence:.3f} do "
            "not meet a decoy preparation threshold."
        ),
    }


def build_decision(prediction, profile, catalog):
    """Combine a prediction and profile into one recommendation."""
    source_ip = prediction["source_ip"]
    attack_class = prediction["predicted_class"]
    confidence = float(prediction["confidence"])

    if profile is None:
        risk_score = 0
        profile_note = (
            " No rule-based attacker profile was available."
        )
    else:
        risk_score = int(profile["risk_score"] or 0)
        profile_note = ""

    selected = choose_action(
        attack_class=attack_class,
        confidence=confidence,
        risk_score=risk_score,
        catalog=catalog,
    )

    selected["reason"] += profile_note

    return {
        "prediction_id": prediction["prediction_id"],
        "source_ip": source_ip,
        "attack_class": attack_class,
        "confidence": confidence,
        "risk_score": risk_score,
        "risk_bucket": risk_bucket(risk_score),
        "recommended_action": selected[
            "recommended_action"
        ],
        "decoy_key": selected["decoy_key"],
        "reason": selected["reason"],
        "policy_version": POLICY_VERSION,
        "execution_mode": "observe",
        "execution_status": "recommended",
        "created_at": utc_iso_now(),
    }


def save_decision(decision):
    """Save a recommendation once per prediction."""
    connection = get_connection()

    try:
        cursor = connection.execute(
            """
            INSERT OR IGNORE INTO deception_decisions (
                prediction_id,
                source_ip,
                attack_class,
                confidence,
                risk_score,
                risk_bucket,
                recommended_action,
                decoy_key,
                reason,
                policy_version,
                execution_mode,
                execution_status,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                decision["prediction_id"],
                decision["source_ip"],
                decision["attack_class"],
                decision["confidence"],
                decision["risk_score"],
                decision["risk_bucket"],
                decision["recommended_action"],
                decision["decoy_key"],
                decision["reason"],
                decision["policy_version"],
                decision["execution_mode"],
                decision["execution_status"],
                decision["created_at"],
            ),
        )

        connection.commit()
        inserted = cursor.rowcount == 1
    finally:
        connection.close()

    return inserted


def run_decision_cycle():
    """Evaluate all latest pending source predictions."""
    catalog = load_catalog()
    predictions = fetch_latest_pending_predictions()
    results = []

    for prediction in predictions:
        profile = fetch_attacker_profile(
            prediction["source_ip"]
        )

        decision = build_decision(
            prediction=prediction,
            profile=profile,
            catalog=catalog,
        )

        decision["inserted"] = save_decision(decision)
        results.append(decision)

    return results


def main():
    """Run one observe-only decision cycle."""
    try:
        results = run_decision_cycle()
    except (
        FileNotFoundError,
        ValueError,
        TypeError,
        KeyError,
        json.JSONDecodeError,
    ) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)

    if not results:
        print("No new latest predictions require decisions.")
        return

    for result in results:
        print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
