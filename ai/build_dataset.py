"""
Builds a labeled training dataset by:
1. Reading ground-truth scenario windows from Kali's scenario_log.jsonl
   (must be copied to deception-vm first, or read via shared path).
2. For each window, pulling matching events from the events table.
3. Computing numerical features per window.
4. Writing everything to a CSV for training.
"""

import sys
import os
import json
import csv
from datetime import datetime, timezone

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from config.settings import IGNORE_IP_PREFIXES
from ai.feature_extraction import compute_features
from logger.database import get_connection

SCENARIO_LOG_PATH = os.path.join(os.path.dirname(__file__), "scenario_log.jsonl")
OUTPUT_CSV = os.path.join(os.path.dirname(__file__), "dataset", "training_data.csv")

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
    "label",
]


def load_scenarios():
    scenarios = []
    if not os.path.exists(SCENARIO_LOG_PATH):
        print(f"ERROR: {SCENARIO_LOG_PATH} not found. Copy scenario_log.jsonl from Kali first.")
        sys.exit(1)
    with open(SCENARIO_LOG_PATH, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            scenarios.append(json.loads(line))
    return scenarios


def fetch_all_events():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM events WHERE source_ip IS NOT NULL AND source_ip != ''")
    rows = cur.fetchall()
    conn.close()

    events = []
    for row in rows:
        e = dict(row)
        if e["source_ip"].startswith(IGNORE_IP_PREFIXES):
            continue
        try:
            # our stored timestamps are ISO format strings
            ts = datetime.fromisoformat(e["timestamp"].replace("Z", "+00:00"))
            e["_ts_epoch"] = ts.timestamp()
        except Exception:
            e["_ts_epoch"] = None
        events.append(e)
    return events




def build_dataset():
    scenarios = load_scenarios()
    all_events = fetch_all_events()

    os.makedirs(os.path.dirname(OUTPUT_CSV), exist_ok=True)
    rows_written = 0

    with open(OUTPUT_CSV, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=FEATURE_COLUMNS)
        writer.writeheader()

        for scenario in scenarios:
            start = scenario.get("timestamp_start")
            end = scenario.get("timestamp_end")
            label = scenario.get("label", "UNKNOWN")

            if start is None or end is None:
                continue

            # small buffer window to catch events slightly before/after due to network delay
            window_events = [
                e for e in all_events
                if e["_ts_epoch"] is not None and (start - 2) <= e["_ts_epoch"] <= (end + 2)
            ]

            if not window_events:
                continue

            features = compute_features(window_events)
            features["label"] = label
            writer.writerow(features)
            rows_written += 1

    print(f"Dataset built: {rows_written} rows written to {OUTPUT_CSV}")


if __name__ == "__main__":
    build_dataset()
