import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "logger"))

from config.settings import IGNORE_IP_PREFIXES
from database import get_connection
from rules import evaluate_source


def fetch_events_by_source():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM events WHERE source_ip IS NOT NULL AND source_ip != ''")
    rows = cur.fetchall()
    conn.close()

    grouped = {}
    for row in rows:
        event = dict(row)
        ip = event["source_ip"]
        if ip.startswith(IGNORE_IP_PREFIXES):
            continue
        grouped.setdefault(ip, []).append(event)
    return grouped


def run_detection():
    grouped = fetch_events_by_source()

    if not grouped:
        print("No events with source_ip found yet.")
        return

    for ip, events in grouped.items():
        findings = evaluate_source(events)
        print(f"\n=== Source: {ip} ({len(events)} total events) ===")
        if not findings:
            print("  No suspicious pattern detected.")
        else:
            for f in findings:
                print(f"  [{f['severity']}] {f['attack_type']} — {f['reason']}")


if __name__ == "__main__":
    run_detection()
